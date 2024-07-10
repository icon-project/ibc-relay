package icon

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"

	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	rlycommon "github.com/cosmos/relayer/v2/relayer/common"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/gorilla/websocket"
	"github.com/icon-project/goloop/common"
	"github.com/icon-project/goloop/common/codec"
	"github.com/pkg/errors"
)

const (
	queryTimeout                = 5 * time.Second
	latestHeightQueryRetryDelay = 1 * time.Second
	queryRetries                = 5
)

const (
	notProcessed = "not-processed"
	processed    = "processed"
)

type IconChainProcessor struct {
	log           *zap.Logger
	chainProvider *IconProvider

	pathProcessors processor.PathProcessors

	inSync    bool
	firstTime bool

	latestBlock   provider.LatestBlock
	latestBlockMu sync.Mutex

	latestClientState

	// holds open state for known connections
	connectionStateCache processor.ConnectionStateCache

	// holds open state for known channels
	channelStateCache processor.ChannelStateCache

	// map of connection ID to client ID
	connectionClients map[string]string

	// map of channel ID to connection ID
	channelConnections map[string]string

	// metrics to monitor lifetime of processor
	metrics *processor.PrometheusMetrics

	verifier *Verifier

	heightSnapshotChan chan struct{}
}

type Verifier struct {
	nextProofContext       [][]byte
	verifiedHeight         int64
	prevNetworkSectionHash []byte
}

func NewIconChainProcessor(log *zap.Logger, provider *IconProvider, metrics *processor.PrometheusMetrics, heightSnapshot chan struct{}) *IconChainProcessor {
	return &IconChainProcessor{
		log:                  log.With(zap.String("chain_name", provider.ChainName()), zap.String("chain_id", provider.ChainId())),
		chainProvider:        provider,
		latestClientState:    make(latestClientState),
		connectionStateCache: make(processor.ConnectionStateCache),
		channelStateCache:    make(processor.ChannelStateCache),
		connectionClients:    make(map[string]string),
		channelConnections:   make(map[string]string),
		metrics:              metrics,
		heightSnapshotChan:   heightSnapshot,
	}
}

// Arrangement For the Latest height
type latestClientState map[string]provider.ClientState

func (l latestClientState) update(ctx context.Context, clientInfo clientInfo, icp *IconChainProcessor) {

	existingClientInfo, ok := l[clientInfo.clientID]
	if ok {
		if clientInfo.consensusHeight.LT(existingClientInfo.ConsensusHeight) {
			// height is less than latest, so no-op
			return
		}
	}

	clientState := clientInfo.ClientState()
	l[clientInfo.clientID] = clientState
}

type btpBlockResponse struct {
	Height      int64
	Header      IconIBCHeader
	EventLogs   []types.EventLog
	IsProcessed string
}
type btpBlockRequest struct {
	height   int64
	hash     types.HexBytes
	indexes  [][]types.HexInt
	events   [][][]types.HexInt
	err      error
	retry    int
	response *btpBlockResponse
}

// ************************************************** For persistence **************************************************
type queryCyclePersistence struct {
	latestHeight   int64
	latestHeightMu sync.Mutex

	lastQueriedHeight     int64
	latestQueriedHeightMu sync.Mutex

	minQueryLoopDuration time.Duration
}

func (icp *IconChainProcessor) Run(ctx context.Context, initialBlockHistory uint64) error {
	persistence := queryCyclePersistence{
		minQueryLoopDuration: time.Second,
	}

	var eg errgroup.Group

	eg.Go(func() error {
		return icp.initializeConnectionState(ctx)
	})
	eg.Go(func() error {
		return icp.initializeChannelState(ctx)
	})
	if err := eg.Wait(); err != nil {
		return err
	}

	// start_query_cycle
	icp.log.Debug("Starting query cycle")
	err := icp.monitoring(ctx, &persistence)
	return err
}

func (icp *IconChainProcessor) StartFromHeight(ctx context.Context) int64 {
	cfg := icp.Provider().ProviderConfig().(*IconProviderConfig)

	if cfg.StartHeight != 0 {
		return cfg.StartHeight
	}
	snapshotHeight, err := rlycommon.LoadSnapshotHeight(icp.Provider().ChainId())
	if err != nil {
		icp.log.Warn("Failed to load height from snapshot", zap.Error(err))
	} else {
		icp.log.Info("Obtained start height from config", zap.Int64("height", snapshotHeight))
	}
	return snapshotHeight
}

func (icp *IconChainProcessor) getLastSavedHeight() int64 {
	snapshotHeight, err := rlycommon.LoadSnapshotHeight(icp.Provider().ChainId())
	if err != nil || snapshotHeight < 0 {
		return 0
	}
	return snapshotHeight
}

func (icp *IconChainProcessor) initializeConnectionState(ctx context.Context) error {
	// ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	// defer cancel()

	connections, err := icp.chainProvider.QueryConnections(ctx)
	if err != nil {
		return fmt.Errorf("error querying connections: %w", err)
	}

	for _, c := range connections {
		icp.connectionClients[c.Id] = c.ClientId
		icp.connectionStateCache[processor.ConnectionKey{
			ConnectionID:         c.Id,
			ClientID:             c.ClientId,
			CounterpartyConnID:   c.Counterparty.ConnectionId,
			CounterpartyClientID: c.Counterparty.ClientId,
		}] = c.State == conntypes.OPEN

		icp.log.Debug("Found open connection",
			zap.String("client-id ", c.ClientId),
			zap.String("connection-id ", c.Id),
		)
	}
	return nil
}

func (icp *IconChainProcessor) initializeChannelState(ctx context.Context) error {
	// ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	// defer cancel()
	channels, err := icp.chainProvider.QueryChannels(ctx)
	if err != nil {
		return fmt.Errorf("error querying channels: %w", err)
	}
	for _, ch := range channels {
		if len(ch.ConnectionHops) != 1 {
			icp.log.Error("Found channel using multiple connection hops. Not currently supported, ignoring.",
				zap.String("channel_id", ch.ChannelId),
				zap.String("port_id", ch.PortId),
				zap.Strings("connection_hops", ch.ConnectionHops),
			)
			continue
		}

		icp.channelConnections[ch.ChannelId] = ch.ConnectionHops[0]
		icp.channelStateCache[processor.ChannelKey{
			ChannelID:             ch.ChannelId,
			PortID:                ch.PortId,
			CounterpartyChannelID: ch.Counterparty.ChannelId,
			CounterpartyPortID:    ch.Counterparty.PortId,
		}] = ch.State == chantypes.OPEN

		icp.log.Debug("Found open channel",
			zap.String("channel-id", ch.ChannelId),
			zap.String("port-id ", ch.PortId),
			zap.String("counterparty-channel-id", ch.Counterparty.ChannelId),
			zap.String("counterparty-port-id", ch.Counterparty.PortId))
	}

	return nil
}

func (icp *IconChainProcessor) Provider() provider.ChainProvider {
	return icp.chainProvider
}

func (icp *IconChainProcessor) SetPathProcessors(pathProcessors processor.PathProcessors) {
	icp.pathProcessors = pathProcessors
}

func (icp *IconChainProcessor) GetLatestHeight() uint64 {
	return icp.latestBlock.Height
}

func (icp *IconChainProcessor) monitoring(ctx context.Context, persistence *queryCyclePersistence) error {

	errCh := make(chan error)                                            // error channel
	reconnectCh := make(chan struct{}, 1)                                // reconnect channel
	btpBlockNotifCh := make(chan *types.BlockNotification, 10)           // block notification channel
	btpBlockRespCh := make(chan *btpBlockResponse, cap(btpBlockNotifCh)) // block result channel

	reconnect := func() {
		select {
		case reconnectCh <- struct{}{}:
		default:
		}
		for len(btpBlockRespCh) > 0 || len(btpBlockNotifCh) > 0 {
			select {
			case <-btpBlockRespCh: // clear block result channel
			case <-btpBlockNotifCh: // clear block notification channel
			}
		}
	}

	var err error
	processedheight := icp.StartFromHeight(ctx)
	latestHeight, err := icp.chainProvider.QueryLatestHeight(ctx)
	if err != nil {
		icp.log.Error("Error fetching block", zap.Error(err))
		return err
	}
	if processedheight > latestHeight {
		icp.log.Warn("Start height set is greater than latest height",
			zap.Int64("start height", processedheight),
			zap.Int64("latest Height", latestHeight),
		)
		processedheight = latestHeight
	}
	if processedheight <= 0 {
		processedheight = latestHeight
	}

	icp.log.Info("Start to query from height", zap.Int64("height", processedheight))
	// subscribe to monitor block
	ctxMonitorBlock, cancelMonitorBlock := context.WithCancel(ctx)
	reconnect()

	icp.firstTime = true

	blockReq := &types.BlockRequest{
		Height:       types.NewHexInt(int64(processedheight)),
		EventFilters: GetMonitorEventFilters(icp.chainProvider.PCfg.IbcHandlerAddress),
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err

		case <-icp.heightSnapshotChan:
			icp.SnapshotHeight(icp.getHeightToSave(int64(icp.latestBlock.Height)))

		case <-reconnectCh:
			cancelMonitorBlock()
			ctxMonitorBlock, cancelMonitorBlock = context.WithCancel(ctx)

			go func(ctx context.Context, cancel context.CancelFunc) {
				blockReq.Height = types.NewHexInt(processedheight)
				icp.log.Debug("Try to reconnect from", zap.Int64("height", processedheight))
				err := icp.chainProvider.client.MonitorBlock(ctx, blockReq, func(conn *websocket.Conn, v *types.BlockNotification) error {
					if !errors.Is(ctx.Err(), context.Canceled) {
						if len(v.Indexes) > 0 {
							ht, _ := v.Height.Value()
							fmt.Println("Processing for height With value", ht)
							blockHeader, err := icp.chainProvider.client.GetBlockHeaderByHeight(ht)
							if err != nil {
								icp.log.Warn("Failed to get block header",
									zap.Int64("height", ht),
									zap.Error(err),
								)
							}

							var receiptHash types.BlockHeaderResult
							_, err = codec.RLP.UnmarshalFromBytes(blockHeader.Result, &receiptHash)
							if err != nil {
								icp.log.Warn("Failed to decode block header",
									zap.Int64("height", ht),
									zap.Error(err),
								)

							}
							var eventlogs []types.EventLog
							for id := 0; id < len(v.Indexes); id++ {
								for i, index := range v.Indexes[id] {
									p := &types.ProofEventsParam{
										Index:     index,
										BlockHash: v.Hash,
										Events:    v.Events[id][i],
									}

									proofs, err := icp.chainProvider.client.GetProofForEvents(p)
									if err != nil {
										icp.log.Warn("Failed to get proof for events block header",
											zap.Int64("height", ht),
											zap.Error(err),
										)
									}
									// Processing receipt index
									serializedReceipt, err := MptProve(index, proofs[0], receiptHash.ReceiptHash)
									if err != nil {
										icp.log.Warn("Failed to get serialized receipts",
											zap.Int64("height", ht),
											zap.Error(err),
										)

									}
									var result types.TxResult
									_, err = codec.RLP.UnmarshalFromBytes(serializedReceipt, &result)
									if err != nil {
										icp.log.Warn("Failed to get serialized txresult",
											zap.Int64("height", ht),
											zap.Error(err),
										)
									}

									for j := 0; j < len(p.Events); j++ {
										serializedEventLog, err := MptProve(
											p.Events[j], proofs[j+1], common.HexBytes(result.EventLogsHash))
										if err != nil {
											icp.log.Warn("Failed to Mptprove",
												zap.Int64("height", ht),
												zap.Error(err),
											)
										}
										var el types.EventLog
										_, err = codec.RLP.UnmarshalFromBytes(serializedEventLog, &el)
										if err != nil {
											icp.log.Warn("Failed to decode eventlog",
												zap.Int64("height", ht),
												zap.Error(err),
											)
										}
										icp.log.Info("Detected eventlog ", zap.Any("height", ht),
											zap.String("eventlog", IconCosmosEventMap[string(el.Indexed[0])]))
										eventlogs = append(eventlogs, el)
									}
									icp.latestBlock = provider.LatestBlock{
										Height: uint64(ht),
									}

									ibcMessage := parseIBCMessagesFromEventlog(icp.log, eventlogs, uint64(ht))
									ibcMessageCache := processor.NewIBCMessagesCache()
									// message handler
									for _, m := range ibcMessage {
										icp.handleMessage(ctx, *m, ibcMessageCache)
									}

									validators, err := icp.chainProvider.GetProofContextByHeight(ht)
									if err != nil {
										icp.log.Warn("Failed to get proof context by Height",
											zap.Int64("height", ht),
											zap.Error(err),
										)
									}

									btpHeader, err := icp.chainProvider.GetBtpHeader(ht)
									var bHeader IconIBCHeader
									if err != nil {
										if RequiresBtpHeader(eventlogs) {
											icp.log.Warn("Failed to check btp header requirement",
												zap.Int64("height", ht),
												zap.Error(err),
											)
										}
										if btpBlockNotPresent(err) {
											bHeader = NewIconIBCHeader(nil, validators, ht)
										}
									} else {
										bHeader = NewIconIBCHeader(btpHeader, validators, int64(btpHeader.MainHeight))
									}

									ibcHeaderCache := make(processor.IBCHeaderCache)
									ibcHeaderCache[uint64(ht)] = bHeader
									err = icp.handlePathProcessorUpdate(ctx, bHeader, ibcMessageCache, ibcHeaderCache.Clone())
									if err != nil {
										reconnect()
										icp.log.Warn("Reconnect: error occured during handle block response  ",
											zap.Int64("got", ht),
										)
										break
									}

								}
							}
						} else {
							ht, _ := v.Height.Value()
							if ht%50 == 0 {
								icp.latestBlock = provider.LatestBlock{
									Height: uint64(ht),
								}
								validators, err := icp.chainProvider.GetProofContextByHeight(ht)
								if err != nil {
									fmt.Println(err)
								}
								bHeader := NewIconIBCHeader(nil, validators, ht)
								ibcHeaderCache := make(processor.IBCHeaderCache)
								ibcHeaderCache[uint64(ht)] = bHeader
								ibcMessageCache := processor.NewIBCMessagesCache()
								err = icp.handlePathProcessorUpdate(ctx, bHeader, ibcMessageCache, ibcHeaderCache.Clone())
								if err != nil {
									icp.log.Warn("Failed to handle path processor updates",
										zap.Int64("height", ht),
										zap.Error(err),
									)
								}
							}
						}
					}
					return nil
				}, func(conn *websocket.Conn) {
				}, func(conn *websocket.Conn, err error) {})
				if err != nil {
					ht := icp.getHeightToSave(processedheight)
					if ht != icp.getLastSavedHeight() {
						icp.SnapshotHeight(ht)
					}
					if errors.Is(err, context.Canceled) {
						return
					}
					time.Sleep(time.Second * 5)
					reconnect()
					icp.log.Warn("Error occured during monitor block", zap.Error(err))
				}

			}(ctxMonitorBlock, cancelMonitorBlock)
		}
	}
}

func (icp *IconChainProcessor) getHeightToSave(height int64) int64 {
	retryAfter := icp.Provider().ProviderConfig().GetFirstRetryBlockAfter()
	ht := height - int64(retryAfter)
	if ht < 0 {
		return 0
	}
	return ht
}

func (icp *IconChainProcessor) SnapshotHeight(height int64) {
	icp.log.Info("Save height for snapshot", zap.Int64("height", height))
	err := rlycommon.SnapshotHeight(icp.Provider().ChainId(), height)
	if err != nil {
		icp.log.Warn("Failed saving height snapshot for height", zap.Int64("height", height))
	}
}

func (icp *IconChainProcessor) verifyBlock(ctx context.Context, ibcHeader provider.IBCHeader) error {
	header, ok := ibcHeader.(IconIBCHeader)
	if !ok {
		return fmt.Errorf("provided header is not compatible with IBCHeader")
	}
	if icp.firstTime {
		proofContext, err := icp.chainProvider.GetProofContextByHeight(int64(header.MainHeight) - 1)
		if err != nil {
			return err
		}
		icp.verifier = &Verifier{
			nextProofContext: proofContext,
			verifiedHeight:   int64(header.MainHeight) - 1,
		}
	}

	if !ibcHeader.IsCompleteBlock() {
		icp.verifier.nextProofContext = header.Validators
		icp.verifier.verifiedHeight = int64(header.Height())
		return nil
	}

	// prevNetworkSectionHash would be nil for first block
	if icp.verifier.prevNetworkSectionHash != nil &&
		!bytes.Equal(icp.verifier.prevNetworkSectionHash, header.Header.PrevNetworkSectionHash) {
		return fmt.Errorf("failed to match prevNetworkSectionHash")
	}

	sigs, err := icp.chainProvider.GetBTPProof(int64(header.MainHeight))
	if err != nil {
		return err
	}

	decision := types.NewNetworkTypeSectionDecision(
		getSrcNetworkId(icp.chainProvider.PCfg.ICONNetworkID),
		icp.chainProvider.PCfg.BTPNetworkTypeID,
		int64(header.MainHeight),
		header.Header.Round,
		types.NetworkTypeSection{
			NextProofContextHash: header.Header.NextProofContextHash,
			NetworkSectionsRoot:  GetNetworkSectionRoot(header.Header),
		})

	valid, err := VerifyBtpProof(decision, sigs, icp.verifier.nextProofContext)
	if err != nil {
		return err
	}

	if !valid {
		return fmt.Errorf("failed to Verify block")
	}

	icp.verifier.nextProofContext = header.Validators
	icp.verifier.verifiedHeight = int64(header.Height())
	icp.verifier.prevNetworkSectionHash = types.NewNetworkSection(header.Header).Hash()
	icp.log.Debug("Verified block ",
		zap.Uint64("height", header.Height()))
	return nil
}

func (icp *IconChainProcessor) handleBTPBlockRequest(
	request *btpBlockRequest, requestCh chan *btpBlockRequest) {
	defer func() {
		time.Sleep(500 * time.Millisecond)
		requestCh <- request
	}()

	if request.response == nil {
		request.response = &btpBlockResponse{
			IsProcessed: notProcessed,
			Height:      request.height,
		}
	}

	containsEventlogs := len(request.indexes) > 0 && len(request.events) > 0
	if containsEventlogs {
		blockHeader, err := icp.chainProvider.client.GetBlockHeaderByHeight(request.height)
		if err != nil {
			request.err = errors.Wrapf(request.err, "getBlockHeader: %v", err)
			return
		}

		var receiptHash types.BlockHeaderResult
		_, err = codec.RLP.UnmarshalFromBytes(blockHeader.Result, &receiptHash)
		if err != nil {
			request.err = errors.Wrapf(err, "BlockHeaderResult.UnmarshalFromBytes: %v", err)
			return

		}

		var eventlogs []types.EventLog
		for id := 0; id < len(request.indexes); id++ {
			for i, index := range request.indexes[id] {
				p := &types.ProofEventsParam{
					Index:     index,
					BlockHash: request.hash,
					Events:    request.events[id][i],
				}

				proofs, err := icp.chainProvider.client.GetProofForEvents(p)
				if err != nil {
					request.err = errors.Wrapf(err, "GetProofForEvents: %v", err)
					return

				}

				// Processing receipt index
				serializedReceipt, err := MptProve(index, proofs[0], receiptHash.ReceiptHash)
				if err != nil {
					request.err = errors.Wrapf(err, "MPTProve Receipt: %v", err)
					return

				}
				var result types.TxResult
				_, err = codec.RLP.UnmarshalFromBytes(serializedReceipt, &result)
				if err != nil {
					request.err = errors.Wrapf(err, "Unmarshal Receipt: %v", err)
					return
				}

				for j := 0; j < len(p.Events); j++ {
					serializedEventLog, err := MptProve(
						p.Events[j], proofs[j+1], common.HexBytes(result.EventLogsHash))
					if err != nil {
						request.err = errors.Wrapf(err, "event.MPTProve: %v", err)
						return
					}
					var el types.EventLog
					_, err = codec.RLP.UnmarshalFromBytes(serializedEventLog, &el)
					if err != nil {
						request.err = errors.Wrapf(err, "event.UnmarshalFromBytes: %v", err)
						return
					}
					icp.log.Info("Detected eventlog ", zap.Int64("height", request.height),
						zap.String("eventlog", IconCosmosEventMap[string(el.Indexed[0])]))
					eventlogs = append(eventlogs, el)
				}

			}
		}
		request.response.EventLogs = eventlogs
	}

	validators, err := icp.chainProvider.GetProofContextByHeight(request.height)
	if err != nil {
		request.err = errors.Wrapf(err, "Failed to get proof context: %v", err)
		return
	}

	btpHeader, err := icp.chainProvider.GetBtpHeader(request.height)
	if err != nil {
		if RequiresBtpHeader(request.response.EventLogs) {
			request.err = errors.Wrapf(err, "Btp header required but not present: %v", err)
			return
		}
		if btpBlockNotPresent(err) {
			request.response.Header = NewIconIBCHeader(nil, validators, (request.height))
			request.response.IsProcessed = processed
			return
		}
		request.err = errors.Wrapf(err, "Failed to get btp header: %v", err)
		return
	}
	request.response.Header = NewIconIBCHeader(btpHeader, validators, int64(btpHeader.MainHeight))
	request.response.IsProcessed = processed
}

func (icp *IconChainProcessor) handlePathProcessorUpdate(ctx context.Context,
	latestHeader provider.IBCHeader, messageCache processor.IBCMessagesCache,
	ibcHeaderCache processor.IBCHeaderCache) error {

	chainID := icp.chainProvider.ChainId()
	latestHeight, _ := icp.chainProvider.QueryLatestHeight(ctx)

	inSync := false

	if latestHeight != 0 && uint64(latestHeight)-latestHeader.Height() < 3 {
		inSync = true
	}

	for _, pp := range icp.pathProcessors {
		clientID := pp.RelevantClientID(chainID)
		clientState, err := icp.clientState(ctx, clientID)
		if err != nil {
			icp.log.Error("Error fetching client state",
				zap.String("client_id", clientID),
				zap.Error(err),
			)
			continue
		}

		pp.HandleNewData(chainID, processor.ChainProcessorCacheData{
			LatestBlock:          icp.latestBlock,
			LatestHeader:         latestHeader,
			IBCMessagesCache:     messageCache,
			InSync:               inSync,
			ClientState:          clientState,
			ConnectionStateCache: icp.connectionStateCache.FilterForClient(clientID),
			ChannelStateCache:    icp.channelStateCache.FilterForClient(clientID, icp.channelConnections, icp.connectionClients),
			IBCHeaderCache:       ibcHeaderCache.Clone(),
			IsGenesis:            icp.firstTime,
		})
	}
	return nil

}

// clientState will return the most recent client state if client messages
// have already been observed for the clientID, otherwise it will query for it.
func (icp *IconChainProcessor) clientState(ctx context.Context, clientID string) (provider.ClientState, error) {
	if state, ok := icp.latestClientState[clientID]; ok {
		return state, nil
	}

	cs, err := icp.chainProvider.QueryClientStateWithoutProof(ctx, int64(icp.latestBlock.Height), clientID)
	if err != nil {
		return provider.ClientState{}, err
	}

	clientState := provider.ClientState{
		ClientID:        clientID,
		ConsensusHeight: cs.GetLatestHeight().(clienttypes.Height),
	}
	icp.latestClientState[clientID] = clientState
	return clientState, nil
}
