package wasm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avast/retry-go/v4"
	sdk "github.com/cosmos/cosmos-sdk/types"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	"github.com/cosmos/relayer/v2/relayer/common"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/cosmos/relayer/v2/relayer/provider"

	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cometbft/cometbft/types"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type WasmChainProcessor struct {
	log *zap.Logger

	chainProvider *WasmProvider

	pathProcessors processor.PathProcessors

	// indicates whether queries are in sync with latest height of the chain
	inSync bool

	// highest block
	latestBlock provider.LatestBlock

	// holds highest consensus height and header for all clients
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

	// parsed gas prices accepted by the chain (only used for metrics)
	parsedGasPrices *sdk.DecCoins

	verifier *Verifier

	heightSnapshotChan chan struct{}
}

type Verifier struct {
	Header *types.LightBlock
}

func NewWasmChainProcessor(log *zap.Logger, provider *WasmProvider, metrics *processor.PrometheusMetrics, heightSnapshot chan struct{}) *WasmChainProcessor {
	return &WasmChainProcessor{
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

var (
	inSyncNumBlocksThreshold = int64(2)
	numOffsetBlocks          = int64(2)
)

const (
	queryTimeout                = 5 * time.Second
	blockResultsQueryTimeout    = 2 * time.Minute
	latestHeightQueryRetryDelay = 1 * time.Second
	latestHeightQueryRetries    = 5

	// TODO: review transfer to providerConfig
	defaultMinQueryLoopDuration      = 1 * time.Second
	defaultBalanceUpdateWaitDuration = 60 * time.Second

	MaxBlockFetch = 100
)

// latestClientState is a map of clientID to the latest clientInfo for that client.
type latestClientState map[string]provider.ClientState

func (l latestClientState) update(ctx context.Context, clientInfo clientInfo, ccp *WasmChainProcessor) {
	existingClientInfo, ok := l[clientInfo.clientID]
	var trustingPeriod time.Duration
	if ok {
		if clientInfo.consensusHeight.LT(existingClientInfo.ConsensusHeight) {
			// height is less than latest, so no-op
			return
		}
		trustingPeriod = existingClientInfo.TrustingPeriod
	}
	// TODO
	// if trustingPeriod == 0 {
	// 	cs, err := ccp.chainProvider.QueryClientState(ctx, 0, clientInfo.clientID)
	// 	if err != nil {
	// 		ccp.log.Error(
	// 			"Failed to query client state to get trusting period",
	// 			zap.String("client_id", clientInfo.clientID),
	// 			zap.Error(err),
	// 		)
	// 		return
	// 	}
	// 	// trustingPeriod = cs.TrustingPeriod
	// }
	clientState := clientInfo.ClientState(trustingPeriod)

	// update latest if no existing state or provided consensus height is newer
	l[clientInfo.clientID] = clientState

}

// Provider returns the ChainProvider, which provides the methods for querying, assembling IBC messages, and sending transactions.
func (ccp *WasmChainProcessor) Provider() provider.ChainProvider {
	return ccp.chainProvider
}

// Set the PathProcessors that this ChainProcessor should publish relevant IBC events to.
// ChainProcessors need reference to their PathProcessors and vice-versa, handled by EventProcessorBuilder.Build().
func (ccp *WasmChainProcessor) SetPathProcessors(pathProcessors processor.PathProcessors) {
	ccp.pathProcessors = pathProcessors
}

// latestHeightWithRetry will query for the latest height, retrying in case of failure.
// It will delay by latestHeightQueryRetryDelay between attempts, up to latestHeightQueryRetries.
func (ccp *WasmChainProcessor) latestHeightWithRetry(ctx context.Context) (latestHeight int64, err error) {
	return latestHeight, retry.Do(func() error {
		latestHeightQueryCtx, cancelLatestHeightQueryCtx := context.WithTimeout(ctx, queryTimeout)
		defer cancelLatestHeightQueryCtx()
		var err error
		latestHeight, err = ccp.chainProvider.QueryLatestHeight(latestHeightQueryCtx)
		return err
	}, retry.Context(ctx), retry.Attempts(latestHeightQueryRetries), retry.Delay(latestHeightQueryRetryDelay), retry.LastErrorOnly(true), retry.OnRetry(func(n uint, err error) {
		ccp.log.Error(
			"Failed to query latest height",
			zap.Uint("attempt", n+1),
			zap.Uint("max_attempts", latestHeightQueryRetries),
			zap.Error(err),
		)
	}))
}

// nodeStatusWithRetry will query for the latest node status, retrying in case of failure.
// It will delay by latestHeightQueryRetryDelay between attempts, up to latestHeightQueryRetries.
func (ccp *WasmChainProcessor) nodeStatusWithRetry(ctx context.Context) (status *ctypes.ResultStatus, err error) {
	return status, retry.Do(func() error {
		latestHeightQueryCtx, cancelLatestHeightQueryCtx := context.WithTimeout(ctx, queryTimeout)
		defer cancelLatestHeightQueryCtx()
		var err error
		status, err = ccp.chainProvider.QueryStatus(latestHeightQueryCtx)
		return err
	}, retry.Context(ctx), retry.Attempts(latestHeightQueryRetries), retry.Delay(latestHeightQueryRetryDelay), retry.LastErrorOnly(true), retry.OnRetry(func(n uint, err error) {
		ccp.log.Error(
			"Failed to query node status",
			zap.Uint("attempt", n+1),
			zap.Uint("max_attempts", latestHeightQueryRetries),
			zap.Error(err),
		)
	}))
}

// clientState will return the most recent client state if client messages
// have already been observed for the clientID, otherwise it will query for it.
func (ccp *WasmChainProcessor) clientState(ctx context.Context, clientID string) (provider.ClientState, error) {
	if state, ok := ccp.latestClientState[clientID]; ok {
		return state, nil
	}
	cs, err := ccp.chainProvider.QueryClientState(ctx, int64(ccp.latestBlock.Height), clientID)
	if err != nil {
		return provider.ClientState{}, err
	}
	clientState := provider.ClientState{
		ClientID:        clientID,
		ConsensusHeight: cs.GetLatestHeight().(clienttypes.Height),
		// TrustingPeriod:  cs.TrustingPeriod,
	}
	ccp.latestClientState[clientID] = clientState
	return clientState, nil
}

// queryCyclePersistence hold the variables that should be retained across queryCycles.
type queryCyclePersistence struct {
	latestHeight              int64
	latestQueriedBlock        int64
	minQueryLoopDuration      time.Duration
	lastBalanceUpdate         time.Time
	balanceUpdateWaitDuration time.Duration
}

func (ccp *WasmChainProcessor) StartFromHeight(ctx context.Context) int64 {
	cfg := ccp.Provider().ProviderConfig().(*WasmProviderConfig)
	if cfg.StartHeight != 0 {
		return int64(cfg.StartHeight)
	}
	snapshotHeight, err := common.LoadSnapshotHeight(ccp.Provider().ChainId())
	if err != nil {
		ccp.log.Warn("Failed to load height from snapshot", zap.Error(err))
	} else {
		ccp.log.Info("Obtained start height from config", zap.Int64("height", snapshotHeight))
	}
	return snapshotHeight
}

// Run starts the query loop for the chain which will gather applicable ibc messages and push events out to the relevant PathProcessors.
// The initialBlockHistory parameter determines how many historical blocks should be fetched and processed before continuing with current blocks.
// ChainProcessors should obey the context and return upon context cancellation.
func (ccp *WasmChainProcessor) Run(ctx context.Context, initialBlockHistory uint64) error {
	// this will be used for persistence across query cycle loop executions
	persistence := queryCyclePersistence{
		minQueryLoopDuration:      defaultMinQueryLoopDuration,
		lastBalanceUpdate:         time.Unix(0, 0),
		balanceUpdateWaitDuration: defaultBalanceUpdateWaitDuration,
	}

	// Infinite retry to get initial latest height
	for {
		status, err := ccp.nodeStatusWithRetry(ctx)
		if err != nil {
			ccp.log.Error(
				"Failed to query latest height after max attempts",
				zap.Uint("attempts", latestHeightQueryRetries),
				zap.Error(err),
			)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			continue
		}
		persistence.latestHeight = status.SyncInfo.LatestBlockHeight
		break
	}

	// this will make initial QueryLoop iteration look back initialBlockHistory blocks in history
	latestQueriedBlock := ccp.StartFromHeight(ctx)
	if latestQueriedBlock <= 0 || latestQueriedBlock > persistence.latestHeight {
		latestQueriedBlock = persistence.latestHeight
	}

	persistence.latestQueriedBlock = int64(latestQueriedBlock)

	ccp.log.Info("Start to query from height ", zap.Int64("height", latestQueriedBlock))

	_, lightBlock, err := ccp.chainProvider.QueryLightBlock(ctx, persistence.latestQueriedBlock)
	if err != nil {
		ccp.log.Error("Failed to get ibcHeader",
			zap.Int64("height", persistence.latestQueriedBlock),
			zap.Any("error", err),
		)
		return err
	}

	ccp.verifier = &Verifier{
		Header: lightBlock,
	}

	var eg errgroup.Group
	eg.Go(func() error {
		return ccp.initializeConnectionState(ctx)
	})
	eg.Go(func() error {
		return ccp.initializeChannelState(ctx)
	})
	if err := eg.Wait(); err != nil {
		return err
	}

	ccp.log.Debug("Entering Wasm main query loop")
	if ccp.chainProvider.rangeSupport {
		numOffsetBlocks = 7
		inSyncNumBlocksThreshold = 20
		defaultQueryLoopTime := 7
		if ccp.chainProvider.PCfg.BlockRPCRefreshTime > 0 {
			defaultQueryLoopTime = ccp.chainProvider.PCfg.BlockRPCRefreshTime
		}
		persistence.minQueryLoopDuration = time.Duration(defaultQueryLoopTime) * time.Second
	}
	ticker := time.NewTicker(persistence.minQueryLoopDuration)
	defer ticker.Stop()
	for {

		select {
		case <-ctx.Done():
			return nil
		case <-ccp.heightSnapshotChan:
			ccp.SnapshotHeight(ccp.getHeightToSave(persistence.latestHeight))
		case <-ticker.C:
			ticker.Reset(persistence.minQueryLoopDuration)
			if err := ccp.queryCycle(ctx, &persistence); err != nil {
				return err
			}
		}
	}
}

// initializeConnectionState will bootstrap the connectionStateCache with the open connection state.
func (ccp *WasmChainProcessor) initializeConnectionState(ctx context.Context) error {
	// ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	// defer cancel()
	connections, err := ccp.chainProvider.QueryConnections(ctx)
	if err != nil {
		return fmt.Errorf("error querying connections: %w", err)
	}
	for _, c := range connections {
		ccp.connectionClients[c.Id] = c.ClientId
		ccp.connectionStateCache[processor.ConnectionKey{
			ConnectionID:         c.Id,
			ClientID:             c.ClientId,
			CounterpartyConnID:   c.Counterparty.ConnectionId,
			CounterpartyClientID: c.Counterparty.ClientId,
		}] = c.State == conntypes.OPEN

		ccp.log.Debug("Found open connection",
			zap.String("client-id ", c.ClientId),
			zap.String("connection-id ", c.Id),
		)
	}
	return nil
}

// initializeChannelState will bootstrap the channelStateCache with the open channel state.
func (ccp *WasmChainProcessor) initializeChannelState(ctx context.Context) error {
	// ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	// defer cancel()
	channels, err := ccp.chainProvider.QueryChannels(ctx)
	if err != nil {
		return fmt.Errorf("error querying channels: %w", err)
	}
	for _, ch := range channels {
		if len(ch.ConnectionHops) != 1 {
			ccp.log.Error("Found channel using multiple connection hops. Not currently supported, ignoring.",
				zap.String("channel_id", ch.ChannelId),
				zap.String("port_id", ch.PortId),
				zap.Strings("connection_hops", ch.ConnectionHops),
			)
			continue
		}
		ccp.channelConnections[ch.ChannelId] = ch.ConnectionHops[0]
		ccp.channelStateCache[processor.ChannelKey{
			ChannelID:             ch.ChannelId,
			PortID:                ch.PortId,
			CounterpartyChannelID: ch.Counterparty.ChannelId,
			CounterpartyPortID:    ch.Counterparty.PortId,
		}] = ch.State == chantypes.OPEN
		ccp.log.Debug("Found open channel",
			zap.String("channel-id", ch.ChannelId),
			zap.String("port-id ", ch.PortId),
			zap.String("counterparty-channel-id", ch.Counterparty.ChannelId),
			zap.String("counterparty-port-id", ch.Counterparty.PortId))
	}
	return nil
}

func (ccp *WasmChainProcessor) getBlocksToProcess(ctx context.Context, blockToRequest int64) ([]int64, error) {
	ibcHandlerAddr := ccp.chainProvider.PCfg.IbcHandlerAddress
	queryFilter := fmt.Sprintf("tx.height>=%d AND execute._contract_address='%s'",
		blockToRequest, ibcHandlerAddr)
	queryCtx, cancelQueryCtx := context.WithTimeout(ctx, blockResultsQueryTimeout)
	defer cancelQueryCtx()
	page := int(1)
	perPage := int(50)
	txsResult, err := ccp.chainProvider.BlockRPCClient.TxSearch(queryCtx, queryFilter, true, &page, &perPage, "asc")
	var resultArr []int64
	if err != nil {
		return []int64{}, err
	}
	for _, tx := range txsResult.Txs {
		resultArr = append(resultArr, tx.Height)
	}
	return resultArr, nil
}

func (ccp *WasmChainProcessor) shouldSkipProcessBlock(blocks []int64, block int64) bool {
	if !ccp.chainProvider.rangeSupport || len(blocks) == 0 {
		return false
	}
	for _, blk := range blocks {
		if blk == block {
			return false
		}
	}
	return true
}

func findMaxBlock(blocks []int64) int64 {
	if len(blocks) == 0 {
		return 0
	}
	return blocks[len(blocks)-1]
}

func (ccp *WasmChainProcessor) queryCycle(ctx context.Context, persistence *queryCyclePersistence) error {
	status, err := ccp.nodeStatusWithRetry(ctx)
	if err != nil {
		// don't want to cause WasmChainProcessor to quit here, can retry again next cycle.
		ccp.log.Error(
			"Failed to query node status after max attempts",
			zap.Uint("attempts", latestHeightQueryRetries),
			zap.Error(err),
		)

		// TODO: Save height when node status is false?
		// ccp.SnapshotHeight(ccp.getHeightToSave(status.SyncInfo.LatestBlockHeight))
		return nil
	}

	persistence.latestHeight = status.SyncInfo.LatestBlockHeight
	// ccp.chainProvider.setCometVersion(ccp.log, status.NodeInfo.Version)

	if ccp.metrics != nil {
		ccp.CollectMetrics(ctx, persistence)
	}

	// used at the end of the cycle to send signal to path processors to start processing if both chains are in sync and no new messages came in this cycle
	firstTimeInSync := false

	if !ccp.inSync {
		if (persistence.latestHeight - persistence.latestQueriedBlock) < inSyncNumBlocksThreshold {
			ccp.inSync = true
			firstTimeInSync = true
			ccp.log.Info("Chain is in sync")
		} else {
			ccp.log.Info("Chain is not yet in sync",
				zap.Int64("latest_queried_block", persistence.latestQueriedBlock),
				zap.Int64("latest_height", persistence.latestHeight),
				zap.Int64("delta", (persistence.latestHeight-persistence.latestQueriedBlock)),
			)
		}
	}

	ibcMessagesCache := processor.NewIBCMessagesCache()
	ibcHeaderCache := make(processor.IBCHeaderCache)
	ppChanged := false

	newLatestQueriedBlock := persistence.latestQueriedBlock
	chainID := ccp.chainProvider.ChainId()
	var latestHeader provider.IBCHeader

	syncUpHeight := func() int64 {
		if ccp.chainProvider.rangeSupport {
			return persistence.latestHeight - numOffsetBlocks
		}
		if persistence.latestHeight-persistence.latestQueriedBlock > MaxBlockFetch {
			return persistence.latestQueriedBlock + MaxBlockFetch
		}
		return persistence.latestHeight - 1
	}
	var blocks []int64
	heighttoSync := syncUpHeight()
	delta := persistence.latestHeight - persistence.latestQueriedBlock
	minDelta := 7
	if ccp.chainProvider.PCfg.BlockRPCMinDelta > 0 {
		minDelta = ccp.chainProvider.PCfg.BlockRPCMinDelta
	}
	if ccp.chainProvider.rangeSupport && delta > int64(minDelta) {
		status, err := ccp.chainProvider.BlockRPCClient.Status(ctx)
		if err != nil {
			ccp.log.Warn("Error occurred fetching block status", zap.Error(err))
			return nil
		}
		ccp.log.Debug("Fetching range block",
			zap.Int64("last_height", persistence.latestQueriedBlock),
			zap.Int64("latest_height", status.SyncInfo.LatestBlockHeight),
			zap.Int64("delta", delta))
		persistence.latestHeight = status.SyncInfo.LatestBlockHeight
		heighttoSync = syncUpHeight()
		if persistence.latestQueriedBlock > status.SyncInfo.LatestBlockHeight {
			ccp.log.Debug("resetting range block",
				zap.Int64("last_height", persistence.latestQueriedBlock),
				zap.Int64("latest_height", status.SyncInfo.LatestBlockHeight))
			persistence.latestQueriedBlock = status.SyncInfo.LatestBlockHeight
			return nil
		}
		if status.SyncInfo.CatchingUp {
			ccp.log.Debug("chain is still catching up",
				zap.Int64("last_height", persistence.latestQueriedBlock),
				zap.Int64("latest_height", status.SyncInfo.LatestBlockHeight))
			return nil
		}
		if (persistence.latestQueriedBlock + 1) >= persistence.latestHeight {
			return nil
		}
		if (persistence.latestQueriedBlock + 1) > syncUpHeight() {
			return nil
		}
		blocks, err = ccp.getBlocksToProcess(ctx, persistence.latestQueriedBlock+1)
		if err != nil {
			ccp.log.Warn("error occurred getting blocks", zap.Error(err))
			return nil
		}
		maxBlock := findMaxBlock(blocks)
		if maxBlock != 0 {
			heighttoSync = maxBlock
		} else {
			persistence.latestQueriedBlock = syncUpHeight() - 1
		}
	}
	for i := persistence.latestQueriedBlock + 1; i <= heighttoSync; i++ {
		var eg errgroup.Group
		var blockRes *ctypes.ResultBlockResults
		var lightBlock *types.LightBlock
		var h provider.IBCHeader
		i := i
		if ccp.shouldSkipProcessBlock(blocks, i) {
			newLatestQueriedBlock = i
			ccp.log.Debug("Skipping block", zap.Any("height", i),
				zap.Any("last_height", persistence.latestQueriedBlock))
			continue
		}
		eg.Go(func() (err error) {
			queryCtx, cancelQueryCtx := context.WithTimeout(ctx, blockResultsQueryTimeout)
			defer cancelQueryCtx()
			blockRes, err = ccp.chainProvider.RPCClient.BlockResults(queryCtx, &i)
			return err
		})
		eg.Go(func() (err error) {
			queryCtx, cancelQueryCtx := context.WithTimeout(ctx, queryTimeout)
			defer cancelQueryCtx()
			h, lightBlock, err = ccp.chainProvider.QueryLightBlock(queryCtx, i)
			return err
		})

		if err := eg.Wait(); err != nil {
			ccp.log.Warn("Error querying block data", zap.Error(err))
			break
		}

		ccp.log.Debug(
			"Queried block",
			zap.Int64("height", i),
			zap.Int64("latest", persistence.latestHeight),
			zap.Int64("delta", persistence.latestHeight-i),
		)

		latestHeader = h

		if err := ccp.Verify(ctx, lightBlock); err != nil {
			ccp.log.Warn("Failed to verify block", zap.Int64("height", blockRes.Height), zap.Error(err))
			return err
		}

		heightUint64 := uint64(i)

		ccp.latestBlock = provider.LatestBlock{
			Height: heightUint64,
		}

		ibcHeaderCache[heightUint64] = latestHeader
		ppChanged = true

		base64Encoded := ccp.chainProvider.cometLegacyEncoding

		for _, tx := range blockRes.TxsResults {
			if tx.Code != 0 {
				// tx was not successful
				continue
			}
			messages := ibcMessagesFromEvents(ccp.log, tx.Events, chainID, heightUint64, ccp.chainProvider.PCfg.IbcHandlerAddress, base64Encoded)

			for _, m := range messages {
				ccp.log.Info("Detected eventlog", zap.String("eventlog", m.eventType),
					zap.Uint64("height", heightUint64))
				ccp.handleMessage(ctx, m, ibcMessagesCache)
			}
		}
		newLatestQueriedBlock = i
	}
	if newLatestQueriedBlock == persistence.latestQueriedBlock {
		return nil
	}

	if !ppChanged {
		if firstTimeInSync {
			for _, pp := range ccp.pathProcessors {
				pp.ProcessBacklogIfReady()
			}
		}
		persistence.latestQueriedBlock = newLatestQueriedBlock
		return nil
	}

	for _, pp := range ccp.pathProcessors {
		clientID := pp.RelevantClientID(chainID)
		clientState, err := ccp.clientState(ctx, clientID)
		if err != nil {
			ccp.log.Error("Error fetching client state",
				zap.String("client_id", clientID),
				zap.Int64("latest_queried_block", newLatestQueriedBlock),
				zap.Int64("last_queried_block", persistence.latestQueriedBlock),
				zap.Error(err),
			)
		}

		pp.HandleNewData(chainID, processor.ChainProcessorCacheData{
			LatestBlock:          ccp.latestBlock,
			LatestHeader:         latestHeader,
			IBCMessagesCache:     ibcMessagesCache.Clone(),
			InSync:               ccp.inSync,
			ClientState:          clientState,
			ConnectionStateCache: ccp.connectionStateCache.FilterForClient(clientID),
			ChannelStateCache:    ccp.channelStateCache.FilterForClient(clientID, ccp.channelConnections, ccp.connectionClients),
			IBCHeaderCache:       ibcHeaderCache.Clone(),
		})
	}
	persistence.latestQueriedBlock = newLatestQueriedBlock
	return nil
}

func (ccp *WasmChainProcessor) getHeightToSave(height int64) int64 {
	retryAfter := ccp.Provider().ProviderConfig().GetFirstRetryBlockAfter()
	ht := height - int64(retryAfter)
	if ht < 0 {
		return 0
	}
	return ht
}

func (ccp *WasmChainProcessor) SnapshotHeight(height int64) {
	ccp.log.Info("Save height for snapshot", zap.Int64("height", height))
	err := common.SnapshotHeight(ccp.Provider().ChainId(), height)
	if err != nil {
		ccp.log.Warn("Failed saving height snapshot for height", zap.Int64("height", height))
	}
}

func (ccp *WasmChainProcessor) CollectMetrics(ctx context.Context, persistence *queryCyclePersistence) {
	ccp.CurrentBlockHeight(ctx, persistence)

	// Wait a while before updating the balance
	if time.Since(persistence.lastBalanceUpdate) > persistence.balanceUpdateWaitDuration {
		// ccp.CurrentRelayerBalance(ctx)
		persistence.lastBalanceUpdate = time.Now()
	}
}

func (ccp *WasmChainProcessor) CurrentBlockHeight(ctx context.Context, persistence *queryCyclePersistence) {
	ccp.metrics.SetLatestHeight(ccp.chainProvider.ChainId(), persistence.latestHeight)
}

func (ccp *WasmChainProcessor) Verify(ctx context.Context, untrusted *types.LightBlock) error {

	// Ensure that +2/3 of new validators signed correctly.
	if err := untrusted.ValidatorSet.VerifyCommitLight(ccp.verifier.Header.ChainID, untrusted.Commit.BlockID,
		untrusted.Header.Height, untrusted.Commit); err != nil {
		return fmt.Errorf("invalid header: %v", err)
	}

	ccp.verifier.Header = untrusted
	return nil

}

// func (ccp *WasmChainProcessor) CurrentRelayerBalance(ctx context.Context) {
// 	// memoize the current gas prices to only show metrics for "interesting" denoms
// 	if ccp.parsedGasPrices == nil {
// 		gp, err := sdk.ParseDecCoins(ccp.chainProvider.PCfg.GasPrices)
// 		if err != nil {
// 			ccp.log.Error(
// 				"Failed to parse gas prices",
// 				zap.Error(err),
// 			)
// 		}
// 		ccp.parsedGasPrices = &gp
// 	}

// 	// Get the balance for the chain provider's key
// 	relayerWalletBalance, err := ccp.chainProvider.QueryBalance(ctx, ccp.chainProvider.Key())
// 	if err != nil {
// 		ccp.log.Error(
// 			"Failed to query relayer balance",
// 			zap.Error(err),
// 		)
// 	}

// 	// Print the relevant gas prices
// 	for _, gasDenom := range *ccp.parsedGasPrices {
// 		for _, balance := range relayerWalletBalance {
// 			if balance.Denom == gasDenom.Denom {
// 				// Convert to a big float to get a float64 for metrics
// 				f, _ := big.NewFloat(0.0).SetInt(balance.Amount.BigInt()).Float64()
// 				ccp.metrics.SetWalletBalance(ccp.chainProvider.ChainId(), ccp.chainProvider.Key(), balance.Denom, f)
// 			}
// 		}
// 	}
// }
