package wasm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	"github.com/avast/retry-go/v4"
	abci "github.com/cometbft/cometbft/abci/types"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	tmclient "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"
	"github.com/icon-project/IBC-Integration/libraries/go/common/icon"
	"go.uber.org/zap"

	querytypes "github.com/cosmos/cosmos-sdk/types/query"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v7/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"

	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/cosmos/relayer/v2/relayer/chains/wasm/types"
	"github.com/cosmos/relayer/v2/relayer/common"
	"github.com/cosmos/relayer/v2/relayer/provider"
)

const (
	PaginationDelay = 10 * time.Millisecond
	NOT_IMPLEMENTED = " :: Not implemented for WASM"
)

func (ap *WasmProvider) QueryTx(ctx context.Context, hashHex string) (*provider.RelayerTxResponse, error) {
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, err
	}

	resp, err := ap.RPCClient.Tx(ctx, hash, true)
	if err != nil {
		return nil, err
	}

	events := parseEventsFromResponseDeliverTx(resp.TxResult)

	return &provider.RelayerTxResponse{
		Height: resp.Height,
		TxHash: string(hash),
		Code:   resp.TxResult.Code,
		Data:   string(resp.TxResult.Data),
		Events: events,
	}, nil

}
func (ap *WasmProvider) QueryTxs(ctx context.Context, page, limit int, events []string) ([]*provider.RelayerTxResponse, error) {
	if len(events) == 0 {
		return nil, errors.New("must declare at least one event to search")
	}

	if page <= 0 {
		return nil, errors.New("page must greater than 0")
	}

	if limit <= 0 {
		return nil, errors.New("limit must greater than 0")
	}

	res, err := ap.RPCClient.TxSearch(ctx, strings.Join(events, " AND "), true, &page, &limit, "")
	if err != nil {
		return nil, err
	}

	// Currently, we only call QueryTxs() in two spots and in both of them we are expecting there to only be,
	// at most, one tx in the response. Because of this we don't want to initialize the slice with an initial size.
	var txResps []*provider.RelayerTxResponse
	for _, tx := range res.Txs {
		relayerEvents := parseEventsFromResponseDeliverTx(tx.TxResult)
		txResps = append(txResps, &provider.RelayerTxResponse{
			Height: tx.Height,
			TxHash: string(tx.Hash),
			Code:   tx.TxResult.Code,
			Data:   string(tx.TxResult.Data),
			Events: relayerEvents,
		})
	}
	return txResps, nil

}

// parseEventsFromResponseDeliverTx parses the events from a ResponseDeliverTx and builds a slice
// of provider.RelayerEvent's.
// TODO: Comet check needed?
func parseEventsFromResponseDeliverTx(resp abci.ResponseDeliverTx) []provider.RelayerEvent {
	var events []provider.RelayerEvent

	for _, event := range resp.Events {
		attributes := make(map[string]string)
		for _, attribute := range event.Attributes {
			attributes[string(attribute.Key)] = string(attribute.Value)
		}
		events = append(events, provider.RelayerEvent{
			EventType:  event.Type,
			Attributes: attributes,
		})
	}
	return events
}

func (ap *WasmProvider) QueryLatestHeight(ctx context.Context) (int64, error) {

	stat, err := ap.RPCClient.Status(ctx)
	if err != nil {
		return -1, err
	} else if stat.SyncInfo.CatchingUp {
		return -1, fmt.Errorf("node at %s running chain %s not caught up", ap.PCfg.RPCAddr, ap.PCfg.ChainID)
	}
	return stat.SyncInfo.LatestBlockHeight, nil
}

// QueryIBCHeader returns the IBC compatible block header at a specific height.
func (ap *WasmProvider) QueryIBCHeader(ctx context.Context, h int64) (provider.IBCHeader, error) {
	if h == 0 {
		return nil, fmt.Errorf("No header at height 0")
	}
	lightBlock, err := ap.LightProvider.LightBlock(ctx, h)
	if err != nil {
		return nil, err
	}

	return NewWasmIBCHeaderFromLightBlock(lightBlock), nil
}

func (ap *WasmProvider) QueryLightBlock(ctx context.Context, h int64) (provider.IBCHeader, *tmtypes.LightBlock, error) {
	if h == 0 {
		return nil, nil, fmt.Errorf("No header at height 0")
	}
	lightBlock, err := ap.LightProvider.LightBlock(ctx, h)
	if err != nil {
		return nil, nil, err
	}

	return NewWasmIBCHeaderFromLightBlock(lightBlock), lightBlock, nil
}

// query packet info for sequence
func (ap *WasmProvider) QuerySendPacket(ctx context.Context, srcChanID, srcPortID string, sequence uint64) (provider.PacketInfo, error) {
	return provider.PacketInfo{}, fmt.Errorf("Not implemented for Wasm")
}
func (ap *WasmProvider) QueryRecvPacket(ctx context.Context, dstChanID, dstPortID string, sequence uint64) (provider.PacketInfo, error) {
	return provider.PacketInfo{}, fmt.Errorf("Not implemented for Wasm")
}

// bank
func (ap *WasmProvider) QueryBalance(ctx context.Context, keyName string) (sdk.Coins, error) {
	addr, err := ap.ShowAddress(keyName)
	if err != nil {
		return nil, err
	}

	return ap.QueryBalanceWithAddress(ctx, addr)
}

func (ap *WasmProvider) QueryBalanceWithAddress(ctx context.Context, address string) (sdk.Coins, error) {
	qc := bankTypes.NewQueryClient(ap)
	p := DefaultPageRequest()
	coins := sdk.Coins{}

	for {
		res, err := qc.AllBalances(ctx, &bankTypes.QueryAllBalancesRequest{
			Address:    address,
			Pagination: p,
		})
		if err != nil {
			return nil, err
		}

		coins = append(coins, res.Balances...)
		next := res.GetPagination().GetNextKey()
		if len(next) == 0 {
			break
		}

		time.Sleep(PaginationDelay)
		p.Key = next
	}
	return coins, nil
}

func DefaultPageRequest() *querytypes.PageRequest {
	return &querytypes.PageRequest{
		Key:        []byte(""),
		Offset:     0,
		Limit:      1000,
		CountTotal: false,
	}
}

// staking
func (ap *WasmProvider) QueryUnbondingPeriod(context.Context) (time.Duration, error) {
	// move to provider, panic
	return 0, nil
}

// ics 02 - client
func (ap *WasmProvider) QueryClientState(ctx context.Context, height int64, clientid string) (ibcexported.ClientState, error) {
	clientStateRes, err := ap.QueryClientStateResponse(ctx, height, clientid)
	if err != nil {
		return nil, err
	}

	clientStateExported, err := clienttypes.UnpackClientState(clientStateRes.ClientState)
	if err != nil {
		return nil, err
	}
	return clientStateExported, nil
}

// TODO: Check revision number
func (ap *WasmProvider) QueryClientStateResponse(ctx context.Context, height int64, srcClientId string) (*clienttypes.QueryClientStateResponse, error) {

	clS, err := ap.QueryClientStateContract(ctx, srcClientId)
	if err != nil {
		return nil, err
	}
	anyClientState, err := clienttypes.PackClientState(clS)
	if err != nil {
		return nil, err
	}

	storageKey := getStorageKeyFromPath(common.GetClientStateCommitmentKey(srcClientId))
	proof, err := ap.QueryWasmProof(ctx, storageKey, height)
	if err != nil {
		return nil, err
	}

	return &clienttypes.QueryClientStateResponse{
		ClientState: anyClientState,
		Proof:       proof,
		ProofHeight: clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (ap *WasmProvider) QueryClientStateContract(ctx context.Context, clientId string) (*icon.ClientState, error) {
	clientStateParam, err := types.NewClientState(clientId).Bytes()
	if err != nil {
		return nil, err
	}

	clientState, err := ap.QueryIBCHandlerContractProcessed(ctx, clientStateParam)
	if err != nil {
		return nil, err
	}

	cdc := codec.NewProtoCodec(ap.Cdc.InterfaceRegistry)

	clientS, err := clienttypes.UnmarshalClientState(cdc, clientState)
	if err != nil {
		return nil, err
	}

	iconClientState, ok := clientS.(*icon.ClientState)
	if !ok {
		return nil, fmt.Errorf("error casting to icon.ClientState")
	}

	return iconClientState, nil
}

func (ap *WasmProvider) QueryConnectionContract(ctx context.Context, connId string) (*conntypes.ConnectionEnd, error) {
	connStateParam, err := types.NewConnection(connId).Bytes()
	if err != nil {
		return nil, err
	}

	connState, err := ap.QueryIBCHandlerContractProcessed(ctx, connStateParam)
	if err != nil {
		return nil, err
	}

	var connS conntypes.ConnectionEnd
	if err := proto.Unmarshal(connState, &connS); err != nil {
		return nil, err
	}

	return &connS, nil
}

func (ap *WasmProvider) QueryChannelContractNoRetry(ctx context.Context, portId, channelId string) (*chantypes.Channel, error) {
	channelStateParam, err := types.NewChannel(portId, channelId).Bytes()
	if err != nil {
		return nil, err
	}

	channelState, err := ap.QueryIBCHandlerContractNoRetry(ctx, channelStateParam)
	if err != nil {
		return nil, err
	}

	var channelS chantypes.Channel
	if err = proto.Unmarshal(channelState, &channelS); err != nil {
		return nil, err
	}
	return &channelS, nil
}

func (ap *WasmProvider) QueryClientConsensusState(ctx context.Context, chainHeight int64, clientid string, clientHeight ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {

	consensusStateParam, err := types.NewConsensusStateByHeight(clientid, uint64(clientHeight.GetRevisionHeight())).Bytes()
	if err != nil {
		return nil, err
	}
	consensusState, err := ap.QueryIBCHandlerContractNoRetry(ctx, consensusStateParam)
	if err != nil {
		return nil, err
	}

	cdc := codec.NewProtoCodec(ap.Cdc.InterfaceRegistry)
	csState, err := clienttypes.UnmarshalConsensusState(cdc, consensusState)
	if err != nil {
		return nil, err
	}

	anyConsensusState, err := clienttypes.PackConsensusState(csState)
	if err != nil {
		return nil, err
	}
	return clienttypes.NewQueryConsensusStateResponse(anyConsensusState, nil, clienttypes.NewHeight(0, uint64(chainHeight))), nil
}

func (ap *WasmProvider) QueryIBCHandlerContract(ctx context.Context, param wasmtypes.RawContractMessage) (op *wasmtypes.QuerySmartContractStateResponse, err error) {
	return op, retry.Do(func() error {
		done := ap.SetSDKContext()
		defer done()
		op, err = ap.QueryClient.SmartContractState(ctx, &wasmtypes.QuerySmartContractStateRequest{
			Address:   ap.PCfg.IbcHandlerAddress,
			QueryData: param,
		})
		return err
	}, retry.Context(ctx), retry.Attempts(latestHeightQueryRetries), retry.Delay(50*time.Millisecond), retry.LastErrorOnly(true), retry.OnRetry(func(n uint, err error) {
		ap.log.Error(
			"Failed to query",
			zap.Uint("attempt", n+1),
			zap.Uint("max_attempts", latestHeightQueryRetries),
			zap.Any("Param", param),
			zap.Error(err),
		)
	}))
}

func (ap *WasmProvider) QueryIBCHandlerContractNoRetry(ctx context.Context, param wasmtypes.RawContractMessage) ([]byte, error) {
	done := ap.SetSDKContext()
	defer done()
	resp, err := ap.QueryClient.SmartContractState(ctx, &wasmtypes.QuerySmartContractStateRequest{
		Address:   ap.PCfg.IbcHandlerAddress,
		QueryData: param,
	})
	if err != nil {
		ap.log.Error(
			"Failed to query",
			zap.Any("Param", param),
			zap.Error(err),
		)
		return nil, err
	}
	return ProcessContractResponse(resp)
}

func (ap *WasmProvider) QueryIBCHandlerContractProcessed(ctx context.Context, param wasmtypes.RawContractMessage) ([]byte, error) {
	res, err := ap.QueryIBCHandlerContract(ctx, param)
	if err != nil {
		return nil, err
	}
	return ProcessContractResponse(res)
}

func (ap *WasmProvider) QueryUpgradedClient(ctx context.Context, height int64) (*clienttypes.QueryClientStateResponse, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryUpgradedConsState(ctx context.Context, height int64) (*clienttypes.QueryConsensusStateResponse, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryConsensusState(ctx context.Context, height int64) (ibcexported.ConsensusState, int64, error) {

	commit, err := ap.RPCClient.Commit(ctx, &height)
	if err != nil {
		return &tmclient.ConsensusState{}, 0, err
	}

	page := 1
	count := 10_000

	nextHeight := height + 1
	nextVals, err := ap.RPCClient.Validators(ctx, &nextHeight, &page, &count)
	if err != nil {
		return &tmclient.ConsensusState{}, 0, err
	}

	state := &tmclient.ConsensusState{
		Timestamp:          commit.Time,
		Root:               commitmenttypes.NewMerkleRoot(commit.AppHash),
		NextValidatorsHash: tmtypes.NewValidatorSet(nextVals.Validators).Hash(),
	}

	return state, height, nil
}

func (ap *WasmProvider) getAllPorts(ctx context.Context) ([]string, error) {
	param, err := types.NewGetAllPorts().Bytes()
	if err != nil {
		return make([]string, 0), err
	}
	op, err := ap.QueryIBCHandlerContract(ctx, param)
	if err != nil {
		return make([]string, 0), err
	}
	resp := op.Data.Bytes()
	var ports []string
	err = json.Unmarshal(resp, &ports)
	if err != nil {
		return make([]string, 0), nil
	}
	return ports, nil
}

func (ap *WasmProvider) getNextSequence(ctx context.Context, methodName string) (int, error) {
	switch methodName {
	case MethodGetNextClientSequence:
		param, err := types.NewNextClientSequence().Bytes()
		if err != nil {
			return 0, err
		}

		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}

		return byteToInt(op.Data.Bytes())

	case MethodGetNextChannelSequence:
		param, err := types.NewNextChannelSequence().Bytes()
		if err != nil {
			return 0, err
		}
		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}
		return byteToInt(op.Data.Bytes())

	case MethodGetNextConnectionSequence:
		param, err := types.NewNextConnectionSequence().Bytes()
		if err != nil {
			return 0, err
		}
		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}
		return byteToInt(op.Data.Bytes())

	default:
		return 0, errors.New("Invalid method name")
	}
}

func (ap *WasmProvider) QueryClients(ctx context.Context) (clienttypes.IdentifiedClientStates, error) {

	seq, err := ap.getNextSequence(ctx, MethodGetNextClientSequence)
	if err != nil {
		return nil, err
	}

	if seq == 0 {
		return nil, nil
	}

	identifiedClientStates := make(clienttypes.IdentifiedClientStates, 0)
	for i := 0; i <= int(seq)-1; i++ {
		clientIdentifier := common.GetIdentifier(common.IconLightClient, i)
		clientState, err := ap.QueryClientStateContract(ctx, clientIdentifier)
		if err != nil {
			return nil, err
		}
		identifiedClientStates = append(identifiedClientStates, clienttypes.NewIdentifiedClientState(clientIdentifier, clientState))

	}
	return identifiedClientStates, nil
}

// ics 03 - connection
func (ap *WasmProvider) QueryConnection(ctx context.Context, height int64, connectionid string) (*conntypes.QueryConnectionResponse, error) {
	connectionStateParams, err := types.NewConnection(connectionid).Bytes()
	if err != nil {
		return nil, err
	}

	connState, err := ap.QueryIBCHandlerContractProcessed(ctx, connectionStateParams)
	if err != nil {
		return nil, err
	}

	var conn conntypes.ConnectionEnd
	err = proto.Unmarshal(connState, &conn)
	if err != nil {
		return nil, err
	}

	storageKey := getStorageKeyFromPath(common.GetConnectionCommitmentKey(connectionid))
	connProof, err := ap.QueryWasmProof(ctx, storageKey, height)
	if err != nil {
		return nil, err
	}

	return conntypes.NewQueryConnectionResponse(conn, connProof, clienttypes.NewHeight(0, uint64(height))), nil
}

func (ap *WasmProvider) QueryWasmProof(ctx context.Context, storageKey []byte, height int64) ([]byte, error) {
	done := ap.SetSDKContext()
	defer done()
	ibcAddr, err := sdk.AccAddressFromBech32(ap.PCfg.IbcHandlerAddress)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(fmt.Sprintf("%s%x%x", WASM_CONTRACT_PREFIX, ibcAddr.Bytes(), storageKey))
	if err != nil {
		return nil, err
	}

	if height > 2 {
		height--
	}

	req := abci.RequestQuery{
		Path:   "store/wasm/key",
		Data:   key,
		Prove:  true,
		Height: height,
	}

	opts := rpcclient.ABCIQueryOptions{
		Height: req.Height,
		Prove:  req.Prove,
	}
	result, err := ap.RPCClient.ABCIQueryWithOptions(ctx, req.Path, req.Data, opts)
	if err != nil {
		return nil, err
	}

	proof, err := commitmenttypes.ConvertProofs(result.Response.ProofOps)
	if err != nil {
		return nil, err
	}

	proofBytes, err := proto.Marshal(&proof)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil

}

func (ap *WasmProvider) QueryConnections(ctx context.Context) (conns []*conntypes.IdentifiedConnection, err error) {

	seq, err := ap.getNextSequence(ctx, MethodGetNextConnectionSequence)
	if err != nil {
		return nil, err
	}

	if seq == 0 {
		return nil, nil
	}

	for i := 0; i <= int(seq)-1; i++ {
		connectionId := common.GetIdentifier(common.ConnectionKey, i)
		conn, err := ap.QueryConnectionContract(ctx, connectionId)
		if err != nil {
			continue
		}

		// Only return open conenctions
		if conn.State == conntypes.OPEN {
			identifiedConn := conntypes.IdentifiedConnection{
				Id:           connectionId,
				ClientId:     conn.ClientId,
				Versions:     conn.Versions,
				State:        conn.State,
				Counterparty: conn.Counterparty,
				DelayPeriod:  conn.DelayPeriod,
			}
			conns = append(conns, &identifiedConn)
		}
	}

	return conns, nil
}

func (ap *WasmProvider) QueryConnectionsUsingClient(ctx context.Context, height int64, clientid string) (*conntypes.QueryConnectionsResponse, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) GenerateConnHandshakeProof(ctx context.Context, height int64, clientId, connId string) (clientState ibcexported.ClientState,
	clientStateProof []byte, consensusProof []byte, connectionProof []byte,
	connectionProofHeight ibcexported.Height, err error) {

	clientResponse, err := ap.QueryClientStateResponse(ctx, height, clientId)
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	anyClientState := clientResponse.ClientState
	clientState_, err := clienttypes.UnpackClientState(anyClientState)
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	connStorageKey := getStorageKeyFromPath(common.GetConnectionCommitmentKey(connId))
	proofConnBytes, err := ap.QueryWasmProof(ctx, connStorageKey, height)
	if err != nil {
		return nil, nil, nil, nil, nil, err

	}

	consStorageKey := getStorageKeyFromPath(common.GetConsensusStateCommitmentKey(clientId, big.NewInt(0), big.NewInt(height)))
	proofConsensusBytes, err := ap.QueryWasmProof(ctx, consStorageKey, height)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return clientState_, clientResponse.GetProof(), proofConsensusBytes, proofConnBytes, clienttypes.NewHeight(0, uint64(height)), nil
}

// ics 04 - channel
func (ap *WasmProvider) QueryChannel(ctx context.Context, height int64, channelid, portid string) (chanRes *chantypes.QueryChannelResponse, err error) {
	channelParams, err := types.NewChannel(portid, channelid).Bytes()
	if err != nil {
		return nil, err
	}

	channelState, err := ap.QueryIBCHandlerContractProcessed(ctx, channelParams)
	if err != nil {
		return nil, err
	}

	if channelState == nil {
		return nil, err
	}

	var channelS chantypes.Channel
	if err := proto.Unmarshal(channelState, &channelS); err != nil {
		return nil, err
	}

	storageKey := getStorageKeyFromPath(common.GetChannelCommitmentKey(portid, channelid))
	proof, err := ap.QueryWasmProof(ctx, storageKey, height)
	if err != nil {
		return nil, err
	}

	return chantypes.NewQueryChannelResponse(channelS, proof, clienttypes.NewHeight(0, uint64(height))), nil
}

func (ap *WasmProvider) QueryChannelClient(ctx context.Context, height int64, channelid, portid string) (*clienttypes.IdentifiedClientState, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryConnectionChannels(ctx context.Context, height int64, connectionid string) ([]*chantypes.IdentifiedChannel, error) {
	allChannel, err := ap.QueryChannels(ctx)
	if err != nil {
		return nil, fmt.Errorf("error querying Channels %v", err)
	}
	var identifiedChannels []*chantypes.IdentifiedChannel
	for _, c := range allChannel {
		if c.ConnectionHops[0] == connectionid {
			identifiedChannels = append(identifiedChannels, c)
		}
	}
	return identifiedChannels, nil
}

func (ap *WasmProvider) QueryChannels(ctx context.Context) ([]*chantypes.IdentifiedChannel, error) {
	nextSeq, err := ap.getNextSequence(ctx, MethodGetNextChannelSequence)
	if err != nil {
		return nil, err
	}
	var channels []*chantypes.IdentifiedChannel

	allPorts, err := ap.getAllPorts(ctx)
	if err != nil {
		return nil, err
	}
	if allPorts == nil || len(allPorts) <= 0 {
		return channels, nil
	}

	for i := 0; i <= int(nextSeq)-1; i++ {
		for _, portId := range allPorts {
			channelId := common.GetIdentifier(common.ChannelKey, i)
			channel, err := ap.QueryChannelContractNoRetry(ctx, portId, channelId)
			if err != nil {
				continue
			}

			// check if the channel is open
			if channel.State == chantypes.OPEN {
				identifiedChannel := chantypes.IdentifiedChannel{
					State:          channel.State,
					Ordering:       channel.Ordering,
					Counterparty:   channel.Counterparty,
					ConnectionHops: channel.ConnectionHops,
					Version:        channel.Version,
					PortId:         portId,
					ChannelId:      channelId,
				}
				channels = append(channels, &identifiedChannel)
			}
		}
	}

	return channels, nil
}

func (ap *WasmProvider) QueryPacketCommitments(ctx context.Context, height uint64, channelid, portid string) (commitments *chantypes.QueryPacketCommitmentsResponse, err error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryPacketAcknowledgements(ctx context.Context, height uint64, channelid, portid string) (acknowledgements []*chantypes.PacketState, err error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryUnreceivedPackets(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryUnreceivedAcknowledgements(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	panic(fmt.Sprintf("%s%s", ap.ChainName(), NOT_IMPLEMENTED))
}

func (ap *WasmProvider) QueryNextSeqRecv(ctx context.Context, height int64, channelid, portid string) (recvRes *chantypes.QueryNextSequenceReceiveResponse, err error) {
	nextSeqRecvParams, err := types.NewNextSequenceReceive(portid, channelid).Bytes()
	if err != nil {
		return nil, err
	}
	nextSeqRecv, err := ap.QueryIBCHandlerContract(ctx, nextSeqRecvParams)
	if err != nil {
		return nil, err
	}
	var seq uint64
	if err := json.Unmarshal(nextSeqRecv.Data, &seq); err != nil {
		return nil, err
	}

	proof, err := ap.QueryWasmProof(ctx, common.MustHexStrToBytes(STORAGEKEY__NextSequenceReceive), height)
	if err != nil {
		return nil, err
	}

	return &chantypes.QueryNextSequenceReceiveResponse{
		NextSequenceReceive: seq,
		Proof:               proof,
		ProofHeight:         clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (ap *WasmProvider) QueryPacketCommitment(ctx context.Context, height int64, channelid, portid string, seq uint64) (comRes *chantypes.QueryPacketCommitmentResponse, err error) {
	pktCommitmentParams, err := types.NewPacketCommitment(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}
	pktCommitment, err := ap.QueryIBCHandlerContract(ctx, pktCommitmentParams)
	if err != nil {
		return nil, err
	}
	storageKey := getStorageKeyFromPath(common.GetPacketCommitmentKey(portid, channelid, big.NewInt(int64(seq))))
	proof, err := ap.QueryWasmProof(ctx, storageKey, height)

	if err != nil {
		return nil, err
	}
	return &chantypes.QueryPacketCommitmentResponse{
		Commitment:  pktCommitment.Data.Bytes(),
		Proof:       proof,
		ProofHeight: clienttypes.NewHeight(0, uint64(height)),
	}, nil

}

func (ap *WasmProvider) QueryPacketAcknowledgement(ctx context.Context, height int64, channelid, portid string, seq uint64) (ackRes *chantypes.QueryPacketAcknowledgementResponse, err error) {
	pktAcknowledgementParams, err := types.NewPacketAcknowledgementCommitment(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}
	pktAcknowledgement, err := ap.QueryIBCHandlerContract(ctx, pktAcknowledgementParams)
	if err != nil {
		return nil, err
	}
	storageKey := getStorageKeyFromPath(common.GetPacketAcknowledgementCommitmentKey(portid, channelid, big.NewInt(int64(seq))))
	proof, err := ap.QueryWasmProof(ctx, storageKey, height)

	return &chantypes.QueryPacketAcknowledgementResponse{
		Acknowledgement: pktAcknowledgement.Data.Bytes(),
		Proof:           proof,
		ProofHeight:     clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (ap *WasmProvider) QueryPacketReceipt(ctx context.Context, height int64, channelid, portid string, seq uint64) (recRes *chantypes.QueryPacketReceiptResponse, err error) {

	// getting proof from commitment map in contract
	storageKey := getStorageKeyFromPath(common.GetPacketReceiptCommitmentKey(portid, channelid, big.NewInt(int64(seq))))
	proof, err := ap.QueryWasmProof(ctx, storageKey, height)
	if err != nil {
		return nil, err
	}

	pktReceiptParams, err := types.NewPacketReceipt(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}

	pktReceipt, err := ap.QueryIBCHandlerContract(ctx, pktReceiptParams)
	if err != nil && !strings.Contains(err.Error(), "PacketReceiptNotFound") {
		return nil, err
	}

	return &chantypes.QueryPacketReceiptResponse{
		Received:    pktReceipt != nil, // TODO: Bytes to boolean
		Proof:       proof,
		ProofHeight: clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (ap *WasmProvider) GetCommitmentPrefixFromContract(ctx context.Context) ([]byte, error) {

	pktCommitmentParams, err := types.NewCommitmentPrefix().Bytes()
	if err != nil {
		return nil, err
	}
	return ap.QueryIBCHandlerContractProcessed(ctx, pktCommitmentParams)

}

// ics 20 - transfer
func (ap *WasmProvider) QueryDenomTrace(ctx context.Context, denom string) (*transfertypes.DenomTrace, error) {
	transfers, err := transfertypes.NewQueryClient(ap).DenomTrace(ctx,
		&transfertypes.QueryDenomTraceRequest{
			Hash: denom,
		})
	if err != nil {
		return nil, err
	}
	return transfers.DenomTrace, nil
}
func (ap *WasmProvider) QueryDenomTraces(ctx context.Context, offset, limit uint64, height int64) ([]transfertypes.DenomTrace, error) {
	qc := transfertypes.NewQueryClient(ap)
	p := DefaultPageRequest()
	transfers := []transfertypes.DenomTrace{}
	for {
		res, err := qc.DenomTraces(ctx,
			&transfertypes.QueryDenomTracesRequest{
				Pagination: p,
			})

		if err != nil || res == nil {
			return nil, err
		}

		transfers = append(transfers, res.DenomTraces...)
		next := res.GetPagination().GetNextKey()
		if len(next) == 0 {
			break
		}

		time.Sleep(PaginationDelay)
		p.Key = next
	}
	return transfers, nil
}

func (ap *WasmProvider) QueryClientPrevConsensusStateHeight(ctx context.Context, chainHeight int64, clientId string, clientHeight int64) (exported.Height, error) {
	param, err := types.NewPrevConsensusStateHeight(clientId, uint64(clientHeight)).Bytes()
	res, err := ap.QueryIBCHandlerContract(ctx, param)
	if err != nil {
		return nil, err
	}

	var heights []int64
	err = json.Unmarshal(res.Data.Bytes(), &heights)

	if err != nil {
		return nil, err
	}

	if len(heights) == 0 {
		return nil, fmt.Errorf("consensus state of client %s before %d", clientId, clientHeight)
	}
	return clienttypes.Height{RevisionNumber: 0, RevisionHeight: uint64(heights[0])}, nil
}
