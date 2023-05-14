package archway

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	abci "github.com/cometbft/cometbft/abci/types"
	tmtypes "github.com/cometbft/cometbft/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	tmclient "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"
	"github.com/icon-project/IBC-Integration/libraries/go/common/icon"

	querytypes "github.com/cosmos/cosmos-sdk/types/query"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v7/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/cosmos/relayer/v2/relayer/chains/archway/types"
	"github.com/cosmos/relayer/v2/relayer/provider"
)

const PaginationDelay = 10 * time.Millisecond

func (ap *ArchwayProvider) QueryTx(ctx context.Context, hashHex string) (*provider.RelayerTxResponse, error) {
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
func (ap *ArchwayProvider) QueryTxs(ctx context.Context, page, limit int, events []string) ([]*provider.RelayerTxResponse, error) {
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

func (ap *ArchwayProvider) QueryLatestHeight(ctx context.Context) (int64, error) {

	stat, err := ap.RPCClient.Status(ctx)
	if err != nil {
		return -1, err
	} else if stat.SyncInfo.CatchingUp {
		return -1, fmt.Errorf("node at %s running chain %s not caught up", ap.PCfg.RPCAddr, ap.PCfg.ChainID)
	}
	return stat.SyncInfo.LatestBlockHeight, nil
}

// QueryIBCHeader returns the IBC compatible block header at a specific height.
func (ap *ArchwayProvider) QueryIBCHeader(ctx context.Context, h int64) (provider.IBCHeader, error) {
	if h == 0 {
		return nil, fmt.Errorf("No header at height 0")
	}
	lightBlock, err := ap.LightProvider.LightBlock(ctx, h)
	if err != nil {
		return nil, err
	}
	return provider.TendermintIBCHeader{
		SignedHeader: lightBlock.SignedHeader,
		ValidatorSet: lightBlock.ValidatorSet,
	}, nil

}

// query packet info for sequence
func (ap *ArchwayProvider) QuerySendPacket(ctx context.Context, srcChanID, srcPortID string, sequence uint64) (provider.PacketInfo, error) {
	return provider.PacketInfo{}, fmt.Errorf("Not implemented for Archway")
}
func (ap *ArchwayProvider) QueryRecvPacket(ctx context.Context, dstChanID, dstPortID string, sequence uint64) (provider.PacketInfo, error) {
	return provider.PacketInfo{}, fmt.Errorf("Not implemented for Archway")
}

// bank
func (ap *ArchwayProvider) QueryBalance(ctx context.Context, keyName string) (sdk.Coins, error) {
	addr, err := ap.ShowAddress(keyName)
	if err != nil {
		return nil, err
	}

	return ap.QueryBalanceWithAddress(ctx, addr)
}

func (ap *ArchwayProvider) QueryBalanceWithAddress(ctx context.Context, address string) (sdk.Coins, error) {
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
func (ap *ArchwayProvider) QueryUnbondingPeriod(context.Context) (time.Duration, error) {
	return 0, nil
}

// ics 02 - client
func (ap *ArchwayProvider) QueryClientState(ctx context.Context, height int64, clientid string) (ibcexported.ClientState, error) {
	clientStateRes, err := ap.QueryClientStateResponse(ctx, height, clientid)
	if err != nil {
		return nil, err
	}
	// TODO
	fmt.Println(clientStateRes)
	return nil, nil
}

func (ap *ArchwayProvider) QueryClientStateResponse(ctx context.Context, height int64, srcClientId string) (*clienttypes.QueryClientStateResponse, error) {
	clientStateParam, err := types.NewClientState(srcClientId).Bytes()
	if err != nil {
		return nil, err
	}

	clientState, err := ap.QueryIBCHandlerContract(ctx, clientStateParam)
	if err != nil {
		return nil, err
	}
	// TODO
	fmt.Println(clientState)
	return nil, nil
}

func (ap *ArchwayProvider) QueryClientStateContract(ctx context.Context, clientId string) (*icon.ClientState, error) {
	clientStateParam, err := types.NewClientState(clientId).Bytes()
	if err != nil {
		return nil, err
	}

	clientState, err := ap.QueryIBCHandlerContract(ctx, clientStateParam)
	if err != nil {
		return nil, err
	}
	var clS icon.ClientState
	// TODO:: ANY
	if err = proto.Unmarshal(clientState.Data.Bytes(), &clS); err != nil {
		return nil, err
	}
	return &clS, nil
}

func (ap *ArchwayProvider) QueryConnectionContract(ctx context.Context, connId string) (*conntypes.ConnectionEnd, error) {
	connStateParam, err := types.NewConnection(connId).Bytes()
	if err != nil {
		return nil, err
	}

	connState, err := ap.QueryIBCHandlerContract(ctx, connStateParam)
	if err != nil {
		return nil, err
	}
	var connS conntypes.ConnectionEnd
	// TODO:: ANY
	if err = proto.Unmarshal(connState.Data.Bytes(), &connS); err != nil {
		return nil, err
	}
	return &connS, nil
}

func (ap *ArchwayProvider) QueryChannelContract(ctx context.Context, portId, channelId string) (*chantypes.Channel, error) {
	channelStateParam, err := types.NewChannel(portId, channelId).Bytes()
	if err != nil {
		return nil, err
	}

	channelState, err := ap.QueryIBCHandlerContract(ctx, channelStateParam)
	if err != nil {
		return nil, err
	}
	var channelS chantypes.Channel
	// TODO:: ANY
	if err = proto.Unmarshal(channelState.Data.Bytes(), &channelS); err != nil {
		return nil, err
	}
	return &channelS, nil
}

func (ap *ArchwayProvider) QueryClientConsensusState(ctx context.Context, chainHeight int64, clientid string, clientHeight ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {
	consensusStateParam, err := types.NewConsensusState(clientid, uint64(chainHeight)).Bytes()
	consensusState, err := ap.QueryIBCHandlerContract(ctx, consensusStateParam)
	if err != nil {
		return nil, err
	}

	// TODO
	fmt.Println(consensusState)

	return nil, nil
}

func (ap *ArchwayProvider) QueryIBCHandlerContract(ctx context.Context, param wasmtypes.RawContractMessage) (*wasmtypes.QuerySmartContractStateResponse, error) {
	return ap.QueryClient.SmartContractState(ctx, &wasmtypes.QuerySmartContractStateRequest{
		Address:   ap.PCfg.IbcHandlerAddress,
		QueryData: param,
	})
}

func (ap *ArchwayProvider) QueryUpgradedClient(ctx context.Context, height int64) (*clienttypes.QueryClientStateResponse, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryUpgradedConsState(ctx context.Context, height int64) (*clienttypes.QueryConsensusStateResponse, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryConsensusState(ctx context.Context, height int64) (ibcexported.ConsensusState, int64, error) {

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

func (ap *ArchwayProvider) getNextSequence(ctx context.Context, methodName string) (uint64, error) {
	// TODO
	switch methodName {
	case types.MethodGetNextClientSequence:
		param, err := types.NewNextClientSequence().Bytes()
		if err != nil {
			return 0, err
		}
		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}
		fmt.Println(op)
	case types.MethodGetNextChannelSequence:
		param, err := types.NewNextChannelSequence().Bytes()
		if err != nil {
			return 0, err
		}
		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}
		fmt.Println(op)
	case types.MethodGetNextConnectionSequence:
		param, err := types.NewNextConnectionSequence().Bytes()
		if err != nil {
			return 0, err
		}
		op, err := ap.QueryIBCHandlerContract(ctx, param)
		if err != nil {
			return 0, err
		}
		fmt.Println(op)
	default:
		return 0, errors.New("Invalid method name")
	}
	// TODO
	return 0, nil
}

func (ap *ArchwayProvider) QueryClients(ctx context.Context) (clienttypes.IdentifiedClientStates, error) {

	seq, err := ap.getNextSequence(ctx, types.MethodGetNextClientSequence)
	if err != nil {
		return nil, err
	}

	if seq == 0 {
		return nil, nil
	}

	identifiedClientStates := make(clienttypes.IdentifiedClientStates, 0)
	for i := 0; i <= int(seq)-1; i++ {
		clientIdentifier := fmt.Sprintf("client-%d", i)
		clientState, err := ap.QueryClientStateContract(ctx, clientIdentifier)
		if err != nil {
			return nil, err
		}
		identifiedClientStates = append(identifiedClientStates, clienttypes.NewIdentifiedClientState(clientIdentifier, clientState))

	}
	return identifiedClientStates, nil
}

// ics 03 - connection
func (ap *ArchwayProvider) QueryConnection(ctx context.Context, height int64, connectionid string) (*conntypes.QueryConnectionResponse, error) {
	connectionStateParams, err := types.NewConnection(connectionid).Bytes()
	if err != nil {
		return nil, err
	}

	connectionState, err := ap.QueryIBCHandlerContract(ctx, connectionStateParams)
	if err != nil {
		return nil, err
	}

	// TODO
	fmt.Println(connectionState)
	return nil, nil
}
func (ap *ArchwayProvider) QueryConnections(ctx context.Context) (conns []*conntypes.IdentifiedConnection, err error) {

	seq, err := ap.getNextSequence(ctx, types.MethodGetNextConnectionSequence)
	if err != nil {
		return nil, err
	}

	if seq == 0 {
		return nil, nil
	}

	for i := 0; i <= int(seq)-1; i++ {
		connectionId := fmt.Sprintf("connection-%d", i)
		conn, err := ap.QueryConnectionContract(ctx, connectionId)
		if err != nil {
			return nil, err
		}

		// Only return open conenctions
		if conn.State == 3 {
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

func (ap *ArchwayProvider) QueryConnectionsUsingClient(ctx context.Context, height int64, clientid string) (*conntypes.QueryConnectionsResponse, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) GenerateConnHandshakeProof(ctx context.Context, height int64, clientId, connId string) (clientState ibcexported.ClientState,
	clientStateProof []byte, consensusProof []byte, connectionProof []byte,
	connectionProofHeight ibcexported.Height, err error) {
	return nil, nil, nil, nil, nil, nil
}

// ics 04 - channel
func (ap *ArchwayProvider) QueryChannel(ctx context.Context, height int64, channelid, portid string) (chanRes *chantypes.QueryChannelResponse, err error) {
	channelParams, err := types.NewChannel(portid, channelid).Bytes()
	if err != nil {
		return nil, err
	}

	channelState, err := ap.QueryIBCHandlerContract(ctx, channelParams)
	if err != nil {
		return nil, err
	}

	//TODO
	fmt.Println(channelState)
	return nil, nil
}

func (ap *ArchwayProvider) QueryChannelClient(ctx context.Context, height int64, channelid, portid string) (*clienttypes.IdentifiedClientState, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryConnectionChannels(ctx context.Context, height int64, connectionid string) ([]*chantypes.IdentifiedChannel, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryChannels(ctx context.Context) ([]*chantypes.IdentifiedChannel, error) {
	nextSeq, err := ap.getNextSequence(ctx, types.MethodGetNextChannelSequence)
	if err != nil {
		return nil, err
	}
	var channels []*chantypes.IdentifiedChannel

	testPort := "mock" //TODO:

	for i := 0; i <= int(nextSeq)-1; i++ {
		channelId := fmt.Sprintf("channel-%d", i)
		channel, err := ap.QueryChannelContract(ctx, testPort, channelId)
		if err != nil {
			return nil, err
		}

		// check if the channel is open
		if channel.State == 3 {
			identifiedChannel := chantypes.IdentifiedChannel{
				State:          channel.State,
				Ordering:       channel.Ordering,
				Counterparty:   channel.Counterparty,
				ConnectionHops: channel.ConnectionHops,
				Version:        channel.Version,
				PortId:         testPort,
				ChannelId:      channelId,
			}
			channels = append(channels, &identifiedChannel)
		}
	}

	return channels, nil
}
func (ap *ArchwayProvider) QueryPacketCommitments(ctx context.Context, height uint64, channelid, portid string) (commitments *chantypes.QueryPacketCommitmentsResponse, err error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryPacketAcknowledgements(ctx context.Context, height uint64, channelid, portid string) (acknowledgements []*chantypes.PacketState, err error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryUnreceivedPackets(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryUnreceivedAcknowledgements(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}

func (ap *ArchwayProvider) QueryNextSeqRecv(ctx context.Context, height int64, channelid, portid string) (recvRes *chantypes.QueryNextSequenceReceiveResponse, err error) {
	nextSeqRecvParams, err := types.NewNextSequenceReceive(portid, channelid).Bytes()
	if err != nil {
		return nil, err
	}
	nextSeqRecv, err := ap.QueryIBCHandlerContract(ctx, nextSeqRecvParams)
	if err != nil {
		return nil, err
	}

	// TODO
	fmt.Println(nextSeqRecv)
	return nil, nil
}

func (ap *ArchwayProvider) QueryPacketCommitment(ctx context.Context, height int64, channelid, portid string, seq uint64) (comRes *chantypes.QueryPacketCommitmentResponse, err error) {
	pktCommitmentParams, err := types.NewPacketCommitment(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}
	pktCommitment, err := ap.QueryIBCHandlerContract(ctx, pktCommitmentParams)
	if err != nil {
		return nil, err
	}
	// TODO
	fmt.Println(pktCommitment)

	return nil, nil
}

func (ap *ArchwayProvider) QueryPacketAcknowledgement(ctx context.Context, height int64, channelid, portid string, seq uint64) (ackRes *chantypes.QueryPacketAcknowledgementResponse, err error) {
	pktAcknowledgementParams, err := types.NewPacketAcknowledgementCommitment(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}
	pktAcknowledgement, err := ap.QueryIBCHandlerContract(ctx, pktAcknowledgementParams)
	if err != nil {
		return nil, err
	}
	// TODO
	fmt.Println(pktAcknowledgement)
	return nil, nil
}

func (ap *ArchwayProvider) QueryPacketReceipt(ctx context.Context, height int64, channelid, portid string, seq uint64) (recRes *chantypes.QueryPacketReceiptResponse, err error) {
	pktReceiptParams, err := types.NewPacketReceipt(portid, channelid, seq).Bytes()
	if err != nil {
		return nil, err
	}
	pktReceipt, err := ap.QueryIBCHandlerContract(ctx, pktReceiptParams)
	if err != nil {
		return nil, err
	}
	// TODO
	fmt.Println(pktReceipt)
	return nil, nil
}

// ics 20 - transfer
func (ap *ArchwayProvider) QueryDenomTrace(ctx context.Context, denom string) (*transfertypes.DenomTrace, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}
func (ap *ArchwayProvider) QueryDenomTraces(ctx context.Context, offset, limit uint64, height int64) ([]transfertypes.DenomTrace, error) {
	return nil, fmt.Errorf("Not implemented for Archway")
}