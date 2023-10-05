package icon

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"cosmossdk.io/math"
	"github.com/avast/retry-go/v4"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	//this import should be letter converted to icon types

	"github.com/cosmos/relayer/v2/relayer/chains/icon/cryptoutils"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/common"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/icon-project/IBC-Integration/libraries/go/common/icon"
	itm "github.com/icon-project/IBC-Integration/libraries/go/common/tendermint"

	transfertypes "github.com/cosmos/ibc-go/v7/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	committypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	//change this to icon types after original repo merge
)

// ***************** methods marked with legacy should be updated only when relayer is runned through legacy method *****************

var _ provider.QueryProvider = &IconProvider{}

const (
	epoch           = 24 * 3600 * 1000
	sequenceLimit   = 2
	genesisContract = "cx0000000000000000000000000000000000000000"
)

type CallParamOption func(*types.CallParam)

// if height is less than or zero don't set height
func callParamsWithHeight(height types.HexInt) CallParamOption {
	val, _ := height.Value()
	if val <= 0 {
		return func(*types.CallParam) {}
	}
	return func(cp *types.CallParam) {
		cp.Height = height
	}
}

func (icp *IconProvider) prepareCallParams(methodName string, param map[string]interface{}, options ...CallParamOption) *types.CallParam {

	callData := &types.CallData{
		Method: methodName,
		Params: param,
	}

	callParam := &types.CallParam{
		FromAddress: types.Address(fmt.Sprintf("hx%s", strings.Repeat("0", 40))),
		ToAddress:   types.Address(icp.PCfg.IbcHandlerAddress),
		DataType:    "call",
		Data:        callData,
	}

	for _, option := range options {
		option(callParam)
	}

	return callParam

}

func (icp *IconProvider) BlockTime(ctx context.Context, height int64) (time.Time, error) {
	header, err := icp.client.GetBlockHeaderByHeight(height)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(header.Timestamp, 0), nil
}

// required for cosmos only
func (icp *IconProvider) QueryTx(ctx context.Context, hashHex string) (*provider.RelayerTxResponse, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

// required for cosmos only
func (icp *IconProvider) QueryTxs(ctx context.Context, page, limit int, events []string) ([]*provider.RelayerTxResponse, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryLatestHeight(ctx context.Context) (int64, error) {
	var block *types.Block
	var err error
	retry.Do(func() error {
		block, err = icp.client.GetLastBlock()

		return err
	}, retry.Context(ctx),
		retry.Attempts(queryRetries),
		retry.OnRetry(func(n uint, err error) {
			icp.log.Warn("failed to query latestHeight", zap.String("Chain Id", icp.ChainId()))
		}))

	if block != nil {
		return block.Height, nil
	}
	return 0, fmt.Errorf("failed to query latest block")
}

// legacy
func (icp *IconProvider) QueryIBCHeader(ctx context.Context, h int64) (provider.IBCHeader, error) {

	validators, err := icp.GetProofContextByHeight(h)
	if err != nil {
		return nil, err
	}
	header, err := icp.GetBtpHeader(h)
	if err != nil {
		if btpBlockNotPresent(err) {
			return NewIconIBCHeader(nil, validators, int64(h)), nil
		}
	}
	return NewIconIBCHeader(header, validators, int64(header.MainHeight)), err
}

func (icp *IconProvider) QuerySendPacket(ctx context.Context, srcChanID, srcPortID string, sequence uint64) (provider.PacketInfo, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryRecvPacket(ctx context.Context, dstChanID, dstPortID string, sequence uint64) (provider.PacketInfo, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryBalance(ctx context.Context, keyName string) (sdk.Coins, error) {
	addr, err := icp.ShowAddress(keyName)
	if err != nil {
		return nil, err
	}

	return icp.QueryBalanceWithAddress(ctx, addr)
}

// implementing is not required
func (icp *IconProvider) QueryBalanceWithAddress(ctx context.Context, addr string) (sdk.Coins, error) {
	param := types.AddressParam{
		Address: types.Address(addr),
	}
	balance, err := icp.client.GetBalance(&param)
	if err != nil {
		return nil, err
	}
	return sdk.Coins{sdk.Coin{
		Denom:  "ICX",
		Amount: math.NewInt(balance.Int64()),
	}}, nil
}

func (icp *IconProvider) QueryUnbondingPeriod(context.Context) (time.Duration, error) {
	return epoch, nil
}

// ****************ClientStates*******************  //
// ics 02 - client

func (icp *IconProvider) QueryClientState(ctx context.Context, height int64, clientid string) (ibcexported.ClientState, error) {

	clientStateRes, err := icp.QueryClientStateResponse(ctx, height, clientid)
	if err != nil {
		return nil, err
	}

	clientStateExported, err := clienttypes.UnpackClientState(clientStateRes.ClientState)
	if err != nil {
		return nil, err
	}

	return clientStateExported, nil

}

func (icp *IconProvider) QueryClientStateWithoutProof(ctx context.Context, height int64, clientid string) (ibcexported.ClientState, error) {
	callParams := icp.prepareCallParams(MethodGetClientState, map[string]interface{}{
		"clientId": clientid,
	}, callParamsWithHeight(types.NewHexInt(height)))

	//similar should be implemented
	var clientStateB types.HexBytes
	err := icp.client.Call(callParams, &clientStateB)
	if err != nil {
		return nil, err
	}

	clientStateByte, err := clientStateB.Value()
	if err != nil {
		return nil, err
	}

	// TODO: Use ICON Client State after cosmos chain integrated--
	any, err := icp.ClientToAny(clientid, clientStateByte)
	if err != nil {
		return nil, err
	}

	clientStateRes := clienttypes.NewQueryClientStateResponse(any, nil, clienttypes.NewHeight(0, uint64(height)))
	clientStateExported, err := clienttypes.UnpackClientState(clientStateRes.ClientState)
	if err != nil {
		return nil, err
	}

	return clientStateExported, nil

}

func (icp *IconProvider) QueryClientStateResponse(ctx context.Context, height int64, srcClientId string) (*clienttypes.QueryClientStateResponse, error) {

	callParams := icp.prepareCallParams(MethodGetClientState, map[string]interface{}{
		"clientId": srcClientId,
	}, callParamsWithHeight(types.NewHexInt(height)))

	//similar should be implemented
	var clientStateB types.HexBytes
	err := icp.client.Call(callParams, &clientStateB)
	if err != nil {
		return nil, err
	}

	clientStateByte, err := clientStateB.Value()
	if err != nil {
		return nil, err
	}

	any, err := icp.ClientToAny(srcClientId, clientStateByte)
	if err != nil {
		return nil, err
	}

	commitmentHash := getCommitmentHash(common.GetClientStateCommitmentKey(srcClientId), clientStateByte)
	proof, err := icp.QueryIconProof(ctx, height, commitmentHash)
	if err != nil {
		return nil, err
	}

	return clienttypes.NewQueryClientStateResponse(any, proof, clienttypes.NewHeight(0, uint64(height))), nil
}

func (icp *IconProvider) QueryClientConsensusState(ctx context.Context, chainHeight int64, clientid string, clientHeight ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {

	h, ok := clientHeight.(clienttypes.Height)
	if !ok {
		return nil, fmt.Errorf("clientHeight type mismatched ")
	}

	heightBytes, err := icp.codec.Marshaler.Marshal(&h)
	if err != nil {
		return nil, err
	}

	callParams := icp.prepareCallParams(MethodGetConsensusState, map[string]interface{}{
		"clientId": clientid,
		"height":   types.NewHexBytes(heightBytes),
	})

	var cnsStateHexByte types.HexBytes
	err = icp.client.Call(callParams, &cnsStateHexByte)
	if err != nil {
		return nil, err
	}
	cnsStateByte, err := cnsStateHexByte.Value()
	if err != nil {
		return nil, err
	}

	any, err := icp.ConsensusToAny(clientid, cnsStateByte)
	if err != nil {
		return nil, err
	}

	key := common.GetConsensusStateCommitmentKey(clientid, big.NewInt(0), big.NewInt(int64(h.RevisionHeight)))
	commitmentHash := getCommitmentHash(key, cnsStateByte)

	proof, err := icp.QueryIconProof(ctx, chainHeight, commitmentHash)
	if err != nil {
		return nil, err
	}

	return &clienttypes.QueryConsensusStateResponse{
		ConsensusState: any,
		Proof:          proof,
		ProofHeight:    clienttypes.NewHeight(0, uint64(chainHeight)),
	}, nil
}

func (icp *IconProvider) QueryUpgradedClient(ctx context.Context, height int64) (*clienttypes.QueryClientStateResponse, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryUpgradedConsState(ctx context.Context, height int64) (*clienttypes.QueryConsensusStateResponse, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryConsensusState(ctx context.Context, height int64) (ibcexported.ConsensusState, int64, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

// query all the clients of the chain
func (icp *IconProvider) QueryClients(ctx context.Context) (clienttypes.IdentifiedClientStates, error) {
	seq, err := icp.getNextSequence(ctx, MethodGetNextClientSequence, 0, map[string]interface{}{})

	if err != nil {
		return nil, err
	}

	if seq == 0 {
		return nil, nil
	}

	identifiedClientStates := make(clienttypes.IdentifiedClientStates, 0)
	for i := 0; i <= int(seq)-1; i++ {
		clientIdentifier := common.GetIdentifier(common.TendermintLightClient, i)
		callParams := icp.prepareCallParams(MethodGetClientState, map[string]interface{}{
			"clientId": clientIdentifier,
		})

		//similar should be implemented
		var clientStateB types.HexBytes
		err := icp.client.Call(callParams, &clientStateB)
		if err != nil {
			return nil, err
		}
		clientStateBytes, _ := clientStateB.Value()

		// TODO: Use ICON Client State after cosmos chain integrated--
		var clientState itm.ClientState
		if err = icp.codec.Marshaler.Unmarshal(clientStateBytes, &clientState); err != nil {
			return nil, err
		}

		identifiedClientStates = append(identifiedClientStates, clienttypes.NewIdentifiedClientState(clientIdentifier, &clientState))

	}
	return identifiedClientStates, nil
}

// query connection to the ibc host based on the connection-id
func (icp *IconProvider) QueryConnection(ctx context.Context, height int64, connectionid string) (*conntypes.QueryConnectionResponse, error) {

	callParam := icp.prepareCallParams(MethodGetConnection, map[string]interface{}{
		"connectionId": connectionid,
	}, callParamsWithHeight(types.NewHexInt(height)))

	var conn_string_ types.HexBytes
	err := icp.client.Call(callParam, &conn_string_)
	if err != nil {
		return emptyConnRes, err
	}

	connectionBytes, err := conn_string_.Value()
	if err != nil {
		return emptyConnRes, err
	}

	var conn conntypes.ConnectionEnd
	_, err = HexBytesToProtoUnmarshal(conn_string_, &conn)
	if err != nil {
		return emptyConnRes, err
	}

	key := common.GetConnectionCommitmentKey(connectionid)
	commitmentHash := getCommitmentHash(key, connectionBytes)

	proof, err := icp.QueryIconProof(ctx, height, commitmentHash)
	if err != nil {
		return emptyConnRes, err
	}

	return conntypes.NewQueryConnectionResponse(conn, proof, clienttypes.NewHeight(0, uint64(height))), nil

}

var emptyConnRes = conntypes.NewQueryConnectionResponse(
	conntypes.NewConnectionEnd(
		conntypes.UNINITIALIZED,
		"client",
		conntypes.NewCounterparty(
			"client",
			"connection",
			committypes.MerklePrefix(committypes.NewMerklePrefix(make([]byte, 0))),
		),
		[]*conntypes.Version{},
		0,
	),
	[]byte{},
	clienttypes.NewHeight(0, 0),
)

// ics 03 - connection
func (icp *IconProvider) QueryConnections(ctx context.Context) (conns []*conntypes.IdentifiedConnection, err error) {

	// sending -1 for latest height
	nextSeq, err := icp.getNextSequence(ctx, MethodGetNextConnectionSequence, -1, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	if nextSeq == 0 {
		return nil, nil
	}

	for i := 0; i <= int(nextSeq)-1; i++ {
		connectionId := common.GetIdentifier(common.ConnectionKey, i)
		var conn_string_ types.HexBytes
		err := icp.client.Call(icp.prepareCallParams(MethodGetConnection, map[string]interface{}{
			"connectionId": connectionId,
		}), &conn_string_)
		if err != nil {
			icp.log.Error("unable to fetch connection for  ", zap.String("connection id", connectionId))
			continue
		}

		var conn conntypes.ConnectionEnd
		_, err = HexBytesToProtoUnmarshal(conn_string_, &conn)
		if err != nil {
			icp.log.Info("unable to unmarshal connection for ", zap.String("connection id ", connectionId))
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

func (icp *IconProvider) getNextSequence(ctx context.Context, methodName string, height int64, params map[string]interface{}) (uint64, error) {
	var seq types.HexInt
	options := make([]CallParamOption, 0)
	if height > 0 {
		options = append(options, callParamsWithHeight(types.NewHexInt(height)))
	}

	callParam := icp.prepareCallParams(methodName, params, options...)
	if err := icp.client.Call(callParam, &seq); err != nil {
		return 0, err
	}
	val, _ := seq.Value()
	return uint64(val), nil
}

func (icp *IconProvider) getAllPorts(ctx context.Context) ([]string, error) {
	var portIds []string
	callParam := icp.prepareCallParams(MethodGetAllPorts, map[string]interface{}{})
	if err := icp.client.Call(callParam, &portIds); err != nil {
		return nil, err
	}
	return portIds, nil
}

func (icp *IconProvider) QueryConnectionsUsingClient(ctx context.Context, height int64, clientid string) (*conntypes.QueryConnectionsResponse, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}
func (icp *IconProvider) GenerateConnHandshakeProof(ctx context.Context, height int64, clientId, connId string) (ibcexported.ClientState,
	[]byte, []byte, []byte,
	ibcexported.Height, error) {

	// clientProof
	clientResponse, err := icp.QueryClientStateResponse(ctx, height, clientId)
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	// clientState
	anyClientState := clientResponse.ClientState
	clientState_, err := clienttypes.UnpackClientState(anyClientState)
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	// consensusRes
	consensusRes, err := icp.QueryClientConsensusState(ctx, height, clientId, clientState_.GetLatestHeight())
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	// connectionProof
	connResponse, err := icp.QueryConnection(ctx, height, connId)
	if err != nil {
		return nil, nil, nil, nil, clienttypes.Height{}, err
	}

	return clientState_, clientResponse.Proof, consensusRes.Proof, connResponse.Proof, clienttypes.NewHeight(0, uint64(height)), nil
}

// ics 04 - channel
func (icp *IconProvider) QueryChannel(ctx context.Context, height int64, channelid, portid string) (chanRes *chantypes.QueryChannelResponse, err error) {

	callParam := icp.prepareCallParams(MethodGetChannel, map[string]interface{}{
		"channelId": channelid,
		"portId":    portid,
	}, callParamsWithHeight(types.NewHexInt(height)))

	var _channel types.HexBytes
	err = icp.client.Call(callParam, &_channel)
	if err != nil {
		return emptyChannelRes, err
	}

	channelBytes, err := _channel.Value()
	if err != nil {
		return emptyChannelRes, err
	}

	var channel icon.Channel
	_, err = HexBytesToProtoUnmarshal(_channel, &channel)
	if err != nil {
		return emptyChannelRes, err
	}

	channelCommitment := common.GetChannelCommitmentKey(portid, channelid)
	commitmentHash := getCommitmentHash(channelCommitment, channelBytes)
	proof, err := icp.QueryIconProof(ctx, height, commitmentHash)
	if err != nil {
		return emptyChannelRes, err
	}

	cosmosChan := chantypes.NewChannel(
		chantypes.State(channel.State),
		chantypes.Order(channel.Ordering),
		chantypes.NewCounterparty(
			channel.Counterparty.PortId,
			channel.Counterparty.ChannelId),
		channel.ConnectionHops,
		channel.Version,
	)

	return chantypes.NewQueryChannelResponse(cosmosChan, proof, clienttypes.NewHeight(0, uint64(height))), nil
}

var emptyChannelRes = chantypes.NewQueryChannelResponse(
	chantypes.NewChannel(
		chantypes.UNINITIALIZED,
		chantypes.UNORDERED,
		chantypes.NewCounterparty(
			"port",
			"channel",
		),
		[]string{},
		"version",
	),
	[]byte{},
	clienttypes.NewHeight(0, 0),
)

func (icp *IconProvider) QueryChannelClient(ctx context.Context, height int64, channelid, portid string) (*clienttypes.IdentifiedClientState, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

// is not needed currently for the operation
// get all the channel and start the init-process
func (icp *IconProvider) QueryConnectionChannels(ctx context.Context, height int64, connectionid string) ([]*chantypes.IdentifiedChannel, error) {
	allChannel, err := icp.QueryChannels(ctx)
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

func (icp *IconProvider) QueryChannels(ctx context.Context) ([]*chantypes.IdentifiedChannel, error) {
	nextSeq, err := icp.getNextSequence(ctx, MethodGetNextChannelSequence, 0, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var channels []*chantypes.IdentifiedChannel

	allPorts, err := icp.getAllPorts(ctx)
	if err != nil {
		return nil, err
	}

	if allPorts == nil || len(allPorts) <= 0 {
		return channels, nil
	}

	for i := 0; i <= int(nextSeq)-1; i++ {
		for _, portId := range allPorts {
			channelId := common.GetIdentifier(common.ChannelKey, i)
			var _channel types.HexBytes
			err := icp.client.Call(icp.prepareCallParams(MethodGetChannel, map[string]interface{}{
				"channelId": channelId,
				"portId":    portId,
			}), &_channel)
			if err != nil {
				icp.log.Error("unable to fetch channel for  ", zap.String("channel-id ", channelId), zap.Error(err))
				continue
			}

			if _channel == "" {
				icp.log.Debug("Channel not present for ", zap.String("channel-id ", channelId), zap.String("port-id ", portId))
				continue
			}

			var channel chantypes.Channel
			_, err = HexBytesToProtoUnmarshal(_channel, &channel)
			if err != nil {
				icp.log.Info("Unable to unmarshal channel for ",
					zap.String("channel-id ", channelId), zap.Error(err))
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

// required to flush packets
func (icp *IconProvider) QueryPacketCommitments(ctx context.Context, height uint64, channelid, portid string) (commitments *chantypes.QueryPacketCommitmentsResponse, err error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryPacketAcknowledgements(ctx context.Context, height uint64, channelid, portid string) (acknowledgements []*chantypes.PacketState, err error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryUnreceivedPackets(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryUnreceivedAcknowledgements(ctx context.Context, height uint64, channelid, portid string, seqs []uint64) ([]uint64, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryNextSeqRecv(ctx context.Context, height int64, channelid, portid string) (recvRes *chantypes.QueryNextSequenceReceiveResponse, err error) {

	seq, err := icp.getNextSequence(ctx, MethodGetNextSequenceReceive, height, map[string]interface{}{
		"portId":    portid,
		"channelId": channelid,
	})

	key := common.GetNextSequenceRecvCommitmentKey(portid, channelid)
	keyHash := common.Sha3keccak256(key, []byte(types.NewHexInt(int64(seq))))

	proof, err := icp.QueryIconProof(ctx, height, keyHash)
	if err != nil {
		return nil, err
	}

	return &chantypes.QueryNextSequenceReceiveResponse{
		NextSequenceReceive: seq,
		Proof:               proof,
		ProofHeight:         clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (icp *IconProvider) QueryPacketCommitment(ctx context.Context, height int64, channelid, portid string, seq uint64) (comRes *chantypes.QueryPacketCommitmentResponse, err error) {
	callParam := icp.prepareCallParams(MethodGetPacketCommitment, map[string]interface{}{
		"portId":    portid,
		"channelId": channelid,
		"sequence":  types.NewHexInt(int64(seq)),
	}, callParamsWithHeight(types.NewHexInt(height)))
	var packetCommitmentHexBytes types.HexBytes
	if err := icp.client.Call(callParam, &packetCommitmentHexBytes); err != nil {
		return nil, err
	}
	packetCommitmentBytes, err := packetCommitmentHexBytes.Value()
	if err != nil {
		return nil, err
	}
	if len(packetCommitmentBytes) == 0 {
		return nil, fmt.Errorf("Invalid commitment bytes")
	}

	key := common.GetPacketCommitmentKey(portid, channelid, big.NewInt(int64(seq)))
	keyHash := common.Sha3keccak256(key, packetCommitmentBytes)
	proof, err := icp.QueryIconProof(ctx, height, keyHash)
	if err != nil {
		return nil, err
	}

	return &chantypes.QueryPacketCommitmentResponse{
		Commitment:  packetCommitmentBytes,
		Proof:       proof,
		ProofHeight: clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (icp *IconProvider) QueryPacketAcknowledgement(ctx context.Context, height int64, channelid, portid string, seq uint64) (ackRes *chantypes.QueryPacketAcknowledgementResponse, err error) {
	callParam := icp.prepareCallParams(MethodGetPacketAcknowledgementCommitment, map[string]interface{}{
		"portId":    portid,
		"channelId": channelid,
		"sequence":  types.NewHexInt(int64(seq)),
	}, callParamsWithHeight(types.NewHexInt(height)))

	var packetAckHexBytes types.HexBytes
	if err := icp.client.Call(callParam, &packetAckHexBytes); err != nil {
		return nil, err
	}
	packetAckBytes, err := packetAckHexBytes.Value()
	if err != nil {
		return nil, err
	}
	if len(packetAckBytes) == 0 {
		return nil, fmt.Errorf("Invalid packet bytes")
	}

	key := common.GetPacketAcknowledgementCommitmentKey(portid, channelid, big.NewInt(int64(seq)))
	keyhash := common.Sha3keccak256(key, packetAckBytes)

	proof, err := icp.QueryIconProof(ctx, height, keyhash)
	if err != nil {
		return nil, err
	}

	return &chantypes.QueryPacketAcknowledgementResponse{
		Acknowledgement: packetAckBytes,
		Proof:           proof,
		ProofHeight:     clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (icp *IconProvider) QueryPacketReceipt(ctx context.Context, height int64, channelid, portid string, seq uint64) (recRes *chantypes.QueryPacketReceiptResponse, err error) {
	callParam := icp.prepareCallParams(MethodGetPacketReceipt, map[string]interface{}{
		"portId":    portid,
		"channelId": channelid,
		"sequence":  types.NewHexInt(int64(seq)),
	})
	var packetReceiptHexByte types.HexInt
	if err := icp.client.Call(callParam, &packetReceiptHexByte); err != nil {
		packetReceiptHexByte = types.NewHexInt(0)
	}
	packetReceipt, err := packetReceiptHexByte.Value()
	if err != nil {
		return nil, err
	}

	keyhash := common.Sha3keccak256(common.GetPacketReceiptCommitmentPath(portid, channelid, big.NewInt(height)))

	proof, err := icp.QueryIconProof(ctx, height, keyhash)
	if err != nil {
		return nil, err
	}

	return &chantypes.QueryPacketReceiptResponse{
		Received:    packetReceipt == 1,
		Proof:       proof,
		ProofHeight: clienttypes.NewHeight(0, uint64(height)),
	}, nil
}

func (icp *IconProvider) QueryMissingPacketReceipts(ctx context.Context, latestHeight int64, channelId, portId string, startSeq, endSeq uint64) ([]uint64, error) {
	receipts := make([]uint64, 0)

	if endSeq <= startSeq {
		return receipts, fmt.Errorf("start sequence %d is greater than end sequence: %d ", startSeq, endSeq)
	}

	paginate := common.NewPaginate(startSeq, endSeq, sequenceLimit)

	for paginate.HasNext() {
		start, end, err := paginate.Next()
		if err != nil {
			return nil, err
		}
		callParam := icp.prepareCallParams(MethodGetMissingPacketReceipts, map[string]interface{}{
			"portId":        portId,
			"channelId":     channelId,
			"startSequence": types.NewHexInt(int64(start)),
			"endSequence":   types.NewHexInt(int64(end)),
		}, callParamsWithHeight(types.NewHexInt(latestHeight)))

		var missingReceipts []types.HexInt
		if err := icp.client.Call(callParam, &missingReceipts); err != nil {
			return nil, err
		}

		for _, h := range missingReceipts {
			val, err := h.Value()
			if err != nil {
				return nil, err
			}
			receipts = append(receipts, uint64(val))
		}

	}

	return receipts, nil
}

func (icp *IconProvider) QueryPacketHeights(ctx context.Context, latestHeight int64, channelId, portId string, startSeq, endSeq uint64) (provider.MessageHeights, error) {
	return icp.QueryMessageHeights(ctx, MethodGetPacketHeights, latestHeight, channelId, portId, startSeq, endSeq)
}

func (icp *IconProvider) QueryAckHeights(ctx context.Context, latestHeight int64, channelId, portId string, startSeq, endSeq uint64) (provider.MessageHeights, error) {
	return icp.QueryMessageHeights(ctx, MethodGetAckHeights, latestHeight, channelId, portId, startSeq, endSeq)
}

func (icp *IconProvider) QueryMessageHeights(ctx context.Context, methodName string, latestHeight int64, channelId, portId string, startSeq, endSeq uint64) (provider.MessageHeights, error) {

	packetHeights := make(provider.MessageHeights, 0)

	if methodName != MethodGetPacketHeights &&
		methodName != MethodGetAckHeights {
		return provider.MessageHeights{}, fmt.Errorf("invalid methodName: %s", methodName)
	}

	if endSeq <= startSeq {
		return provider.MessageHeights{}, fmt.Errorf("start sequence %d is greater than end sequence: %d ", startSeq, endSeq)
	}

	paginate := common.NewPaginate(startSeq, endSeq, sequenceLimit)
	for paginate.HasNext() {
		start, end, err := paginate.Next()
		if err != nil {
			return nil, err
		}

		callParam := icp.prepareCallParams(methodName, map[string]interface{}{
			"portId":        portId,
			"channelId":     channelId,
			"startSequence": types.NewHexInt(int64(start)),
			"endSequence":   types.NewHexInt(int64(end)),
		}, callParamsWithHeight(types.NewHexInt(latestHeight)))

		var rawPacketHeights map[int64]types.HexInt
		if err := icp.client.Call(callParam, &rawPacketHeights); err != nil {
			return nil, err
		}

		for seq, h := range rawPacketHeights {
			heightInt, err := h.Value()
			if err != nil {
				return nil, err
			}

			packetHeights[uint64(seq)] = uint64(heightInt)
		}
	}

	return packetHeights, nil
}

func (ap *IconProvider) QueryPacketMessageByEventHeight(ctx context.Context, eventType string, srcChanID, srcPortID string, sequence uint64, seqHeight uint64) (provider.PacketInfo, error) {
	var eventName = ""
	switch eventType {
	case chantypes.EventTypeSendPacket:
		eventName = EventTypeSendPacket
	case chantypes.EventTypeWriteAck:
		eventName = EventTypeWriteAcknowledgement
	}

	block, err := ap.client.GetBlockByHeight(&types.BlockHeightParam{
		Height: types.NewHexInt(int64(seqHeight)),
	})
	if err != nil {
		return provider.PacketInfo{}, err
	}

	for _, res := range block.NormalTransactions {

		txResult, err := ap.client.GetTransactionResult(&types.TransactionHashParam{
			Hash: res.TxHash,
		})
		if err != nil {
			return provider.PacketInfo{}, err
		}
		for _, el := range txResult.EventLogs {
			if el.Addr != types.Address(ap.PCfg.IbcHandlerAddress) &&
				// sendPacket will be of index length 2
				len(el.Indexed) != 2 &&
				el.Indexed[0] != eventName {
				continue
			}
			// for ack
			if eventName == EventTypeWriteAcknowledgement {
				if len(el.Data) == 0 || el.Data[0] == "" {
					continue
				}
			}

			packetStr := el.Indexed[1]
			packetByte, err := hex.DecodeString(strings.TrimPrefix(packetStr, "0x"))
			if err != nil {
				return provider.PacketInfo{}, err
			}
			var packet icon.Packet
			if err := proto.Unmarshal(packetByte, &packet); err != nil {
				return provider.PacketInfo{}, err
			}

			if packet.Sequence == sequence && packet.SourceChannel == srcChanID && packet.SourcePort == srcPortID {
				packet := provider.PacketInfo{
					// in case of icon we need to consider btp block because of which if a message is send at height h
					// btp header will be in h + 1
					Height:           seqHeight + 1,
					Sequence:         packet.Sequence,
					SourcePort:       packet.SourcePort,
					SourceChannel:    packet.SourceChannel,
					DestPort:         packet.DestinationPort,
					DestChannel:      packet.DestinationChannel,
					Data:             packet.Data,
					TimeoutHeight:    clienttypes.NewHeight(packet.TimeoutHeight.RevisionNumber, packet.TimeoutHeight.RevisionHeight),
					TimeoutTimestamp: packet.TimeoutTimestamp,
				}
				// adding ack bytes
				if eventName == EventTypeWriteAcknowledgement {
					packet.Ack, err = hex.DecodeString(strings.TrimPrefix(el.Data[0], "0x"))
					if err != nil {
						return provider.PacketInfo{}, err
					}
				}
				return packet, nil
			}

		}

	}

	return provider.PacketInfo{}, fmt.Errorf(
		fmt.Sprintf("Packet of seq number : %d, srcchannel:%s, srcPort:%s not found at height %d",
			sequence, srcChanID, srcPortID, seqHeight))

}

func (ap *IconProvider) QueryNextSeqSend(ctx context.Context, height int64, channelid, portid string) (seq uint64, err error) {
	return ap.getNextSequence(ctx, MethodGetNextSequenceSend, height, map[string]interface{}{
		"channelId": channelid,
		"portId":    portid,
	})
}

// ics 20 - transfer
// not required for icon
func (icp *IconProvider) QueryDenomTrace(ctx context.Context, denom string) (*transfertypes.DenomTrace, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

// not required for icon
func (icp *IconProvider) QueryDenomTraces(ctx context.Context, offset, limit uint64, height int64) ([]transfertypes.DenomTrace, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryIconProof(ctx context.Context, height int64, keyHash []byte) ([]byte, error) {
	merkleProofs := icon.MerkleProofs{}

	messages, err := icp.GetBtpMessage(height)

	if err != nil {
		return nil, err
	}

	if len(messages) == 0 {
		icp.log.Info("BTP Message not present",
			zap.Int64("Height", height),
			zap.Int64("BtpNetwork", icp.PCfg.BTPNetworkID))
	}

	if len(messages) > 1 {
		merkleHashTree := cryptoutils.NewMerkleHashTree(messages)
		if err != nil {
			return nil, err
		}
		hashIndex := merkleHashTree.Hashes.FindIndex(keyHash)
		if hashIndex == -1 {
			return nil, errors.New(fmt.Sprintf("Btp message at height %d for hash: %x not found", height, string(keyHash)))
		}

		proof := merkleHashTree.MerkleProof(hashIndex)

		merkleProofs = icon.MerkleProofs{
			Proofs: proof,
		}
		return icp.codec.Marshaler.Marshal(&merkleProofs)
	}
	return nil, nil
}

func (ip *IconProvider) QueryClientPrevConsensusStateHeight(ctx context.Context, chainHeight int64, clientId string, clientHeight int64) (exported.Height, error) {
	panic("QueryClientPrevConsensusStateHeight not implemented")
}

func (icp *IconProvider) HexStringToProtoUnmarshal(encoded string, v proto.Message) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("Encoded string is empty ")
	}

	input_ := strings.TrimPrefix(encoded, "0x")
	inputBytes, err := hex.DecodeString(input_)
	if err != nil {
		return nil, err
	}

	err = icp.codec.Marshaler.UnmarshalInterface(inputBytes, v)
	if err != nil {
		return nil, err
	}
	return inputBytes, nil

}

func (ip *IconProvider) GetProofContextChangePeriod() (uint64, error) {
	// assigning termPeriod
	prep, err := ip.client.GetPrepTerm()
	if err != nil {
		return 0, fmt.Errorf("fail to get prepterm: %v", err)
	}

	decentralized, err := prep.IsDecentralized.Value()
	if err != nil {
		return 0, err
	}

	// storing  prep-term term only if decentralized
	if decentralized == 1 {
		period, err := prep.Period.Value()
		if err != nil {
			return 0, err
		}
		return uint64(period), nil

	}
	return 0, nil
}

func (ip *IconProvider) QueryProofContextChangeHeights(ctx context.Context, counterpartyClientHeight uint64, latestHeight uint64) ([]uint64, error) {
	heights := make([]uint64, 0)
	// querying prepterm

	period, err := ip.GetProofContextChangePeriod()
	if err != nil {
		return heights, err
	}

	// 0 suggest that proof context period is not set
	if period == 0 {
		return heights, nil
	}

	// hasn't reached until the latest block
	if counterpartyClientHeight+period > latestHeight {
		return heights, nil
	}

	lastPeriodChangeHeight := counterpartyClientHeight - counterpartyClientHeight%period

	for lastPeriodChangeHeight < latestHeight {
		lastPeriodChangeHeight += period
		btpblock, err := ip.GetBtpHeader(int64(lastPeriodChangeHeight + 1))
		if err != nil {
			continue
		}
		if btpblock != nil {
			heights = append(heights, btpblock.MainHeight)
		}
	}

	return heights, nil
}
