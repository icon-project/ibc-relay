package icon

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/common"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/icon-project/IBC-Integration/libraries/go/common/icon"
	"github.com/icon-project/goloop/module"

	"go.uber.org/zap"

	sdk "github.com/cosmos/cosmos-sdk/types"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	// integration_types "github.com/icon-project/IBC-Integration/libraries/go/common/icon"
)

var (
	_ provider.ChainProvider  = &IconProvider{}
	_ provider.KeyProvider    = &IconProvider{}
	_ provider.ProviderConfig = &IconProviderConfig{}
)

// Default IBC settings
var (
	defaultDelayPeriod = types.NewHexInt(0)

	DefaultIBCVersionIdentifier = "1"

	DefaultIBCVersion = &icon.Version{
		Identifier: DefaultIBCVersionIdentifier,
		Features:   []string{"ORDER_ORDERED", "ORDER_UNORDERED"},
	}

	NOT_IMPLEMENTED = " :: Not implemented for ICON"
)

/*
 * The provider assumes the key is in
 * KeyDirectory/Keystore.json
 */
type IconProviderConfig struct {
	KeyDirectory         string `json:"key-directory" yaml:"key-directory"`
	ChainName            string `json:"-" yaml:"-"`
	ChainID              string `json:"chain-id" yaml:"chain-id"`
	RPCAddr              string `json:"rpc-addr" yaml:"rpc-addr"`
	Timeout              string `json:"timeout" yaml:"timeout"`
	Keystore             string `json:"keystore" yaml:"keystore"`
	Password             string `json:"password" yaml:"password"`
	ICONNetworkID        int64  `json:"icon-network-id" yaml:"icon-network-id" default:"3"`
	BTPNetworkID         int64  `json:"btp-network-id" yaml:"btp-network-id"`
	BTPNetworkTypeID     int64  `json:"btp-network-type-id" yaml:"btp-network-type-id"`
	StartHeight          int64  `json:"start-height" yaml:"start-height"`
	IbcHandlerAddress    string `json:"ibc-handler-address" yaml:"ibc-handler-address"`
	FirstRetryBlockAfter uint64 `json:"first-retry-block-after" yaml:"first-retry-block-after"`
	BlockInterval        uint64 `json:"block-interval" yaml:"block-interval"`
}

func (pp *IconProviderConfig) Validate() error {
	if _, err := time.ParseDuration(pp.Timeout); err != nil {
		return fmt.Errorf("invalid Timeout: %w", err)
	}

	if !isValidIconContractAddress(pp.IbcHandlerAddress) {
		return fmt.Errorf("Ibc handler Address cannot be empty")
	}

	if pp.BlockInterval == 0 {
		return fmt.Errorf("Block interval cannot be zero")
	}

	return nil
}

func (pp *IconProviderConfig) GetBlockInterval() uint64 {
	return pp.BlockInterval
}

func (pp *IconProviderConfig) GetFirstRetryBlockAfter() uint64 {
	if pp.FirstRetryBlockAfter != 0 {
		return pp.FirstRetryBlockAfter
	}
	return 8
}

// NewProvider should provide a new Icon provider
func (pp *IconProviderConfig) NewProvider(log *zap.Logger, homepath string, debug bool, chainName string) (provider.ChainProvider, error) {

	pp.ChainName = chainName

	if err := pp.Validate(); err != nil {
		return nil, err
	}

	codec := MakeCodec(ModuleBasics, []string{})

	return &IconProvider{
		log:         log.With(zap.String("chain_id", pp.ChainID)),
		client:      NewClient(pp.getRPCAddr(), log),
		PCfg:        pp,
		StartHeight: uint64(pp.StartHeight),
		codec:       codec,
	}, nil
}

func (pp IconProviderConfig) getRPCAddr() string {
	return pp.RPCAddr
}

func (pp IconProviderConfig) BroadcastMode() provider.BroadcastMode {
	return provider.BroadcastModeBatch
}

type IconProvider struct {
	log         *zap.Logger
	PCfg        *IconProviderConfig
	txMu        sync.Mutex
	client      *Client
	metrics     *processor.PrometheusMetrics
	codec       Codec
	StartHeight uint64
}

type IconIBCHeader struct {
	Header     *types.BTPBlockHeader
	IsBTPBlock bool
	Validators [][]byte
	MainHeight uint64
}

func NewIconIBCHeader(header *types.BTPBlockHeader, validators [][]byte, height int64) IconIBCHeader {
	iconIBCHeader := IconIBCHeader{
		Header:     header,
		Validators: validators,
	}

	if header == nil {
		iconIBCHeader.IsBTPBlock = false
		iconIBCHeader.MainHeight = uint64(height)
	} else {
		iconIBCHeader.IsBTPBlock = true
		iconIBCHeader.MainHeight = header.MainHeight
	}

	return iconIBCHeader
}

func (h IconIBCHeader) Height() uint64 {
	return h.MainHeight
}

func (h IconIBCHeader) NextValidatorsHash() []byte {
	// nextproofcontext hash is the nextvalidatorHash in BtpHeader
	if h.IsBTPBlock {
		return h.Header.NextProofContextHash
	}
	return nil
}

func (h IconIBCHeader) IsCompleteBlock() bool {
	return h.IsBTPBlock
}

func (h IconIBCHeader) ConsensusState() ibcexported.ConsensusState {
	if h.IsBTPBlock {
		return &icon.ConsensusState{
			MessageRoot:          h.Header.MessageRoot,
			NextProofContextHash: h.Header.NextProofContextHash,
		}
	}
	return &icon.ConsensusState{}
}

func (h IconIBCHeader) ShouldUpdateForProofContextChange() bool {
	if h.Header != nil && h.Header.NextProofContext != nil {
		return true
	}
	return false
}

//ChainProvider Methods

func (icp *IconProvider) Init(ctx context.Context) error {
	// if _, err := os.Stat(icp.PCfg.Keystore); err != nil {
	// 	return err
	// }

	// ksByte, err := os.ReadFile(icp.PCfg.Keystore)
	// if err != nil {
	// 	return err
	// }

	// wallet, err := wallet.NewFromKeyStore(ksByte, []byte(icp.PCfg.Password))
	// if err != nil {
	// 	return err
	// }
	// icp.AddWallet(wallet)
	return nil
}

func (icp *IconProvider) NewClientState(
	dstChainID string,
	dstUpdateHeader provider.IBCHeader,
	dstTrustingPeriod,
	dstUbdPeriod time.Duration,
	allowUpdateAfterExpiry,
	allowUpdateAfterMisbehaviour bool,
) (ibcexported.ClientState, error) {

	if !dstUpdateHeader.IsCompleteBlock() {
		return nil, fmt.Errorf("Not complete block at height:%d", dstUpdateHeader.Height())
	}

	if icp.PCfg.BlockInterval == 0 {
		return nil, fmt.Errorf("Blockinterval cannot be empty in Icon config")
	}

	trustingBlockPeriod := uint64(dstTrustingPeriod) / (icp.PCfg.BlockInterval * uint64(common.NanoToMilliRatio))

	return &icon.ClientState{
		// In case of Icon: Trusting Period is block Difference // see: light.proto in ibc-integration
		TrustingPeriod: trustingBlockPeriod,
		FrozenHeight:   0,
		MaxClockDrift:  3600,
		LatestHeight:   dstUpdateHeader.Height(),
		SrcNetworkId:   getSrcNetworkId(icp.PCfg.ICONNetworkID),
		NetworkId:      uint64(icp.PCfg.BTPNetworkID),
		NetworkTypeId:  uint64(icp.PCfg.BTPNetworkTypeID),
	}, nil

}

func (icp *IconProvider) ConnectionHandshakeProof(ctx context.Context, msgOpenInit provider.ConnectionInfo, height uint64) (provider.ConnectionProof, error) {
	clientState, clientStateProof, consensusStateProof, connStateProof, proofHeight, err := icp.GenerateConnHandshakeProof(ctx, int64(msgOpenInit.Height), msgOpenInit.ClientID, msgOpenInit.ConnID)
	if err != nil {
		return provider.ConnectionProof{}, err
	}

	if len(connStateProof) == 0 {
		return provider.ConnectionProof{}, fmt.Errorf("Received invalid zero length connection state proof")
	}

	return provider.ConnectionProof{
		ClientState:          clientState,
		ClientStateProof:     clientStateProof,
		ConsensusStateProof:  consensusStateProof,
		ConnectionStateProof: connStateProof,
		ProofHeight:          proofHeight.(clienttypes.Height),
	}, nil

}

func (icp *IconProvider) ConnectionProof(ctx context.Context, msgOpenAck provider.ConnectionInfo, height uint64) (provider.ConnectionProof, error) {

	connState, err := icp.QueryConnection(ctx, int64(msgOpenAck.Height), msgOpenAck.ConnID)
	if err != nil {
		return provider.ConnectionProof{}, err
	}
	return provider.ConnectionProof{
		ConnectionStateProof: connState.Proof,
		ProofHeight:          connState.ProofHeight,
	}, nil
}

func (icp *IconProvider) ChannelProof(ctx context.Context, msg provider.ChannelInfo, height uint64) (provider.ChannelProof, error) {

	channelResult, err := icp.QueryChannel(ctx, int64(msg.Height), msg.ChannelID, msg.PortID)
	if err != nil {
		return provider.ChannelProof{}, nil
	}
	return provider.ChannelProof{
		Proof:       channelResult.Proof,
		ProofHeight: channelResult.ProofHeight,
		Ordering:    chantypes.Order(channelResult.Channel.GetOrdering()),
		Version:     channelResult.Channel.Version,
	}, nil
}

func (icp *IconProvider) ValidatePacket(msgTransfer provider.PacketInfo, latestBlock provider.LatestBlock) error {
	if msgTransfer.Sequence <= 0 {
		return fmt.Errorf("refuse to relay packet with sequence 0")
	}
	if len(msgTransfer.Data) == 0 {
		return fmt.Errorf("refuse to relay packet with empty data")
	}
	// This should not be possible, as it violates IBC spec
	if msgTransfer.TimeoutHeight.IsZero() {
		return fmt.Errorf("refusing to relay packet without a timeout (height or timestamp must be set)")
	}

	revision := uint64(0)
	latestClientTypesHeight := clienttypes.NewHeight(revision, latestBlock.Height)

	if !msgTransfer.TimeoutHeight.IsZero() && latestClientTypesHeight.GTE(msgTransfer.TimeoutHeight) {
		return provider.NewTimeoutHeightError(latestBlock.Height, msgTransfer.TimeoutHeight.RevisionHeight)
	}
	// latestTimestamp := uint64(latestBlock.Time.UnixNano())
	// if msgTransfer.TimeoutTimestamp > 0 && latestTimestamp > msgTransfer.TimeoutTimestamp {
	// 	return provider.NewTimeoutTimestampError(latestTimestamp, msgTransfer.TimeoutTimestamp)
	// }

	return nil
}

func (icp *IconProvider) PacketCommitment(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetCommitmentResponse, err := icp.QueryPacketCommitment(
		ctx, int64(msgTransfer.Height), msgTransfer.SourceChannel, msgTransfer.SourcePort, msgTransfer.Sequence,
	)

	if err != nil {
		return provider.PacketProof{}, err
	}
	return provider.PacketProof{
		Proof:       packetCommitmentResponse.Proof,
		ProofHeight: packetCommitmentResponse.ProofHeight,
	}, nil
}

func (icp *IconProvider) PacketAcknowledgement(ctx context.Context, msgRecvPacket provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetAckResponse, err := icp.QueryPacketAcknowledgement(ctx, int64(msgRecvPacket.Height), msgRecvPacket.DestChannel, msgRecvPacket.DestPort, msgRecvPacket.Sequence)
	if err != nil {
		return provider.PacketProof{}, err
	}
	return provider.PacketProof{
		Proof:       packetAckResponse.Proof,
		ProofHeight: packetAckResponse.ProofHeight,
	}, nil

}

func (icp *IconProvider) PacketReceipt(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetReceiptResponse, err := icp.QueryPacketReceipt(ctx, int64(msgTransfer.Height), msgTransfer.DestChannel, msgTransfer.DestPort, msgTransfer.Sequence)

	if err != nil {
		return provider.PacketProof{}, err
	}
	return provider.PacketProof{
		Proof:       packetReceiptResponse.Proof,
		ProofHeight: packetReceiptResponse.ProofHeight,
	}, nil

}

func (icp *IconProvider) NextSeqRecv(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	nextSeqRecvResponse, err := icp.QueryNextSeqRecv(ctx, int64(msgTransfer.Height), msgTransfer.DestChannel, msgTransfer.DestPort)
	if err != nil {
		return provider.PacketProof{}, err
	}
	return provider.PacketProof{
		Proof:       nextSeqRecvResponse.Proof,
		ProofHeight: nextSeqRecvResponse.ProofHeight,
	}, nil

}

func (icp *IconProvider) MsgTransfer(dstAddr string, amount sdk.Coin, info provider.PacketInfo) (provider.RelayerMessage, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) QueryICQWithProof(ctx context.Context, msgType string, request []byte, height uint64) (provider.ICQProof, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) MsgSubmitQueryResponse(chainID string, queryID provider.ClientICQQueryID, proof provider.ICQProof) (provider.RelayerMessage, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) RelayPacketFromSequence(ctx context.Context, src provider.ChainProvider, srch, dsth, seq uint64, srcChanID, srcPortID string, order chantypes.Order) (provider.RelayerMessage, provider.RelayerMessage, error) {
	msg, err := src.QuerySendPacket(ctx, srcChanID, srcPortID, seq)
	if err != nil {
		return nil, nil, err
	}
	dstTime, err := icp.BlockTime(ctx, int64(dsth))
	if err != nil {
		return nil, nil, err
	}

	if err := icp.ValidatePacket(msg, provider.LatestBlock{
		Height: dsth,
		Time:   dstTime,
	}); err != nil {
		// TODO: handle
	}

	return nil, nil, nil
}

func (icp *IconProvider) AcknowledgementFromSequence(ctx context.Context, dst provider.ChainProvider, dsth, seq uint64, dstChanID, dstPortID, srcChanID, srcPortID string) (provider.RelayerMessage, error) {
	msgRecvPacket, err := dst.QueryRecvPacket(ctx, dst.ChainId(), dstPortID, seq)
	if err != nil {
		return nil, err
	}
	pp, err := dst.PacketAcknowledgement(ctx, msgRecvPacket, dsth)
	if err != nil {
		return nil, err
	}
	msg, err := icp.MsgAcknowledgement(msgRecvPacket, pp)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (icp *IconProvider) MsgSubmitMisbehaviour(clientID string, misbehaviour ibcexported.ClientMessage) (provider.RelayerMessage, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}

func (icp *IconProvider) ChainName() string {
	return icp.PCfg.ChainName
}

func (icp *IconProvider) ChainId() string {
	return icp.PCfg.ChainID
}

func (icp *IconProvider) Type() string {
	return common.IconModule
}

func (icp *IconProvider) ProviderConfig() provider.ProviderConfig {
	return icp.PCfg
}

func (icp *IconProvider) CommitmentPrefix() commitmenttypes.MerklePrefix {
	return commitmenttypes.NewMerklePrefix(nil)
}

func (icp *IconProvider) Key() string {
	return icp.PCfg.Keystore
}

func (icp *IconProvider) Wallet() (module.Wallet, error) {
	return icp.RestoreIconKeyStore(icp.PCfg.Keystore, []byte(icp.PCfg.Password))
}

func (icp *IconProvider) Address() (string, error) {
	return icp.ShowAddress(icp.PCfg.Keystore)
}

func (icp *IconProvider) Timeout() string {
	return icp.PCfg.Timeout
}

func (icp *IconProvider) TrustingPeriod(ctx context.Context) (time.Duration, error) {
	return 1000, nil
}

// not required initially
func (icp *IconProvider) WaitForNBlocks(ctx context.Context, n int64) error {
	return nil
}

func (icp *IconProvider) Sprint(toPrint proto.Message) (string, error) {
	return "", nil
}

func (icp *IconProvider) GetBtpMessage(height int64) ([][]byte, error) {
	pr := types.BTPBlockParam{
		Height:    types.NewHexInt(height),
		NetworkId: types.NewHexInt(icp.PCfg.BTPNetworkID),
	}

	msgs, err := icp.client.GetBTPMessage(&pr)
	if err != nil {
		return nil, err
	}

	results := make([][]byte, 0)
	for _, mg := range msgs {
		m, err := base64.StdEncoding.DecodeString(mg)
		if err != nil {
			return nil, err
		}
		results = append(results, m)
	}
	return results, nil
}

func (icp *IconProvider) GetBtpHeader(height int64) (*types.BTPBlockHeader, error) {
	var header types.BTPBlockHeader
	encoded, err := icp.client.GetBTPHeader(&types.BTPBlockParam{
		Height:    types.NewHexInt(height),
		NetworkId: types.NewHexInt(icp.PCfg.BTPNetworkID),
	})
	if err != nil {
		return nil, err
	}

	_, err = Base64ToData(encoded, &header)
	if err != nil {
		return nil, err
	}
	return &header, nil
}

func (icp *IconProvider) GetBTPProof(height int64) ([][]byte, error) {
	var valSigs types.ValidatorSignatures
	encoded, err := icp.client.GetBTPProof(&types.BTPBlockParam{
		Height:    types.NewHexInt(int64(height)),
		NetworkId: types.NewHexInt(icp.PCfg.BTPNetworkID),
	})
	if err != nil {
		return nil, err
	}

	_, err = Base64ToData(encoded, &valSigs)
	if err != nil {
		return nil, err
	}
	return valSigs.Signatures, nil

}

func (icp *IconProvider) GetProofContextByHeight(height int64) ([][]byte, error) {
	var validatorList types.ValidatorList
	info, err := icp.client.GetNetworkTypeInfo(int64(height), icp.PCfg.BTPNetworkTypeID)
	if err != nil {
		return nil, err
	}

	_, err = Base64ToData(string(info.NextProofContext), &validatorList)
	if err != nil {
		return nil, err
	}
	return validatorList.Validators, nil
}

func (icp *IconProvider) GetCurrentBtpNetworkStartHeight() (int64, error) {
	info, err := icp.client.GetBTPNetworkInfo(&types.BTPNetworkInfoParam{
		Id: types.NewHexInt(icp.PCfg.BTPNetworkID),
	})
	if err != nil {
		return 0, err
	}
	return info.StartHeight.Value()
}

func (icp *IconProvider) MsgRegisterCounterpartyPayee(portID, channelID, relayerAddr, counterpartyPayeeAddr string) (provider.RelayerMessage, error) {
	panic(fmt.Sprintf("%s%s", icp.ChainName(), NOT_IMPLEMENTED))
}
