package icon

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cosmos/gogoproto/proto"
	itm "github.com/cosmos/relayer/v2/relayer/chains/icon/tendermint"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/icon-project/goloop/common/wallet"
	"github.com/icon-project/goloop/module"

	"go.uber.org/zap"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	tmclient "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"
	// integration_types "github.com/icon-project/ibc-integration/libraries/go/common/icon"
)

var (
	_ provider.ChainProvider  = &IconProvider{}
	_ provider.KeyProvider    = &IconProvider{}
	_ provider.ProviderConfig = &IconProviderConfig{}
)

// Default IBC settings
var (
	defaultChainPrefix = types.NewMerklePrefix([]byte("ibc"))
	defaultDelayPeriod = types.NewHexInt(0)

	DefaultIBCVersionIdentifier = "1"

	DefaultIBCVersion = &types.Version{
		Identifier: DefaultIBCVersionIdentifier,
		Features:   []string{"ORDER_ORDERED", "ORDER_UNORDERED"},
	}
)

type IconProviderConfig struct {
	Key               string `json:"key" yaml:"key"`
	ChainName         string `json:"-" yaml:"-"`
	ChainID           string `json:"chain-id" yaml:"chain-id"`
	RPCAddr           string `json:"rpc-addr" yaml:"rpc-addr"`
	Timeout           string `json:"timeout" yaml:"timeout"`
	Keystore          string `json:"keystore" yaml:"keystore"`
	Password          string `json:"password" yaml:"password"`
	ICONNetworkID     int64  `json:"icon-network-id" yaml:"icon-network-id" default:"3"`
	BTPNetworkID      int64  `json:"btp-network-id" yaml:"btp-network-id"`
	BTPHeight         int64  `json:"start-btp-height" yaml:"start-btp-height"`
	IbcHandlerAddress string `json:"ibc-handler-address" yaml:"ibc-handler-address"`
}

func (pp IconProviderConfig) Validate() error {
	if _, err := time.ParseDuration(pp.Timeout); err != nil {
		return fmt.Errorf("invalid Timeout: %w", err)
	}
	return nil
}

// NewProvider should provide a new Icon provider
// NewProvider should provide a new Icon provider
func (pp IconProviderConfig) NewProvider(log *zap.Logger, homepath string, debug bool, chainName string) (provider.ChainProvider, error) {

	pp.ChainName = chainName
	if _, err := os.Stat(pp.Keystore); err != nil {
		return nil, err
	}

	if err := pp.Validate(); err != nil {
		return nil, err
	}

	ksByte, err := os.ReadFile(pp.Keystore)
	if err != nil {
		return nil, err
	}

	wallet, err := wallet.NewFromKeyStore(ksByte, []byte(pp.Password))
	if err != nil {
		return nil, err
	}

	return &IconProvider{
		log:    log.With(zap.String("sys", "chain_client")),
		client: NewClient(pp.getRPCAddr(), log),
		PCfg:   pp,
		wallet: wallet,
	}, nil
}

func (icp *IconProvider) AddWallet(w module.Wallet) {
	icp.wallet = w
}

func (pp IconProviderConfig) getRPCAddr() string {
	return pp.RPCAddr
}

func (pp IconProviderConfig) BroadcastMode() provider.BroadcastMode {
	return provider.BroadcastModeSingle
}

type IconProvider struct {
	log     *zap.Logger
	PCfg    IconProviderConfig
	txMu    sync.Mutex
	client  *Client
	wallet  module.Wallet
	metrics *processor.PrometheusMetrics
	codec   codec.ProtoCodecMarshaler
}

type SignedHeader struct {
	header     types.BTPBlockHeader
	signatures []types.HexBytes
}

type ValidatorSet struct {
	validators []types.HexBytes
}

type IconIBCHeader struct {
	Header *types.BTPBlockHeader
}

func NewIconIBCHeader(header *types.BTPBlockHeader) *IconIBCHeader {
	return &IconIBCHeader{
		Header: header,
	}
}

func (h IconIBCHeader) Height() uint64 {
	return uint64(h.Header.MainHeight)
}

func (h IconIBCHeader) NextValidatorsHash() []byte {

	// nextproofcontext hash is the nextvalidatorHash in BtpHeader
	return h.Header.NextProofContextHash
}

func (h IconIBCHeader) ConsensusState() ibcexported.ConsensusState {
	return &types.ConsensusState{
		MessageRoot: h.Header.MessagesRoot,
	}
}

//ChainProvider Methods

func (icp *IconProvider) Init(ctx context.Context) error {

	return nil
}

func (icp *IconProvider) Codec() codec.ProtoCodecMarshaler {
	return icp.codec
}

// TODO: Remove later
func (icp *IconProvider) NewClientStateMock(
	dstChainID string,
	dstUpdateHeader provider.IBCHeader,
	dstTrustingPeriod,
	dstUbdPeriod time.Duration,
	allowUpdateAfterExpiry,
	allowUpdateAfterMisbehaviour bool,
) (ibcexported.ClientState, error) {

	return &itm.ClientState{
		ChainId: dstChainID,
		TrustLevel: &itm.Fraction{
			Numerator:   2,
			Denominator: 3,
		},
		TrustingPeriod: &itm.Duration{
			Seconds: int64(dstTrustingPeriod),
		},
		UnbondingPeriod: &itm.Duration{
			Seconds: int64(dstUbdPeriod),
		},
		MaxClockDrift: &itm.Duration{
			Seconds: int64(time.Minute) * 20,
		},
		FrozenHeight:                 0,
		LatestHeight:                 int64(dstUpdateHeader.Height()),
		AllowUpdateAfterExpiry:       allowUpdateAfterExpiry,
		AllowUpdateAfterMisbehaviour: allowUpdateAfterMisbehaviour,
	}, nil
}

func (icp *IconProvider) NewClientState(
	dstChainID string,
	dstUpdateHeader provider.IBCHeader,
	dstTrustingPeriod,
	dstUbdPeriod time.Duration,
	allowUpdateAfterExpiry,
	allowUpdateAfterMisbehaviour bool,
) (ibcexported.ClientState, error) {

	revisionNumber := clienttypes.ParseChainID(dstChainID)

	return &tmclient.ClientState{
		ChainId: dstChainID,
		TrustLevel: tmclient.Fraction{
			Numerator:   2,
			Denominator: 3,
		},
		TrustingPeriod:  dstTrustingPeriod,
		UnbondingPeriod: dstUbdPeriod,
		MaxClockDrift:   time.Minute * 10,
		FrozenHeight:    clienttypes.ZeroHeight(),
		LatestHeight: clienttypes.Height{
			RevisionNumber: revisionNumber,
			RevisionHeight: dstUpdateHeader.Height(),
		},
		AllowUpdateAfterExpiry:       allowUpdateAfterExpiry,
		AllowUpdateAfterMisbehaviour: allowUpdateAfterMisbehaviour,
	}, nil

}

func (icp *IconProvider) ConnectionHandshakeProof(ctx context.Context, msgOpenInit provider.ConnectionInfo, height uint64) (provider.ConnectionProof, error) {

	clientState, clientStateProof, consensusStateProof, connStateProof, proofHeight, err := icp.GenerateConnHandshakeProof(ctx, int64(height), msgOpenInit.ClientID, msgOpenInit.ConnID)
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
	connState, err := icp.QueryConnection(ctx, int64(height), msgOpenAck.ConnID)
	if err != nil {
		return provider.ConnectionProof{}, err
	}
	return provider.ConnectionProof{
		ConnectionStateProof: connState.Proof,
		ProofHeight:          connState.ProofHeight,
	}, nil
}

func (icp *IconProvider) ValidatePacket(msgTransfer provider.PacketInfo, latestBlock provider.LatestBlock) error {
	if msgTransfer.Sequence <= 0 {
		return fmt.Errorf("Refuse to relay packet with sequence 0")
	}
	if len(msgTransfer.Data) == 0 {
		return fmt.Errorf("Refuse to relay packet with empty data")
	}
	// This should not be possible, as it violates IBC spec
	if msgTransfer.TimeoutHeight.IsZero() && msgTransfer.TimeoutTimestamp == 0 {
		return fmt.Errorf("refusing to relay packet without a timeout (height or timestamp must be set)")
	}

	revision := clienttypes.ParseChainID(icp.PCfg.ChainID)
	latestClientTypesHeight := clienttypes.NewHeight(revision, latestBlock.Height)
	if !msgTransfer.TimeoutHeight.IsZero() && latestClientTypesHeight.GTE(msgTransfer.TimeoutHeight) {
		return provider.NewTimeoutHeightError(latestBlock.Height, msgTransfer.TimeoutHeight.RevisionHeight)
	}
	latestTimestamp := uint64(latestBlock.Time.UnixNano())
	if msgTransfer.TimeoutTimestamp > 0 && latestTimestamp > msgTransfer.TimeoutTimestamp {
		return provider.NewTimeoutTimestampError(latestTimestamp, msgTransfer.TimeoutTimestamp)
	}

	return nil
}

func (icp *IconProvider) PacketCommitment(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetCommitmentResponse, err := icp.QueryPacketCommitment(
		ctx, int64(height), msgTransfer.SourceChannel, msgTransfer.SourcePort, msgTransfer.Sequence,
	)

	if err != nil {
		return provider.PacketProof{}, nil
	}
	return provider.PacketProof{
		Proof:       packetCommitmentResponse.Proof,
		ProofHeight: packetCommitmentResponse.ProofHeight,
	}, nil
}

func (icp *IconProvider) PacketAcknowledgement(ctx context.Context, msgRecvPacket provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetAckResponse, err := icp.QueryPacketAcknowledgement(ctx, int64(height), msgRecvPacket.SourceChannel, msgRecvPacket.SourcePort, msgRecvPacket.Sequence)
	if err != nil {
		return provider.PacketProof{}, nil
	}
	return provider.PacketProof{
		Proof:       packetAckResponse.Proof,
		ProofHeight: packetAckResponse.GetProofHeight(),
	}, nil

}

func (icp *IconProvider) PacketReceipt(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	packetReceiptResponse, err := icp.QueryPacketReceipt(ctx, int64(height), msgTransfer.SourceChannel, msgTransfer.SourcePort, msgTransfer.Sequence)

	if err != nil {
		return provider.PacketProof{}, nil
	}
	return provider.PacketProof{
		Proof:       packetReceiptResponse.Proof,
		ProofHeight: packetReceiptResponse.ProofHeight,
	}, nil

}

func (icp *IconProvider) NextSeqRecv(ctx context.Context, msgTransfer provider.PacketInfo, height uint64) (provider.PacketProof, error) {
	nextSeqRecvResponse, err := icp.QueryNextSeqRecv(ctx, int64(height), msgTransfer.DestChannel, msgTransfer.DestPort)
	if err != nil {
		return provider.PacketProof{}, nil
	}
	return provider.PacketProof{
		Proof:       nextSeqRecvResponse.Proof,
		ProofHeight: nextSeqRecvResponse.ProofHeight,
	}, nil

}

func (icp *IconProvider) MsgTransfer(dstAddr string, amount sdk.Coin, info provider.PacketInfo) (provider.RelayerMessage, error) {
	return nil, fmt.Errorf("Method not supported on ICON")
}

func (icp *IconProvider) QueryICQWithProof(ctx context.Context, msgType string, request []byte, height uint64) (provider.ICQProof, error) {
	return provider.ICQProof{}, nil
}

func (icp *IconProvider) MsgSubmitQueryResponse(chainID string, queryID provider.ClientICQQueryID, proof provider.ICQProof) (provider.RelayerMessage, error) {
	return nil, nil
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
	return nil, fmt.Errorf("Not implemented")
}

func (icp *IconProvider) SendMessagesToMempool(
	ctx context.Context,
	msgs []provider.RelayerMessage,
	memo string,
	asyncCtx context.Context,
	asyncCallback func(*provider.RelayerTxResponse, error),
) error {
	fmt.Println("mempool segment", len(msgs))
	if len(msgs) == 0 {
		icp.log.Info("Length of Messages is empty ")
		return nil
	}

	fmt.Println("this issssssssssss ")
	for _, msg := range msgs {
		fmt.Println("check the messagessssssss", msg)
		if msg != nil {
			op, _ := msg.MsgBytes()
			fmt.Println("this is the message bytes ", op)
			_, bool, err := icp.SendMessage(ctx, msg, memo)
			if err != nil {
				fmt.Println(" there is some errro in packet xx ")
			}
			if !bool {
				fmt.Println("error when Executing transaction")
			}
		}
	}

	return nil
}

func (icp *IconProvider) ChainName() string {
	return icp.PCfg.ChainName
}

func (icp *IconProvider) ChainId() string {
	return icp.PCfg.ChainID
}

func (icp *IconProvider) Type() string {
	return "icon"
}

func (icp *IconProvider) ProviderConfig() provider.ProviderConfig {
	return icp.PCfg
}

func (icp *IconProvider) CommitmentPrefix() commitmenttypes.MerklePrefix {
	return commitmenttypes.NewMerklePrefix([]byte("ibc"))
}

func (icp *IconProvider) Key() string {
	return ""
}

func (icp *IconProvider) Address() (string, error) {
	return icp.wallet.Address().String(), nil
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
			fmt.Println(err)
		}
		results = append(results, m)
	}
	return results, nil
}

func (icp *IconProvider) GetBtpHeader(p *types.BTPBlockParam) (*types.BTPBlockHeader, error) {
	var header types.BTPBlockHeader
	encoded, err := icp.client.GetBTPHeader(p)
	if err != nil {
		return nil, err
	}

	_, err = Base64ToData(encoded, &header)
	if err != nil {
		return nil, err
	}
	return &header, nil
}
