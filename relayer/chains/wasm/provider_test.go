package wasm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	cosmosclient "github.com/cosmos/cosmos-sdk/client"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/gogoproto/proto"
	itm "github.com/icon-project/IBC-Integration/libraries/go/common/tendermint"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"

	// tendermint "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"

	"github.com/cosmos/relayer/v2/relayer/chains/icon"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type mockAccountSequenceMismatchError struct {
	Expected uint64
	Actual   uint64
}

func (err mockAccountSequenceMismatchError) Error() string {
	return fmt.Sprintf("account sequence mismatch, expected %d, got %d: incorrect account sequence", err.Expected, err.Actual)
}

func GetProvider(ctx context.Context, handlerAddr string, local bool) (provider.ChainProvider, error) {

	absPath, _ := filepath.Abs("../../../env/archway/keys")
	var config = WasmProviderConfig{
		KeyDirectory:      absPath,
		Key:               "testWallet",
		ChainName:         "archway",
		ChainID:           "localnet",
		RPCAddr:           "http://localhost:26657",
		AccountPrefix:     "archway",
		KeyringBackend:    "test",
		GasAdjustment:     1.5,
		GasPrices:         "0.02stake",
		Debug:             true,
		Timeout:           "20s",
		SignModeStr:       "direct",
		MinGasAmount:      1000_000,
		IbcHandlerAddress: handlerAddr,
		BlockInterval:     6000,
	}
	if !local {
		config.RPCAddr = "https://rpc.constantine.archway.tech:443"
		config.ChainID = "constantine-3"
		config.GasPrices = "0.02uconst"
	}

	p, err := config.NewProvider(zaptest.NewLogger(&testing.T{}), "../../../env/archway", true, "archway")
	if err != nil {
		return nil, err
	}
	err = p.Init(ctx)
	if err != nil {
		return nil, err
	}
	return p, err

}

type HexBytes string

func (hs HexBytes) Value() ([]byte, error) {
	if hs == "" {
		return nil, nil
	}
	return hex.DecodeString(string(hs[2:]))
}
func NewHexBytes(b []byte) HexBytes {
	return HexBytes(hex.EncodeToString(b))
}

type SendPacket struct {
	Pkt struct {
		Packet HexBytes `json:"packet"`
		Id     string   `json:"id"`
	} `json:"send_packet"`
}

func (m *SendPacket) Type() string {
	return "sendPacket"
}

func (m *SendPacket) MsgBytes() ([]byte, error) {
	return json.Marshal(m)
}

func TestSerializeAny(t *testing.T) {

	d := clienttypes.Height{
		RevisionNumber: 0,
		RevisionHeight: 20000,
	}
	anyValue, err := codectypes.NewAnyWithValue(&d)
	assert.NoError(t, err)
	clt := clienttypes.MsgCreateClient{
		ClientState:    anyValue,
		ConsensusState: anyValue,
		Signer:         "acbdef",
	}
	cdc := MakeCodec(ModuleBasics, []string{})
	actual, err := cdc.Marshaler.MarshalJSON(&clt)
	assert.NoError(t, err)
	expected, _ := hex.DecodeString("7b22636c69656e745f7374617465223a7b224074797065223a222f6962632e636f72652e636c69656e742e76312e486569676874222c227265766973696f6e5f6e756d626572223a2230222c227265766973696f6e5f686569676874223a223230303030227d2c22636f6e73656e7375735f7374617465223a7b224074797065223a222f6962632e636f72652e636c69656e742e76312e486569676874222c227265766973696f6e5f6e756d626572223a2230222c227265766973696f6e5f686569676874223a223230303030227d2c227369676e6572223a22616362646566227d")
	assert.Equal(t, actual, expected)

}

func GetIconProvider(network_id int) *icon.IconProvider {

	pcfg := icon.IconProviderConfig{
		Keystore:          "godWallet",
		KeyDirectory:      "../../../env",
		ChainID:           "ibc-icon",
		Password:          "gochain",
		ICONNetworkID:     3,
		BTPNetworkID:      int64(network_id),
		BTPNetworkTypeID:  1,
		IbcHandlerAddress: "cxff5fce97254f26dee5a5d35496743f61169b6db6",
		RPCAddr:           "http://localhost:9082/api/v3",
		// RPCAddr: "http://localhost:9999",
		Timeout: "20s",
	}
	log, _ := zap.NewProduction()
	p, _ := pcfg.NewProvider(log, "", false, "icon")

	iconProvider, _ := p.(*icon.IconProvider)
	return iconProvider
}

func TestProtoMarshal(t *testing.T) {

	codec := MakeCodec(ModuleBasics, []string{})
	height := clienttypes.Height{
		RevisionHeight: 32318,
		RevisionNumber: 0,
	}
	expected, _ := hex.DecodeString("10befc01")
	b, err := codec.Marshaler.Marshal(&height)
	assert.NoError(t, err)
	assert.Equal(t, b, expected)

}

func TestDecodeProto(t *testing.T) {
	b := "0a086c6f63616c6e65741204080110031a0408c0a90722003898800140014801"
	by, _ := hex.DecodeString(b)

	var cl itm.ClientState
	codec := MakeCodec(ModuleBasics, []string{})
	err := codec.Marshaler.Unmarshal(by, &cl)
	assert.NoError(t, err)

}

func TestGenRoot(t *testing.T) {

	rootB, _ := hex.DecodeString("99306EBA529FB6416B0984146B97C9C76386F226E9541A47197FA7ADA530EDA3")
	root := commitmenttypes.MerkleRoot{Hash: rootB}

	rootMarshalled, _ := proto.Marshal(&root)

	fmt.Printf("proto marshalled root %x \n", rootMarshalled)

}

func TestProtoUnmarshal(t *testing.T) {
	val, _ := hex.DecodeString("080210021a110a046d6f636b12096368616e6e656c2d30220c636f6e6e656374696f6e2d302a0769637332302d31")
	var channelS chantypes.Channel
	err := proto.Unmarshal(val, &channelS)
	assert.NoError(t, err)
	assert.Equal(t, channelS.State, chantypes.State(2))

}

func TestTxSearch(t *testing.T) {
	rpcNode := "https://1rpc.io:443/inj-rpc"
	rpc, err := cosmosclient.NewClientFromNode(rpcNode)
	assert.NoError(t, err)

	prove := true
	page := 1
	perPage := 100
	orderBy := "asc"

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	res, err := rpc.TxSearch(
		ctx,
		"tx.height>=78328133 AND tx.height<=78328139",
		prove,
		&page,
		&perPage,
		orderBy,
	)
	assert.NoError(t, err)

	fmt.Printf("\nTx Results: %+v\n", res.Txs)
}
