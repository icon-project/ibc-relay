package cosmos

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	"github.com/CosmWasm/wasmd/app"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type mockAccountSequenceMismatchError struct {
	Expected uint64
	Actual   uint64
}

func (err mockAccountSequenceMismatchError) Error() string {
	return fmt.Sprintf("account sequence mismatch, expected %d, got %d: incorrect account sequence", err.Expected, err.Actual)
}

type Msg struct {
	Count int
}

func (m *Msg) Type() string {
	return "int"
}

func (m *Msg) MsgBytes() ([]byte, error) {
	return json.Marshal(m)
}

func (m *Msg) ValidateBasic() error {
	return nil
}

func (m *Msg) GetSigners() []sdk.AccAddress {
	return nil
}

func (m *Msg) Reset() {

}

func (m *Msg) String() string {
	return "str"
}
func (m *Msg) ProtoMessage() {
}

func TestMsgToSdkMsg(t *testing.T) {
	m := &Msg{Count: 1000}
	cMsg := NewCosmosMessage(m)
	msg := CosmosMsgs(cMsg)
	fmt.Println(msg)

}

func GetProvider(ctx context.Context) (provider.ChainProvider, error) {
	config := CosmosProviderConfig{
		KeyDirectory:   "/home/lilixac/.relayer/keys/archway",
		Key:            "tempwallet",
		ChainName:      "archway",
		ChainID:        "constantine-2",
		RPCAddr:        "https://rpc.constantine-2.archway.tech:443",
		AccountPrefix:  "archway",
		KeyringBackend: "test",
		GasAdjustment:  1.5,
		GasPrices:      "0.02uconst",
		Debug:          true,
		Timeout:        "20s",
		SignModeStr:    "direct",
		MinGasAmount:   300_000,
	}

	p, err := config.NewProvider(&zap.Logger{}, "~/.relayer", true, "archway")
	if err != nil {
		return nil, err
	}
	err = p.Init(ctx)
	if err != nil {
		return nil, err
	}
	return p, err

}

func TestGetAddress(t *testing.T) {

	ctx := context.Background()
	p, _ := GetProvider(ctx)
	pCosmos := p.(*CosmosProvider)
	op, _ := pCosmos.ShowAddress("tempwallet")
	fmt.Println("all the added keys are ", op)
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

func TestTxCall(t *testing.T) {

	ctx := context.Background()
	p, _ := GetProvider(ctx)
	pCosmos := p.(*CosmosProvider)

	account := "archway1fgdnyxpcvm3e24zrxsufl0esztr28n5xawe57f"
	contract := "archway192v3xzzftjylqlty0tw6p8k7adrlf2l3ch9j76augya4yp8tf36ss7d3wa"

	// cl, _ := client.NewClientFromNode("http://localhost:26657")
	cl, _ := client.NewClientFromNode("https://rpc.constantine-2.archway.tech:443")
	addr, err := sdk.AccAddressFromBech32(account)
	assert.NoError(t, err)

	encodingConfig := app.MakeEncodingConfig()
	cliCtx := client.Context{}.
		WithClient(cl).
		WithFromName(pCosmos.PCfg.Key).
		WithFromAddress(addr).
		WithTxConfig(encodingConfig.TxConfig).
		WithSkipConfirmation(true).
		WithBroadcastMode("sync")

	/////////////////////////////////////////////////
	/////////////////////// QUERY ///////////////////
	/////////////////////////////////////////////////

	// type GetAllPacket struct {
	// 	GetAllPacket interface{} `json:"get_all_packet"`
	// }

	// _param := GetAllPacket{GetAllPacket: struct{}{}}
	// param, _ := json.Marshal(_param)

	// queryCLient := wasmtypes.NewQueryClient(cliCtx)
	// contractState, _ := queryCLient.SmartContractState(ctx, &wasmtypes.QuerySmartContractStateRequest{
	// 	Address:   contract,
	// 	QueryData: param,
	// })
	// fmt.Println(contractState)

	/////////////////////////////////////////////////
	///////////////////// EXECUTION /////////////////
	/////////////////////////////////////////////////

	type SendPacketParams struct {
		Packet HexBytes `json:"packet"`
		Id     string   `json:"id"`
	}
	type SendPacket struct {
		Pkt SendPacketParams `json:"send_packet"`
	}

	d := []byte("data")

	sendPkt := SendPacket{
		Pkt: SendPacketParams{
			Packet: NewHexBytes(d),
			Id:     "2",
		},
	}

	dB, err := json.Marshal(sendPkt)
	assert.NoError(t, err)

	msg := &wasmtypes.MsgExecuteContract{
		Sender:   account,
		Contract: contract,
		Msg:      dB,
	}

	a := pCosmos.TxFactory()
	factory, _ := pCosmos.PrepareFactory(a)

	err = tx.GenerateOrBroadcastTxWithFactory(cliCtx, factory, msg)
	assert.NoError(t, err)

	/////////////////////////////////////////////////
	///////////////////// EXECUTION /////////////////
	/////////////////////////////////////////////////

}

func TestHandleAccountSequenceMismatchError(t *testing.T) {
	p := &CosmosProvider{}
	p.handleAccountSequenceMismatchError(mockAccountSequenceMismatchError{Actual: 9, Expected: 10})
	require.Equal(t, p.nextAccountSeq, uint64(10))
}
