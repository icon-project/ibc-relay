package cosmos

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"testing"
// 	"time"

// 	cosmwasm_types "github.com/CosmWasm/wasmd/x/wasm/types"
// 	"github.com/cosmos/cosmos-sdk/client"
// 	"github.com/cosmos/cosmos-sdk/client/tx"
// 	"github.com/cosmos/cosmos-sdk/types"

// 	// sdk "github.com/cosmos/cosmos-sdk/types"
// 	"github.com/cosmos/relayer/v2/relayer/provider"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// 	"go.uber.org/zap"
// )

// type mockAccountSequenceMismatchError struct {
// 	Expected uint64
// 	Actual   uint64
// }

// func (err mockAccountSequenceMismatchError) Error() string {
// 	return fmt.Sprintf("account sequence mismatch, expected %d, got %d: incorrect account sequence", err.Expected, err.Actual)
// }

// func TestHandleAccountSequenceMismatchError(t *testing.T) {
// 	p := &CosmosProvider{}
// 	p.handleAccountSequenceMismatchError(mockAccountSequenceMismatchError{Actual: 9, Expected: 10})
// 	require.Equal(t, p.nextAccountSeq, uint64(10))
// }

// type Msg struct {
// 	Count int
// 	Owner string
// }

// func (m *Msg) Type() string {
// 	return "int"
// }

// func (m *Msg) MsgBytes() ([]byte, error) {
// 	return json.Marshal(m)
// }

// func (m *Msg) ValidateBasic() error {
// 	return nil
// }

// func (m *Msg) GetSigners() []types.AccAddress {
// 	return nil
// }

// func (m *Msg) Reset() {

// }

// func (m *Msg) String() string {
// 	return "str"
// }
// func (m *Msg) ProtoMessage() {
// }

// func TestMsgToSdkMsg(t *testing.T) {
// 	m := &Msg{Count: 1000}
// 	cMsg := NewCosmosMessage(m)
// 	msg := CosmosMsgs(cMsg)
// 	fmt.Println(msg)

// }

// func GetProvider(ctx context.Context) (provider.ChainProvider, error) {
// 	config := CosmosProviderConfig{
// 		KeyDirectory:   "/Users/viveksharmapoudel/.relayer/keys/archway",
// 		Key:            "godWallet3",
// 		ChainName:      "archway",
// 		ChainID:        "my-chain",
// 		RPCAddr:        "http://localhost:26657",
// 		AccountPrefix:  "archway",
// 		KeyringBackend: "test",
// 		GasAdjustment:  1.2,
// 		GasPrices:      "0.01validatortoken",
// 		Debug:          true,
// 		Timeout:        "20s",
// 		SignModeStr:    "direct",
// 	}

// 	p, err := config.NewProvider(&zap.Logger{}, "~/.relayer", true, "archway")
// 	if err != nil {
// 		return nil, err
// 	}
// 	err = p.Init(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return p, err

// }

// func TestGetAddress(t *testing.T) {

// 	ctx := context.Background()
// 	p, _ := GetProvider(ctx)
// 	pCosmos := p.(*CosmosProvider)
// 	// key1, err := pCosmos.AddKey("testkey", 1)
// 	// fmt.Println(key1)
// 	// assert.NoError(t, err)
// 	op, _ := pCosmos.ListAddresses()
// 	fmt.Println("all the added keys are ", op)
// }

// func TestTxCall(t *testing.T) {

// 	ctx := context.Background()
// 	p, _ := GetProvider(ctx)
// 	pCosmos := p.(*CosmosProvider)
// 	// pCosmos.buildMessages()

// 	var msgs []provider.RelayerMessage
// 	m := &Msg{Count: 10}
// 	cMsg := NewCosmosMessage(m)
// 	msgs = append(msgs, cMsg)

// 	tx, _, _, err := pCosmos.buildMessages(ctx, msgs, "")
// 	assert.NoError(t, err)

// 	res, err := pCosmos.RPCClient.BroadcastTxSync(ctx, tx)
// 	time.Sleep(time.Second * 5)
// 	assert.NoError(t, err)
// 	fmt.Printf("%+v", res)

// }

// func TestTxContract(t *testing.T) {

// 	cl, _ := client.NewClientFromNode("http://localhost:26657")
// 	ctx := context.Background()

// 	p, _ := GetProvider(ctx)

// 	cosmosP := p.(*CosmosProvider)

// 	// cfg := sdk.GetConfig()
// 	// cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
// 	// cfg.SetBech32PrefixForValidator(app.Bech32PrefixValAddr, app.Bech32PrefixValPub)
// 	// cfg.SetBech32PrefixForConsensusNode(app.Bech32PrefixConsAddr, app.Bech32PrefixConsPub)
// 	// cfg.SetAddressVerifier(wasmtypes.VerifyAddressLen())
// 	// cfg.Seal()

// 	a := cosmosP.TxFactory()
// 	factory, _ := cosmosP.PrepareFactory(a)

// 	cliCtx := client.Context{}.WithClient(cl)

// 	msg := &cosmwasm_types.MsgExecuteContract{
// 		Sender:   "archway1d0hpuustya4rpx082w6vjrw4u4hwtkctshyjpu",
// 		Contract: "archway14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sy85n2u",
// 		Msg:      []byte(`{"reset":{"count":123}}`),
// 	}

// 	err := tx.GenerateOrBroadcastTxWithFactory(cliCtx, factory, msg)
// 	assert.NoError(t, err)

// }
