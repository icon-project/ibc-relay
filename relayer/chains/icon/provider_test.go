package icon

import (
	"context"
	"fmt"
	"os"
	"testing"

	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	"github.com/icon-project/goloop/common/wallet"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestConnectionDecode(t *testing.T) {

	input := ("0x0a0f30372d74656e6465726d696e742d3012230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180322200a0f30372d74656e6465726d696e742d30120d636f6e6e656374696f6e2d3533")

	var conn conntypes.ConnectionEnd
	_, err := HexStringToProtoUnmarshal(input, &conn)
	if err != nil {
		fmt.Println("error occured", err)
		return
	}

	assert.Equal(t, conn.ClientId, "07-tendermint-0")
}

func GetProvider() *IconProvider {
	pcfg := IconProviderConfig{
		Keystore:          "/Users/viveksharmapoudel/my_work_bench/ibriz/ibc-related/ibc-relay/env/godWallet.json",
		Password:          "gochain",
		ICONNetworkID:     3,
		BTPNetworkID:      2,
		IbcHandlerAddress: "cx00ba205e3366369b0ca7f8f2ca39293cffadd33b",
		RPCAddr:           "http://localhost:9082/api/v3",
	}

	c := NewClient(pcfg.RPCAddr, &zap.Logger{})

	ksByte, err := os.ReadFile(pcfg.Keystore)
	if err != nil {
		return nil
	}

	wallet, err := wallet.NewFromKeyStore(ksByte, []byte(pcfg.Password))
	if err != nil {
		return nil
	}

	codec := MakeCodec(ModuleBasics, []string{})

	return &IconProvider{
		PCfg:   &pcfg,
		client: c,
		codec:  codec,
		wallet: wallet,
	}

}

func TestCall(t *testing.T) {

	p := GetProvider()

	ctx := context.Background()
	// height := 441

	// csb, _ := hex.DecodeString("0a0469636f6e1204080210031a0308e80722050880b899292a070880c0cbacf622384440014801")
	// commitmenthash := getCommitmentHash(cryptoutils.GetClientStateCommitmentKey("07-tendermint-0"), csb)
	// b, err := p.QueryIconProof(ctx, int64(height), commitmenthash)

	op, err := p.QueryConnection(ctx, 441, "connection-1")

	assert.NoError(t, err)
	fmt.Printf("check %x \n ", op)
}
