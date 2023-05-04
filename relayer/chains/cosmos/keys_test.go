package cosmos

import (
	"fmt"
	"os"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/relayer/v2/relayer/codecs/ethermint"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func newCosmosProvider() *CosmosProvider {
	pcfg := CosmosProviderConfig{
		ChainName:      "archway",
		KeyDirectory:   "/home/lilixac/.archway/data",
		KeyringBackend: "test",
		Key:            "test-wallet",
		RPCAddr:        "https://rpc.constantine-2.archway.tech",
		AccountPrefix:  "archway",
		Modules:        append([]module.AppModuleBasic{}, ModuleBasics...),
	}
	return &CosmosProvider{
		log:            &zap.Logger{},
		PCfg:           pcfg,
		KeyringOptions: []keyring.Option{ethermint.EthSecp256k1Option()},
		Input:          os.Stdin,
		Output:         os.Stdout,
		Cdc:            MakeCodec(pcfg.Modules, make([]string, 0)),
	}
}
func TestGenerateKey(t *testing.T) {
	cp := newCosmosProvider()
	err := cp.CreateKeystore("/home/lilixac/.archway/data")
	assert.NoError(t, err)
	check := cp.KeystoreCreated("/home/lilixac/.archway/data")
	assert.True(t, check)
	op, err := cp.AddKey("test-wallet", 118)
	assert.NoError(t, err)
	fmt.Println(op)
	addr, err := cp.Address()
	assert.NoError(t, err)
	fmt.Println(addr)
}
