package archway

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"go.uber.org/zap"
)

var (
// _ provider.ChainProvider  = &ArchwayProvider{}
// _ provider.KeyProvider    = &ArchwayProvider{}
// _ provider.ProviderConfig = &ArchwayProviderConfig{}
)

type ArchwayProviderConfig struct {
	Key               string `json:"key" yaml:"key"`
	ChainName         string `json:"-" yaml:"-"`
	ChainID           string `json:"chain-id" yaml:"chain-id"`
	RPCAddr           string `json:"rpc-addr" yaml:"rpc-addr"`
	Timeout           string `json:"timeout" yaml:"timeout"`
	Keystore          string `json:"keystore" yaml:"keystore"`
	Password          string `json:"password" yaml:"password"`
	IbcHandlerAddress string `json:"ibc-handler-address" yaml:"ibc-handler-address"`
}

func (pp *ArchwayProviderConfig) Validate() error {
	if _, err := time.ParseDuration(pp.Timeout); err != nil {
		return fmt.Errorf("invalid Timeout: %w", err)
	}
	return nil
}

func (pp *ArchwayProviderConfig) Set(field string, value interface{}) error {
	// TODO: implement
	return nil
}

func (pp *ArchwayProviderConfig) getRPCAddr() string {
	return pp.RPCAddr
}

func (pp *ArchwayProviderConfig) BroadcastMode() provider.BroadcastMode {
	return provider.BroadcastModeSingle
}

func (pp *ArchwayProviderConfig) NewProvider(log *zap.Logger, homepath string, debug bool, chainName string) (provider.ChainProvider, error) {

	pp.ChainName = chainName
	if _, err := os.Stat(pp.Keystore); err != nil {
		return nil, err
	}

	if err := pp.Validate(); err != nil {
		return nil, err
	}

	// ksByte, err := os.ReadFile(pp.Keystore)
	// if err != nil {
	// 	return nil, err
	// }

	// wallet, err := wallet.NewFromKeyStore(ksByte, []byte(pp.Password))
	// if err != nil {
	// 	return nil, err
	// }

	codec := MakeCodec(ModuleBasics, []string{})

	return &ArchwayProvider{
		log:    log.With(zap.String("sys", "chain_client")),
		client: NewClient(pp.getRPCAddr(), log),
		PCfg:   pp,
		wallet: wallet,
		codec:  codec,
	}, nil
}

type ArchwayProvider struct {
	log     *zap.Logger
	PCfg    *ArchwayProviderConfig
	txMu    sync.Mutex
	metrics *processor.PrometheusMetrics
	codec   Codec
}

// type ArchwayIBCHeader struct {
// }

// func NewArchwayIBCHeader() *ArchwayIBCHeader {
// 	return &ArchwayIBCHeader{}
// }

// func (h ArchwayIBCHeader) Height() uint64 {
// 	return 0
// }

// func (h ArchwayIBCHeader) NextValidatorsHash() []byte {

// 	// nextproofcontext hash is the nextvalidatorHash in BtpHeader
// 	return nil
// }

// func (h ArchwayIBCHeader) ConsensusState() ibcexported.ConsensusState {
// 	return &icon.ConsensusState{
// 		MessageRoot: h.Header.MessagesRoot,
// 	}
// }

type CosmosProvider struct {
	log *zap.Logger

	PCfg           ArchwayProviderConfig
	Keybase        keyring.Keyring
	KeyringOptions []keyring.Option
	RPCClient      rpcclient.Client
	Cdc            Codec

	txMu sync.Mutex

	metrics *processor.PrometheusMetrics

	// for comet < v0.37, decode tm events as base64
	cometLegacyEncoding bool
}

func (cc *ArchwayProvider) ProviderConfig() provider.ProviderConfig {
	return cc.PCfg
}

func (cc *ArchwayProvider) ChainId() string {
	return cc.PCfg.ChainID
}

func (cc *ArchwayProvider) ChainName() string {
	return cc.PCfg.ChainName
}

func (cc *ArchwayProvider) Type() string {
	return "archway"
}

func (cc *ArchwayProvider) Key() string {
	return cc.PCfg.Key
}

func (cc *ArchwayProvider) Timeout() string {
	return cc.PCfg.Timeout
}

// CommitmentPrefix returns the commitment prefix for Cosmos
func (cc *CosmosProvider) CommitmentPrefix() commitmenttypes.MerklePrefix {
	return defaultChainPrefix
}
