package wasm

import (
	"github.com/CosmWasm/wasmd/x/wasm"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
	ibc "github.com/cosmos/ibc-go/v7/modules/core"
	icon_module "github.com/cosmos/relayer/v2/relayer/chains/icon/module"
	wasm_module "github.com/cosmos/relayer/v2/relayer/chains/wasm/module"
	"github.com/cosmos/relayer/v2/relayer/codecs/injective"
)

var ModuleBasics = []module.AppModuleBasic{
	auth.AppModuleBasic{},
	ibc.AppModuleBasic{},
	wasm_module.AppModuleBasic{},
	wasm.AppModuleBasic{},
	icon_module.AppModuleBasic{},
}

type Codec struct {
	InterfaceRegistry types.InterfaceRegistry
	Marshaler         codec.Codec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}

func MakeCodec(moduleBasics []module.AppModuleBasic, extraCodecs []string) Codec {
	modBasic := module.NewBasicManager(moduleBasics...)
	encodingConfig := MakeCodecConfig()
	std.RegisterInterfaces(encodingConfig.InterfaceRegistry)
	injective.RegisterInterfaces(encodingConfig.InterfaceRegistry)
	modBasic.RegisterInterfaces(encodingConfig.InterfaceRegistry)
	return encodingConfig
}

func MakeCodecConfig() Codec {
	interfaceRegistry := types.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)
	return Codec{
		InterfaceRegistry: interfaceRegistry,
		Marshaler:         marshaler,
		TxConfig:          tx.NewTxConfig(marshaler, tx.DefaultSignModes),
		Amino:             codec.NewLegacyAmino(),
	}
}
