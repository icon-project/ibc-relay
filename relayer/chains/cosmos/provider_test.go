package cosmos

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	abci "github.com/cometbft/cometbft/abci/types"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/gogoproto/proto"
	ics23 "github.com/cosmos/ics23/go"

	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
)

// func TestQueryAbci(t *testing.T) {

// 	newCLient, _ := NewRPCClient("http://localhost:9999", 1*time.Second)

// 	ctx := context.Background()

// 	key := []byte(fmt.Sprintf("%s/%s", "archway1fsqwsl7nxnwnc56akan6l6khwwnscsl5pksv9nr8gcmd4qtue8gs6ug66a", "state"))

// 	req := abci.RequestQuery{
// 		Path:  fmt.Sprintf("store/wasm/key"),
// 		Data:  key, //{contract_add}/state_variable
// 		Prove: true,
// 	}

// 	opts := rpcclient.ABCIQueryOptions{
// 		Height: req.Height,
// 		Prove:  req.Prove,
// 	}

// 	result, err := newCLient.ABCIQueryWithOptions(ctx, req.Path, req.Data, opts)
// 	if err != nil {
// 		fmt.Println("error occured", err)
// 		return
// 	}

// 	merkleProof, err := commitmenttypes.ConvertProofs(result.Response.ProofOps)
// 	if err != nil {
// 		return
// 	}

// 	cdcMaster := MakeCodec(ModuleBasics, []string{})
// 	cdc := codec.NewProtoCodec(cdcMaster.InterfaceRegistry)

// 	proofBz, _ := cdc.Marshal(&merkleProof)
// 	// b, _ := proto.Marshal(&merkleProof)

// 	fmt.Printf("check %x \n ", proofBz)

// }

func TestQueryAbci(t *testing.T) {

	newCLient, _ := NewRPCClient("http://localhost:26657", 1*time.Second)

	ctx := context.Background()

	byt, _ := hex.DecodeString("03ade4a5f5803a439835c636395a8d648dee57b2fc90d98dc17fa887159b69638b")
	// bytS := string(byt) + "/state"
	keyByt, _ := hex.DecodeString("7374617465")

	// str := "03ade4a5f5803a439835c636395a8d648dee57b2fc90d98dc17fa887159b69638b" + "/state"

	// contract_key := "archway14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sy85n2u"
	// contract_key := "/"

	x := wasmtypes.QueryRawContractStateRequest{
		Address:   "archway1fsqwsl7nxnwnc56akan6l6khwwnscsl5pksv9nr8gcmd4qtue8gs6ug66a",
		QueryData: keyByt,
	}

	proto.Marshal(&x)

	req := abci.RequestQuery{

		Path:   fmt.Sprintf("/cosmwasm.wasm.v1.Query/RawContractState"),
		Data:   byt,
		Prove:  true,
		Height: 10,
	}

	// op, e := newCLient.ABCIInfo(ctx)
	// assert.NoError(t, e)
	// fmt.Printf("check the output %+v", op.Response.Data)

	opts := rpcclient.ABCIQueryOptions{
		Height: req.Height,
		Prove:  req.Prove,
	}

	result, err := newCLient.ABCIQueryWithOptions(ctx, req.Path, req.Data, opts)
	if err != nil {
		fmt.Println("error occured", err)
		return
	}

	fmt.Println("Reponse : ", result.Response)

	merkleProof, err := commitmenttypes.ConvertProofs(result.Response.ProofOps)

	// byt, err := proto.Marshal(&merkleProof)

	cdcMaster := MakeCodec(ModuleBasics, []string{})
	cdc := codec.NewProtoCodec(cdcMaster.InterfaceRegistry)

	proofBz, _ := cdc.Marshal(&merkleProof)
	// b, _ := proto.Marshal(&merkleProof)

	fmt.Printf("check %x \n ", proofBz)

	// modules := append([]module.AppModuleBasic{}, ModuleBasics...)
	// cdcw := MakeCodec(modules, make([]string, 0))

	// cdc := codec.NewProtoCodec(cdcw.InterfaceRegistry)
	// cdc.Marshal(&merkleProof.Proofs)
	// assert.NoError(t, err)
	// fmt.Printf("check : %x\n", byt)

}

func TestProto(t *testing.T) {

	keyByt, _ := hex.DecodeString("7374617465")

	x := wasmtypes.QueryRawContractStateRequest{
		Address:   "archway14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sy85n2u",
		QueryData: keyByt,
	}

	b, _ := proto.Marshal(&x)

	fmt.Printf("hex print %x \n ", b)
}

func TestVerifyMembership(t *testing.T) {

	value, _ := hex.DecodeString("7b22636f756e74223a3132332c226f776e6572223a22617263687761793137736478337979616868757479646d6370676666717963336776736d6e376861737064646372227d")
	pathB, _ := hex.DecodeString("03" + "ade4a5f5803a439835c636395a8d648dee57b2fc90d98dc17fa887159b69638b" + "7374617465")

	path := commitmenttypes.MerklePath{KeyPath: []string{
		"wasm",
		string(pathB),
	}}

	rootB, _ := hex.DecodeString("5795D36CDD667C9AD779C7926CA55959F2A9878299168CA75C3A609119B32C35")
	root := commitmenttypes.MerkleRoot{Hash: rootB}

	proofB, _ := hex.DecodeString("0a87020a84020a2603ade4a5f5803a439835c636395a8d648dee57b2fc90d98dc17fa887159b69638b737461746512467b22636f756e74223a3132332c226f776e6572223a22617263687761793137736478337979616868757479646d6370676666717963336776736d6e376861737064646372227d1a0c0801180120012a040002a203222a080112260204a2032045c33ad6b1ffd1a824e2e2496a6640500c1ba9b332d3a657422697f755ce493120222a080112260408a20320def8240f5f16c2c4b79d17ee48f4939ff19ea49eb4b1162b1d4443fd71bfa6f820222c080112050812a203201a21205e39646ef489e2fccdac2fe5ba806ce6dc61473ffceb55eb00b686f59cf21ada0a84010a81010a047761736d1220d3eca53b11b0d106280021909b55faa897d1e4aafa694233b147ea0807f4e1471a090801180120012a0100222508011221011107704879ce264af2b8ca54a7ad461538067d296f22b7de0482e4fdf43314b9222508011221012a624d3673d5196e97e16d8233f6c3d1d16da8fa6fda1b24c4d6c34e999ea53a")

	var merkleProof commitmenttypes.MerkleProof

	err := proto.Unmarshal(proofB, &merkleProof)
	if err != nil {
		fmt.Println("couldnt convert ", err)
	}

	err = merkleProof.VerifyMembership([]*ics23.ProofSpec{ics23.IavlSpec, ics23.TendermintSpec}, root, path, value)
	if err != nil {
		fmt.Println("failed to verify Memebership ", err)
	}

}
