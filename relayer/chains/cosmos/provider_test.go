package cosmos

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cosmos/gogoproto/proto"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"
	tendermint "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"
	"github.com/cosmos/relayer/v2/relayer/common"

	tmclient "github.com/cosmos/ibc-go/v7/modules/light-clients/07-tendermint"

	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	ics23 "github.com/cosmos/ics23/go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func GetMockCosmosProvider() (*CosmosProvider, error) {

	pcfg := CosmosProviderConfig{
		AccountPrefix:  "centauri",
		RPCAddr:        "http://localhost:26657",
		Timeout:        "10h",
		KeyringBackend: "test",
		ChainID:        "centauri-testnet-1",
	}
	log := zap.NewNop()
	prov, err := pcfg.NewProvider(log, "/", false, "centaurid")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if err := prov.Init(ctx); err != nil {
		return nil, err
	}

	provid, ok := prov.(*CosmosProvider)
	if !ok {
		return nil, fmt.Errorf("failed to convert type ")
	}
	return provid, nil
}

func TestDecodeMerkleProof(t *testing.T) {

	pro, err := GetMockCosmosProvider()
	assert.NoError(t, err)
	ctx := context.Background()

	height := 10635
	connectionId := "connection-13"
	connection, err := pro.QueryConnection(ctx, int64(height), connectionId)
	assert.NoError(t, err)

	// fromData, _ := hex.DecodeString("0ae0020add020a19636f6e6e656374696f6e732f636f6e6e656374696f6e2d3130124c0a0930382d7761736d2d3212230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180122180a0f30372d74656e6465726d696e742d351a050a036962631a0d0801180120012a050002908001222b08011227020490800120abcebf1caa17e720f9981d4d23b934bff8263b961cdd8726fd508399085cab3120222b08011227040892800120804fb31d265f9febe4df8069e8e867634d9728d79865ed173945bd2e9500d45e20222d08011206060e928001201a21202575ba006a05b3e0b4f777bce72154b0807054a5473412807ba1daa14f5555c5222d080112060a20928001201a212072f68ca2f134b05702d0c81481a33d57b03a184896f939bf6fe78059815ab469222b080112270c4292800120c17c6efb37ea9abaffe34e4dc2f1928e8cbdcf221bc5f5927cab5b9d05e90180200afc010af9010a0369626312205e6ab940f7f3e6758c049b0ed9cdfba1f6b92e605d6e8cb5f1a42c6d5a460c3a1a090801180120012a0100222508011221014e1d5c563b0db0ffdcba6fc97dc0c7b13b5b5c9c341357f08827565047d6c6b9222708011201011a20316a36d621713cc96f137fdce34e0b887317e5bc1d400bdbc7d43a3392f3b441222508011221019f05c673d5e30ae4ce84687b527ec6823f0bb48f41a6f7c0359ff576b5faea1822250801122101c169322de4a462eaecada7ca8e80a4ffb299c9dfad87ce9d79b79c43d0593c9f222708011201011a2034d7875e7c32775823aa0a922f7e23dd09cf55f152f5a40b1778b26e191ca855")
	// assert.Equal(t, connection.Proof, fromData, "proof is not equal")
	fmt.Printf("proof %x \n", connection.Proof)

	var op commitmenttypes.MerkleProof
	err = proto.Unmarshal(connection.Proof, &op)
	assert.NoError(t, err)

	block, err := pro.LightProvider.LightBlock(ctx, int64(height))
	assert.NoError(t, err)

	// consensus state from data
	// csByte, _ := hex.DecodeString("0a0b08ace083aa0610d884c53412220a2031f8b6bfb694c2148c695feeb25834b8ad737a61f1b7883fe7d86b3f6aac1d1d1a209867d31b94e8280141b7cbfd18f675e8cc7066b60932a39404aebcf7e8f6d02d")
	// var cs tmclient.ConsensusState
	// err = proto.Unmarshal(csByte, &cs)
	// assert.NoError(t, err)

	fmt.Printf("root : %x \n", block.SignedHeader.AppHash)
	root := commitmenttypes.MerkleRoot{Hash: block.SignedHeader.AppHash}

	key := host.ConnectionKey(connectionId)
	fmt.Println("connection key: ", string(key))
	merklePath := commitmenttypes.NewMerklePath(string(key))
	path, err := commitmenttypes.ApplyPrefix(defaultChainPrefix, merklePath)
	assert.NoError(t, err)

	// value
	value, err := proto.Marshal(connection.Connection)
	assert.NoError(t, err)
	fmt.Printf("value: %x \n ", value)

	err = op.VerifyMembership([]*ics23.ProofSpec{ics23.IavlSpec, ics23.TendermintSpec}, root, path, value)
	assert.NoError(t, err)

}

func TestGenerateConnectionHandshakeProof(t *testing.T) {

	pro, err := GetMockCosmosProvider()
	assert.NoError(t, err)
	ctx := context.Background()

	height := 10924
	connectionId := "connection-14"

	cs, _, _, _, _, err := pro.GenerateConnHandshakeProof(ctx, int64(height), "08-wasm-3", connectionId)
	assert.NoError(t, err)
	anyCs, err := clienttypes.PackClientState(cs)
	assert.NoError(t, err)

	b, err := proto.Marshal(anyCs)

	fmt.Printf("client state %x \n", b)

}

func TestGenerateVal(t *testing.T) {

	d, _ := hex.DecodeString("0ad8030ad5030a1d636c69656e74732f30382d7761736d2d332f636c69656e7453746174651290010a252f6962632e6c69676874636c69656e74732e7761736d2e76312e436c69656e74537461746512670a3d0a202f69636f6e2e6c69676874636c69656e742e76312e436c69656e745374617465121908c0ba1218901c20c98e072a083078332e69636f6e300338011220dba26dce04b22164b34751ba0e42e60a18e22d179c0d848ad006bd201e7f8bf71a0410c98e071a0d0801180120012a0500028ea601222d080112060204d6aa01201a212003d57c97977de25765fd5ffc14fe57b794d67a665bc3f036d6d15d1635836a82222d080112060408d6aa01201a212050a51e1b4cb7b7b14711ad715ccb4f300f6024a4a98fe4d3d88781fc6d16762b222b080112270610d6aa012025b8312b97b25ee63807b2ecc1592709b283a2b001b5564a69c8f91cbd765c2820222b080112270820d6aa0120047ca7f7a99eb529aa47e5897275f38f5b7f2180f5e6fa4e6fdf6ec3616e3b1920222b080112270a2ed6aa0120c5449ed0890d620585729df614200b9c7630cfa4d9f885ca397173306683158f20222d080112060c56d6aa01201a2120350cea2ecd3e13944b23107b2476e6d1c6accaa99a6c892cbb027f85f66106490afc010af9010a036962631220d497023d6818dfafccb12532875e29df65983eb20b86f7c375875fef2af7ae6d1a090801180120012a0100222508011221014e1d5c563b0db0ffdcba6fc97dc0c7b13b5b5c9c341357f08827565047d6c6b9222708011201011a20316a36d621713cc96f137fdce34e0b887317e5bc1d400bdbc7d43a3392f3b441222508011221019f05c673d5e30ae4ce84687b527ec6823f0bb48f41a6f7c0359ff576b5faea1822250801122101990b5a6d14f4c2ca4ae83341cb992b3a191eb703adfd0b5c538c3986cdda7c6c222708011201011a2004939260c79a0f69a25f2a5a01c8a27286f210729d8c0238e9d59035e768a9e5")
	var c conntypes.ConnectionEnd
	proto.Unmarshal(d, &c)
	fmt.Printf("%s \n", d)

	var op commitmenttypes.MerkleProof
	err := proto.Unmarshal(d, &op)
	assert.NoError(t, err)

	for _, v := range op.Proofs {

		fmt.Printf("key is %x \n", v.GetExist().Key)
		fmt.Printf("value is %x\n", v.GetExist().Value)
	}

	// d ,_ := hex.DecodeString("0a252f6962632e6c69676874636c69656e74732e7761736d2e76312e436c69656e74537461746512670a3d0a202f69636f6e2e6c69676874636c69656e742e76312e436c69656e745374617465121908c0ba1218901c20c98e072a083078332e69636f6e300338011220dba26dce04b22164b34751ba0e42e60a18e22d179c0d848ad006bd201e7f8bf71a0410c98e07")
	// var op wasmclient.ClientState
	// err := proto.Unmarshal(d, &op)
	// assert.NoError(t, err)
	// fmt.Printf("data is: %s ", op.CodeId)

}

func TestWasmClientProtoFile(t *testing.T) {

	// op:=  wasmclient.ClientState{
	// 	Data: []byte("data"),
	// 	CodeId: []byte("code-id"),
	// 	LatestHeight: types.NewHeight(0,20),
	// }

	//  b, err := proto.Marshal(&op)
	// assert.NoError(t, err)
	// fmt.Printf("byte %x \n", b)

	// clientId := "08-wasm"

	// lastInd := strings.LastIndex(clientId, "-")
	// fmt.Println(lastInd)

	pro, err := GetMockCosmosProvider()
	assert.NoError(t, err)
	ctx := context.Background()

	// height := 10924
	// connectionId := "connection-14"
	clientId := "08-wasm-0"

	// height := clienttypes.NewHeight(1, 2201)

	cs, err := pro.QueryClientState(ctx, 0, clientId)
	assert.NoError(t, err)

	// data, err := proto.Marshal(cs.ConsensusState)
	// fmt.Printf("data %x\n", data)
	fmt.Println("type", cs.ClientType())
	fmt.Printf("cs %d \n", cs.GetLatestHeight().GetRevisionHeight())
	fmt.Printf("cs %d \n", cs.GetLatestHeight().GetRevisionNumber())

}

func TestConnectionOpenAck(t *testing.T) {

	b, _ := hex.DecodeString("0a0c636f6e6e656374696f6e2d31120c636f6e6e656374696f6e2d321a230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f52444552454422b8010a2b2f6962632e6c69676874636c69656e74732e74656e6465726d696e742e76312e436c69656e7453746174651288010a1263656e74617572692d746573746e65742d311204080110031a0408c0ba1222040880df6e2a0308d80432003a040801103542190a090801180120012a0100120c0a02000110211804200c300142190a090801180120012a0100120c0a02000110201801200130014a07757067726164654a1075706772616465644942435374617465500158012a06080110c2a40432280a0208010a22122063128404e5cd488d475fa9f5cb7264fff1cfa3e7a7521148eb28a0e5a87d87113a4c0a2408011220dea1f8b19f170ba89f9bec9cbc608c095f1551f740e7193dc1897ebfe69ff6d00a2408011220d06ed9394fd8737c9639fb57ef2305e9fc0e2f2c73fb87b74bfa0caf9363a410424a0a221220e62fbf1bd5989eb5b07fb67fe58e162bf129471bdb4889ca2e4f659bc72556e20a2408011220d06ed9394fd8737c9639fb57ef2305e9fc0e2f2c73fb87b74bfa0caf9363a4104a0408011035522f63656e74617572693167357232766d6e70366c74613963707374346c7a6334737979336b636a326c6a746533746c68")

	var m conntypes.MsgConnectionOpenAck
	err := proto.Unmarshal(b, &m)
	assert.NoError(t, err)

	fmt.Printf("clientState %x \n", m.ClientState.Value)
	// cs, err := clienttypes.UnpackClientState(m.ClientState)
	assert.NoError(t, err)

	// fmt.Println("connectionOpenAck", cs.GetLatestHeight())

	// b, _ := hex.DecodeString("0x0a1263656e74617572692d746573746e65742d311204080110031a0408c0ba1222040880df6e2a0308d80432003a05080110c50342190a090801180120012a0100120c0a02000110211804200c300142190a090801180120012a0100120c0a02000110201801200130014a07757067726164654a107570677261646564494243537461746550015801")
	var tCS tendermint.ClientState

	err = proto.Unmarshal(m.ClientState.Value, &tCS)
	assert.NoError(t, err)

	path := common.GetClientStateCommitmentKey("ics08-tendermint-0")
	csByte := common.Sha3keccak256(m.ClientState.Value)

	fmt.Printf("path : %x \n", path)
	fmt.Printf("clientState keccak: %x \n ", csByte)

	fmt.Println(tCS.GetLatestHeight().GetRevisionHeight())

}

func TestProtoBufDecode(t *testing.T) {
	// b, _ := hex.DecodeString("0a1263656e74617572692d746573746e65742d311204080110031a0408c0ba1222040880df6e2a0308d80432003a05080110fd0242180a090801180120012a0100120b0a010110211804200c300142180a090801180120012a0100120b0a010110201801200130014a07757067726164654a107570677261646564494243537461746550015801")

	b2Equal, _ := hex.DecodeString("0a1263656e74617572692d746573746e65742d311204080110031a0408c0ba1222040880df6e2a0308d80432003a05080110cb0742190a090801180120012a0100120c0a02000110211804200c300142190a090801180120012a0100120c0a02000110201801200130014a07757067726164654a107570677261646564494243537461746550015801")

	var cs tendermint.ClientState

	err := proto.Unmarshal(b2Equal, &cs)
	assert.NoError(t, err)

	specs := commitmenttypes.GetSDKSpecs()
	assert.Equal(t, specs, cs.ProofSpecs)
}

func TestKecca(t *testing.T) {

	d, err := hex.DecodeString("080612087472616e736665721a096368616e6e656c2d3322087472616e736665722a096368616e6e656c2d3132a3017b22616d6f756e74223a22393530303030303030303030222c2264656e6f6d223a22767370222c227265636569766572223a22617263687761793164787979787968797035686b7a676c3372776b6a666b63773530333032636137676539647072222c2273656e646572223a22687862366235373931626530623565663637303633623363313062383430666238313531346462326664222c226d656d6f223a22227d3a06080110a0c21e")
	assert.NoError(t, err)

	var recvPacket chantypes.Packet

	err = proto.Unmarshal(d, &recvPacket)
	assert.NoError(t, err)

	pkt := recvPacket

	fmt.Println("pkt is ", pkt)

	key := host.PacketCommitmentKey(pkt.SourcePort, pkt.SourceChannel, pkt.Sequence)

	fmt.Printf("packet commitment key: %x \n", common.Sha3keccak256(key))

	cdc := MakeCodec(ModuleBasics, []string{})

	commitment := chantypes.CommitPacket(cdc.Marshaler, pkt)

	fmt.Printf("commitment: %x \n", commitment)

	k := common.Sha3keccak256(commitment)

	fmt.Printf("keccak hash: %x \n", k)

	// 174c5d4caf630a3177179384fcb937b32ff2b9c9aa1b75baf9d001ca44c8ba1c8abf0ea23d6df15e019beb89069adde801d0b416ad7313dda3b8918dffcee648
}

func TestCheck(t *testing.T) {

	d, _ := hex.DecodeString("0a0d636f6e6e656374696f6e2d3139120c636f6e6e656374696f6e2d301a230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f52444552454422b9010a2b2f6962632e6c69676874636c69656e74732e74656e6465726d696e742e76312e436c69656e7453746174651289010a1263656e74617572692d746573746e65742d311204080110031a0408c0ba1222040880df6e2a0308d80432003a05080110ed5f42190a090801180120012a0100120c0a02000110211804200c300142190a090801180120012a0100120c0a02000110201801200130014a07757067726164654a1075706772616465644942435374617465500158012a06080110e18d0432280a0208010a2212208a2aa818cbcbf23a39ab8b89ad6e919f63c9a73086c47cb5f42b020c5238f4923a4c0a2408011220a11c2fe63965c80acf540f3641b8a2ab29f4b08e00cfedea6fc08a4ac18c29c00a2408011220199f72f4420d2e29ffe56cbb27858e3b8b2cffacfa0eb1dec3c1add51c2c089e424a0a221220b5f7c49ba32adeb09a4067f59a0140204179a5753700ab778c3ef1d5e05d9f270a2408011220199f72f4420d2e29ffe56cbb27858e3b8b2cffacfa0eb1dec3c1add51c2c089e4a05080110ed5f522f63656e74617572693167357232766d6e70366c74613963707374346c7a6334737979336b636a326c6a746533746c68")

	var msgUpdateClient clienttypes.MsgUpdateClient

	err := proto.Unmarshal(d, &msgUpdateClient)
	assert.NoError(t, err)

	fmt.Println(msgUpdateClient.ClientMessage.Value)

	var d2 tmclient.Header
	err = proto.Unmarshal(msgUpdateClient.ClientMessage.Value, &d2)

	assert.NoError(t, err)

	fmt.Println(d2.SignedHeader.Header.Height)

}
