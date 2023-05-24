package icon

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
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

func GetMockIconProvider(network_id int) *IconProvider {

	absPath, _ := filepath.Abs("../../../env/godWallet.json")

	pcfg := IconProviderConfig{
		Keystore:          absPath,
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

	iconProvider, _ := p.(*IconProvider)
	return iconProvider
}

func TestNetworkSectionHashCheck(t *testing.T) {

	prevNetworkSectionHash, _ := hex.DecodeString("b791b4b069c561ca31093f825f083f6cc3c8e5ad5135625becd2ff77a8ccfa1e")
	messageRoot, _ := hex.DecodeString("84d8e19eb09626e4a94212d3a9db54bc16a75dfd791858c0fab3032b944f657a")
	nextProofContextHash, _ := hex.DecodeString("d090304264eeee3c3562152f2dc355601b0b423a948824fd0a012c11c3fc2fb4")
	header := types.BTPBlockHeader{
		MainHeight:             27,
		Round:                  0,
		NextProofContextHash:   nextProofContextHash,
		NetworkID:              1,
		UpdateNumber:           0,
		PrevNetworkSectionHash: prevNetworkSectionHash,
		MessageCount:           1,
		MessageRoot:            messageRoot,
	}
	networkSectionhash := types.NewNetworkSection(&header).Hash()
	expectNetworkSection, _ := hex.DecodeString("aa517deb1e03f1d461e0f463fa5ebd0126d8a9153fde80778d7d1a1bdfa050fc")
	assert.Equal(t, networkSectionhash, expectNetworkSection)
}
