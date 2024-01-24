package wasm

import (
	"encoding/json"

	"github.com/cosmos/relayer/v2/relayer/provider"
)

type ClaimFeesMsg struct {
	ClaimFees struct {
		Nid     string `json:"nid"`
		Address string `json:"address"`
	} `json:"claim_fees"`
}

func (c *ClaimFeesMsg) Type() string {
	return "claim_fees"
}

func (c *ClaimFeesMsg) MsgBytes() ([]byte, error) {
	return json.Marshal(c)
}

func (ap *WasmProvider) MsgClaimFees(dstChainID, dstAddress string) (provider.RelayerMessage, error) {
	params := &ClaimFeesMsg{
		ClaimFees: struct {
			Nid     string "json:\"nid\""
			Address string "json:\"address\""
		}{
			Nid:     dstChainID,
			Address: dstAddress,
		},
	}
	return params, nil
}
