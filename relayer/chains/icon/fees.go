package icon

import (
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/provider"
)

type MsgClaimFees struct {
	Nid     string         `json:"nid"`
	Address types.HexBytes `json:"address"`
}

func (icp *IconProvider) MsgClaimFees(dstChainID, dstAddress string) (provider.RelayerMessage, error) {

	params := MsgClaimFees{
		Nid:     dstChainID,
		Address: types.NewHexBytes([]byte(dstAddress)),
	}

	msg := icp.NewIconMessage(params, MethodClaimFees)

	return msg, nil
}
