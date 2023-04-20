package archway

import commitmenttypes "github.com/cosmos/ibc-go/v7/modules/core/23-commitment/types"

// Default IBC settings
var (
	defaultChainPrefix = commitmenttypes.NewMerklePrefix([]byte("ibc"))
	defaultDelayPeriod = uint64(0)
)
