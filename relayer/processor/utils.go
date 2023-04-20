package processor

import (
	"strings"

	"github.com/cosmos/relayer/v2/relayer/provider"
)

func IfClientIsIcon(cs provider.ClientState) bool {
	if strings.Contains("icon", cs.ClientID) {
		return true
	}
	return false
}
