package icon

import (
	"fmt"
	"testing"

	"github.com/cosmos/ibc-go/modules/core/exported"
)

func TestExportedClientState(t *testing.T) {
	var clS exported.ClientState
	fmt.Println(clS.ClientType())
}
