package icon

import (
	"encoding/hex"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
)

// Events
var (
	// Client Events
	EventTypeCreateClient = "CreateClient(str,bytes)"
	EventTypeUpdateClient = "UpdateClient(str)"

	// Connection Events
	EventTypeConnectionOpenInit    = "ConnectionOpenInit(str)"
	EventTypeConnectionOpenTry     = "ConnectionOpenTry(str)"
	EventTypeConnectionOpenAck     = "ConnectionOpenAck(str)"
	EventTypeConnectionOpenConfirm = "ConnectionOpenConfirm(str)"

	// Channel Events
	EventTypeChannelOpenInit     = "ChannelOpenInit(str)"
	EventTypeChannelOpenTry      = "ChannelOpenTry(str)"
	EventTypeChannelOpenAck      = "ChannelOpenAck(str)"
	EventTypeChannelOpenConfirm  = "ChannelOpenConfirm(str)"
	EventTypeChannelCloseInit    = "ChannelCloseInit(str)"
	EventTypeChannelCloseConfirm = "ChannelCloseConfirm(str)"

	// Packet Events
	EventTypeSendPacket           = "SendPacket()"
	EventTypeRecvPacket           = "RecvPacket()"
	EventTypeWriteAcknowledgement = "WriteAcknowledgement()"
	EventTypeAcknowledgePacket    = "AcknowledgePacket()"
	EventTypeTimeoutRequest       = "TimeoutRequest()"
	EventTypePacketTimeout        = "PacketTimeout()"
)

// var iconEventNameToEventTypeMap = map[string]string{
// 	// packet Events
// 	EventTypeSendPacket:           chantypes.EventTypeSendPacket,
// 	EventTypeRecvPacket:           chantypes.EventTypeRecvPacket,
// 	EventTypeWriteAck:             chantypes.EventTypeWriteAck,
// 	EventTypeAcknowledgePacket:    chantypes.EventTypeAcknowledgePacket,
// 	EventTypeTimeoutPacket:        chantypes.EventTypeTimeoutPacket,
// 	EventTypeTimeoutPacketOnClose: chantypes.EventTypeTimeoutPacketOnClose,

// 	// channel events
// 	EventTypeChannelOpenInit:     chantypes.EventTypeChannelOpenInit,
// 	EventTypeChannelOpenTry:      chantypes.EventTypeChannelOpenTry,
// 	EventTypeChannelOpenAck:      chantypes.EventTypeChannelOpenAck,
// 	EventTypeChannelOpenConfirm:  chantypes.EventTypeChannelOpenConfirm,
// 	EventTypeChannelCloseInit:    chantypes.EventTypeChannelCloseInit,
// 	EventTypeChannelCloseConfirm: chantypes.EventTypeChannelCloseConfirm,
// 	EventTypeChannelClosed:       chantypes.EventTypeChannelClosed,

// 	// connection Events
// 	EventTypeConnectionOpenInit:    conntypes.EventTypeConnectionOpenInit,
// 	EventTypeConnectionOpenTry:     conntypes.EventTypeConnectionOpenTry,
// 	EventTypeConnectionOpenAck:     conntypes.EventTypeConnectionOpenAck,
// 	EventTypeConnectionOpenConfirm: conntypes.EventTypeConnectionOpenConfirm,

// 	// client Events
// 	EventTypeCreateClient:          clienttypes.EventTypeCreateClient,
// 	EventTypeUpdateClient:          clienttypes.EventTypeUpdateClient,
// 	EventTypeUpgradeClient:         clienttypes.EventTypeUpgradeClient,
// 	EventTypeSubmitMisbehaviour:    clienttypes.EventTypeSubmitMisbehaviour,
// 	EventTypeUpdateClientProposal:  clienttypes.EventTypeUpdateClientProposal,
// 	EventTypeUpgradeChain:          clienttypes.EventTypeUpgradeChain,
// 	EventTypeUpgradeClientProposal: clienttypes.EventTypeUpgradeClientProposal,
// }

var IconCosmosEventMap = map[string]string{
	// client events
	EventTypeCreateClient: clienttypes.EventTypeCreateClient,
	EventTypeUpdateClient: clienttypes.EventTypeUpdateClient,

	// connection events
	EventTypeConnectionOpenInit:    conntypes.EventTypeConnectionOpenInit,
	EventTypeConnectionOpenTry:     conntypes.EventTypeConnectionOpenTry,
	EventTypeConnectionOpenAck:     conntypes.EventTypeConnectionOpenAck,
	EventTypeConnectionOpenConfirm: conntypes.EventTypeConnectionOpenConfirm,

	// channel events
	EventTypeChannelOpenInit:     chantypes.EventTypeChannelOpenInit,
	EventTypeChannelOpenTry:      chantypes.EventTypeChannelOpenTry,
	EventTypeChannelOpenAck:      chantypes.EventTypeChannelOpenAck,
	EventTypeChannelOpenConfirm:  chantypes.EventTypeChannelOpenConfirm,
	EventTypeChannelCloseInit:    chantypes.EventTypeChannelCloseInit,
	EventTypeChannelCloseConfirm: chantypes.EventTypeChannelCloseConfirm,

	// packet events
	EventTypeSendPacket:           chantypes.EventTypeSendPacket,
	EventTypeRecvPacket:           chantypes.EventTypeRecvPacket,
	EventTypeWriteAcknowledgement: chantypes.EventTypeWriteAck,
	EventTypeAcknowledgePacket:    chantypes.EventTypeAcknowledgePacket,
	EventTypePacketTimeout:        chantypes.EventTypeTimeoutPacket,
}

func MustConvertEventNameToBytes(eventName string) []byte {
	input, err := hex.DecodeString(eventName)
	if err != nil {
		return nil
	}
	return input
}

func ToEventLogBytes(evt types.EventLogStr) types.EventLog {
	indexed := make([][]byte, 0)

	for _, idx := range evt.Indexed {
		indexed = append(indexed, []byte(idx))
	}

	data := make([][]byte, 0)

	for _, d := range evt.Indexed {
		indexed = append(indexed, []byte(d))
	}

	return types.EventLog{
		Addr:    evt.Addr,
		Indexed: indexed,
		Data:    data,
	}

}

func GetMonitorEventFilters(address string) []*types.EventFilter {

	filters := []*types.EventFilter{}
	if address == "" {
		return filters
	}

	eventArr := []string{
		EventTypeSendPacket,
		// EventTypeRecvPacket,
		// EventTypeWriteAck,
		// EventTypeAcknowledgePacket,
	}

	for _, event := range eventArr {
		filters = append(filters, &types.EventFilter{
			Addr:      types.Address(address),
			Signature: event,
		})
	}
	return filters
}
