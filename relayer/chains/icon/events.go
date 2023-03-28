package icon

import (
	"encoding/hex"

	clientType "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	connectionType "github.com/cosmos/ibc-go/v7/modules/core/03-connection/types"
	channelType "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
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
var iconEventNameToEventTypeMap = map[string]string{
	// packet Events
	EventTypeSendPacket:           chantypes.EventTypeSendPacket,
	EventTypeRecvPacket:           chantypes.EventTypeRecvPacket,
	EventTypeWriteAck:             chantypes.EventTypeWriteAck,
	EventTypeAcknowledgePacket:    chantypes.EventTypeAcknowledgePacket,
	EventTypeTimeoutPacket:        chantypes.EventTypeTimeoutPacket,
	EventTypeTimeoutPacketOnClose: chantypes.EventTypeTimeoutPacketOnClose,

	// channel events
	EventTypeChannelOpenInit:     chantypes.EventTypeChannelOpenInit,
	EventTypeChannelOpenTry:      chantypes.EventTypeChannelOpenTry,
	EventTypeChannelOpenAck:      chantypes.EventTypeChannelOpenAck,
	EventTypeChannelOpenConfirm:  chantypes.EventTypeChannelOpenConfirm,
	EventTypeChannelCloseInit:    chantypes.EventTypeChannelCloseInit,
	EventTypeChannelCloseConfirm: chantypes.EventTypeChannelCloseConfirm,
	EventTypeChannelClosed:       chantypes.EventTypeChannelClosed,

	// connection Events
	EventTypeConnectionOpenInit:    conntypes.EventTypeConnectionOpenInit,
	EventTypeConnectionOpenTry:     conntypes.EventTypeConnectionOpenTry,
	EventTypeConnectionOpenAck:     conntypes.EventTypeConnectionOpenAck,
	EventTypeConnectionOpenConfirm: conntypes.EventTypeConnectionOpenConfirm,

	// client Events
	EventTypeCreateClient:          clientTypes.EventTypeCreateClient,
	EventTypeUpdateClient:          clientTypes.EventTypeUpdateClient,
	EventTypeUpgradeClient:         clientTypes.EventTypeUpgradeClient,
	EventTypeSubmitMisbehaviour:    clientTypes.EventTypeSubmitMisbehaviour,
	EventTypeUpdateClientProposal:  clientTypes.EventTypeUpdateClientProposal,
	EventTypeUpgradeChain:          clientTypes.EventTypeUpgradeChain,
	EventTypeUpgradeClientProposal: clientTypes.EventTypeUpgradeClientProposal,
}

var IconCosmosEventMap = map[string]string{
	// client events
	EventTypeCreateClient: clientType.EventTypeCreateClient,
	EventTypeUpdateClient: clientType.EventTypeUpdateClient,

	// connection events
	EventTypeConnectionOpenInit:    connectionType.EventTypeConnectionOpenInit,
	EventTypeConnectionOpenTry:     connectionType.EventTypeConnectionOpenTry,
	EventTypeConnectionOpenAck:     connectionType.EventTypeConnectionOpenAck,
	EventTypeConnectionOpenConfirm: connectionType.EventTypeConnectionOpenConfirm,

	// channel events
	EventTypeChannelOpenInit:     channelType.EventTypeChannelOpenInit,
	EventTypeChannelOpenTry:      channelType.EventTypeChannelOpenTry,
	EventTypeChannelOpenAck:      channelType.EventTypeChannelOpenAck,
	EventTypeChannelOpenConfirm:  channelType.EventTypeChannelOpenConfirm,
	EventTypeChannelCloseInit:    channelType.EventTypeChannelCloseInit,
	EventTypeChannelCloseConfirm: channelType.EventTypeChannelCloseConfirm,

	// packet events
	EventTypeSendPacket:           channelType.EventTypeSendPacket,
	EventTypeRecvPacket:           channelType.EventTypeRecvPacket,
	EventTypeWriteAcknowledgement: channelType.EventTypeWriteAck,
	EventTypeAcknowledgePacket:    channelType.EventTypeAcknowledgePacket,
	EventTypePacketTimeout:        channelType.EventTypeTimeoutPacket,
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
