package icon

import (
	"encoding/hex"
	"fmt"

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
	EventTypeConnectionOpenInit    = "ConnectionOpenInit(str,str,bytes)"
	EventTypeConnectionOpenTry     = "ConnectionOpenTry(str,str,bytes)"
	EventTypeConnectionOpenAck     = "ConnectionOpenAck(str,bytes)"
	EventTypeConnectionOpenConfirm = "ConnectionOpenConfirm(str,bytes)"

	// Channel Events
	EventTypeChannelOpenInit     = "ChannelOpenInit(str,str,bytes)"
	EventTypeChannelOpenTry      = "ChannelOpenTry(str,str,bytes)"
	EventTypeChannelOpenAck      = "ChannelOpenAck(str,str,bytes)"
	EventTypeChannelOpenConfirm  = "ChannelOpenConfirm(str,str,bytes)"
	EventTypeChannelCloseInit    = "ChannelCloseInit(str,str,bytes)"
	EventTypeChannelCloseConfirm = "ChannelCloseConfirm(str,str,bytes)"

	// Packet Events
	EventTypeSendPacket           = "SendPacket(bytes)"
	EventTypeRecvPacket           = "RecvPacket(bytes)"
	EventTypeWriteAcknowledgement = "WriteAcknowledgement(str,str,int,bytes)"
	EventTypeAcknowledgePacket    = "AcknowledgePacket(bytes,bytes)"
	EventTypeTimeoutRequest       = "TimeoutRequest(bytes)"
	EventTypePacketTimeout        = "PacketTimeout(bytes)"
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

	for _, d := range evt.Data {
		data = append(data, []byte(d))
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

	fmt.Println("checkkkkkkkkk", address)

	eventArr := []string{
		EventTypeSendPacket,
		EventTypeAcknowledgePacket,
		EventTypeConnectionOpenInit,
		EventTypeConnectionOpenTry,
		EventTypeConnectionOpenAck,
		EventTypeConnectionOpenConfirm,
	}

	for _, event := range eventArr {
		filters = append(filters, &types.EventFilter{
			Addr:      types.Address(address),
			Signature: event,
		})
	}
	return filters
}
