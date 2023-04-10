package icon

import (
	"bytes"
	"encoding/hex"
	"strings"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types/icon"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/gogo/protobuf/proto"

	"go.uber.org/zap"
)

// EventType: EquivalentIBCEvent
// EventName: IconEventLogSignature
type ibcMessage struct {
	eventType string
	eventName string
	info      ibcMessageInfo
}

type ibcMessageInfo interface {
	parseAttrs(log *zap.Logger, event types.EventLog)
}

type packetInfo provider.PacketInfo

func (pi *packetInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	eventType := GetEventLogSignature(event.Indexed)
	packetData := event.Indexed[1]
	var packet icon.Packet
	if err := proto.Unmarshal(packetData, &packet); err != nil {
		log.Error("failed to unmarshal packet")
	}
	pi.SourcePort = packet.SourcePort
	pi.SourceChannel = packet.SourceChannel
	pi.DestPort = packet.DestinationPort
	pi.DestChannel = packet.DestinationChannel
	pi.Sequence = packet.Sequence
	pi.Data = packet.Data
	pi.TimeoutHeight.RevisionHeight = packet.TimeoutHeight.RevisionHeight
	pi.TimeoutHeight.RevisionNumber = packet.TimeoutHeight.RevisionNumber
	pi.TimeoutTimestamp = packet.TimeoutTimestamp

	if bytes.Equal(eventType, MustConvertEventNameToBytes(EventTypeAcknowledgePacket)) {
		pi.Ack = []byte(event.Indexed[2])
	}
}

type channelInfo provider.ChannelInfo

func (ch *channelInfo) parseAttrs(log *zap.Logger, event types.EventLog) {

	ch.PortID = filter(event.Indexed[1])
	ch.ChannelID = filter(event.Indexed[2])

	protoChannel := event.Data[0]
	var channel icon.Channel

	if err := proto.Unmarshal(protoChannel, &channel); err != nil {
		log.Error("Error decoding channel")
	}

	ch.CounterpartyChannelID = channel.Counterparty.GetChannelId()
	ch.CounterpartyPortID = channel.Counterparty.GetPortId()
	ch.ConnID = "" // get connection from eventlog
	ch.Version = channel.GetVersion()
}

type connectionInfo provider.ConnectionInfo

func (co *connectionInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	eventLog := parseEventName(log, event, 0)
	switch eventLog {
	case EventTypeConnectionOpenInit, EventTypeConnectionOpenTry:
		co.ClientID = filter(event.Indexed[1])
		co.ConnID = filter(event.Data[0])

		protoCounterparty_ := strings.TrimPrefix(string(event.Data[1]), "0x")
		protoCounterparty, _ := hex.DecodeString(protoCounterparty_)
		var counterparty icon.Counterparty

		if err := proto.Unmarshal(protoCounterparty, &counterparty); err != nil {
			log.Error("Error decoding counterparty")
		}

		co.CounterpartyClientID = counterparty.GetClientId()
		co.CounterpartyConnID = counterparty.GetConnectionId()

	case EventTypeConnectionOpenAck, EventTypeConnectionOpenConfirm:
		co.ConnID = filter(event.Indexed[0])

		protoConnection_ := strings.TrimPrefix(string(event.Data[0]), "0x")
		protoConnection, _ := hex.DecodeString(protoConnection_)

		var connection icon.ConnectionEnd
		if err := proto.Unmarshal(protoConnection, &connection); err != nil {
			log.Error("Error decoding connectionEnd")
		}

		co.ClientID = connection.GetClientId()
		co.CounterpartyClientID = connection.Counterparty.ClientId
		co.CounterpartyConnID = connection.Counterparty.ConnectionId
	}
}

type clientInfo struct {
	clientID        string
	consensusHeight clienttypes.Height
	header          []byte
}

func (c clientInfo) ClientState() provider.ClientState {
	return provider.ClientState{
		ClientID:        c.clientID,
		ConsensusHeight: c.consensusHeight,
		Header:          c.header,
	}
}

func (cl *clientInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	clientId := event.Indexed[1]
	cl.clientID = string(clientId[:])
}

func parseEventName(log *zap.Logger, event types.EventLog, height uint64) string {
	return string(event.Indexed[0][:])
}

func parseIdentifier(event types.EventLog) string {
	return string(event.Indexed[1][:])
}
func parseIBCMessageFromEvent(
	log *zap.Logger,
	event types.EventLog,
	height uint64,
) *ibcMessage {
	eventName := string(event.Indexed[0][:])
	eventType := getEventTypeFromEventName(eventName)

	switch eventName {
	case EventTypeSendPacket, EventTypeRecvPacket, EventTypeAcknowledgePacket:

		info := &packetInfo{Height: height}
		info.parseAttrs(log, event)
		return &ibcMessage{
			eventType,
			eventName,
			info,
		}
	case EventTypeChannelOpenInit, EventTypeChannelOpenTry,
		EventTypeChannelOpenAck, EventTypeConnectionOpenConfirm,
		EventTypeChannelCloseInit, EventTypeChannelCloseConfirm:

		ci := &channelInfo{Height: height}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			eventName: eventName,
			info:      ci,
		}
	case EventTypeConnectionOpenInit, EventTypeConnectionOpenTry,
		EventTypeConnectionOpenAck, EventTypeConnectionOpenConfirm:
		ci := &connectionInfo{Height: height}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			eventName: eventName,
			info:      ci,
		}
	case EventTypeCreateClient, EventTypeUpdateClient:

		ci := &clientInfo{}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			eventName: eventName,
			info:      ci,
		}

	}
	return nil
}

func getEventTypeFromEventName(eventName string) string {
	return IconCosmosEventMap[eventName]
}

func GetEventLogSignature(indexed [][]byte) []byte {
	return indexed[0][:]
}

func filter(x []byte) string {
	i, _ := hex.DecodeString(strings.TrimPrefix(string(x), "0x"))
	return string(i)
}
