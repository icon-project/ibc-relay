package icon

import (
	"bytes"

	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"google.golang.org/protobuf/proto"

	"go.uber.org/zap"
)

type ibcMessage struct {
	eventType string
	info      ibcMessageInfo
}

type ibcMessageInfo interface {
	parseAttrs(log *zap.Logger, event types.EventLog)
}

type packetInfo provider.PacketInfo

func (pi *packetInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	eventType := GetEventLogSignature(event.Indexed)
	packetData := event.Indexed[1]
	packet, err := _parsePacket(packetData)
	if err != nil {
		log.Error("Error parsing packet", zap.ByteString("value", packetData))
		return
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

	// the required data are not in Indexed. Placeholders for now

	ch.PortID = string(event.Indexed[1][:])
	ch.ChannelID = string(event.Indexed[2][:])

	protoChannel := event.Data[0]
	var channel types.Channel

	if err := proto.Unmarshal(protoChannel, &channel); err != nil {
		panic("")
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
		co.ClientID = string(event.Indexed[1])
		co.ConnID = string(event.Data[0])
		protoCounterparty := event.Data[1]

		var counterparty types.Counterparty
		if err := proto.Unmarshal(protoCounterparty, &counterparty); err != nil {
			panic("Fail to unmarshal")
		}
		co.CounterpartyClientID = counterparty.GetClientId()
		co.CounterpartyConnID = counterparty.GetConnectionId()

	case EventTypeConnectionOpenAck, EventTypeConnectionOpenConfirm:
		co.ConnID = string(event.Indexed[0])
		protoConnection := event.Data[0]
		var connection types.ConnectionEnd
		if err := proto.Unmarshal(protoConnection, &connection); err != nil {
			panic("Fail to unmarshal")
		}
		co.ClientID = connection.GetClientId()
		co.CounterpartyClientID = connection.Counterparty.ClientId
		co.CounterpartyConnID = connection.Counterparty.ConnectionId
	}
}

type clientInfo struct {
	clientID string
}

func (c clientInfo) ClientState() provider.ClientState {
	return provider.ClientState{
		ClientID: c.clientID,
	}
}

// eventType_signature  ,rlpPacket
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
	eventType := string(event.Indexed[0][:])

	switch eventType {
	case EventTypeSendPacket, EventTypeRecvPacket, EventTypeAcknowledgePacket:

		pi := &packetInfo{Height: height}
		pi.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			info:      pi,
		}
	case EventTypeChannelOpenInit, EventTypeChannelOpenTry,
		EventTypeChannelOpenAck, EventTypeConnectionOpenConfirm,
		EventTypeChannelCloseInit, EventTypeChannelCloseConfirm:

		ci := &channelInfo{Height: height}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			info:      ci,
		}
	case EventTypeConnectionOpenInit, EventTypeConnectionOpenTry,
		EventTypeConnectionOpenAck, EventTypeConnectionOpenConfirm:

		ci := &connectionInfo{Height: height}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			info:      ci,
		}
	case EventTypeCreateClient, EventTypeUpdateClient:

		ci := &clientInfo{}
		ci.parseAttrs(log, event)

		return &ibcMessage{
			eventType: eventType,
			info:      ci,
		}

	}
	return nil
}

func GetEventLogSignature(indexed [][]byte) []byte {
	return indexed[0][:]
}

func _parsePacket(pkt []byte) (*types.Packet, error) {
	var p types.Packet
	if err := proto.Unmarshal(pkt, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
