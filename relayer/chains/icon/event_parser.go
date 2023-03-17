package icon

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"cosmossdk.io/errors"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/icon-project/goloop/common/codec"

	"go.uber.org/zap"
)

// func (ip *IconProvider) FetchEvent(height int) {

// 	blockReq := &types.BlockRequest{
// 		EventFilters: []*types.EventFilter{{
// 			Addr:      types.Address(CONTRACT_ADDRESS),
// 			Signature: SEND_PACKET_SIGNATURE,
// 			// Indexed:   []*string{&dstAddr},
// 		}},
// 		Height: types.NewHexInt(int64(height)),
// 	}
// 	ctx := context.Background()
// 	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
// 	defer cancel()

// 	l := zap.Logger{}

// 	client := NewClient(WSS_ENDPOINT, &l)
// 	h, s := height, 0

// 	go func() {
// 		err := client.MonitorBlock(ctx, blockReq, func(conn *websocket.Conn, v *types.BlockNotification) error {
// 			_h, _ := v.Height.Int()
// 			if _h != h {
// 				err := fmt.Errorf("invalid block height: %d, expected: %d", _h, h+1)
// 				l.Warn(err.Error())
// 				return err
// 			}
// 			h++
// 			s++
// 			return nil
// 		},
// 			func(conn *websocket.Conn) {
// 				l.Info("Connected")
// 			},
// 			func(conn *websocket.Conn, err error) {
// 				l.Info("Disconnected")
// 				_ = conn.Close()
// 			})
// 		if err.Error() == "context deadline exceeded" {
// 			return
// 		}
// 	}()

// }

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
	pi.Sequence = packet.Sequence.Uint64()
	pi.Data = packet.Data
	pi.TimeoutHeight.RevisionHeight = packet.TimeoutHeight.RevisionHeight.Uint64()
	pi.TimeoutHeight.RevisionNumber = packet.TimeoutHeight.RevisionNumber.Uint64()
	pi.TimeoutTimestamp = packet.Timestamp.Uint64()

	if bytes.Equal(eventType, MustConvertEventNameToBytes(EventTypeAcknowledgePacket)) {
		pi.Ack = []byte(event.Indexed[2])
	}
}

type channelInfo provider.ChannelInfo

func (ch *channelInfo) parseAttrs(log *zap.Logger, event types.EventLog) {

	// the required data are not in Indexed. Placeholders for now

	portId := event.Indexed[1]
	channelId := event.Indexed[2]
	counterpartyPortId := event.Indexed[3]
	counterpartyChannelId := event.Indexed[4]
	version := event.Indexed[6]

	ch.PortID = string(portId[:])
	ch.ChannelID = string(channelId[:])
	ch.CounterpartyPortID = string(counterpartyPortId[:])
	ch.CounterpartyChannelID = string(counterpartyChannelId[:])
	ch.Version = string(version[:])
}

type connectionInfo provider.ConnectionInfo

func (co *connectionInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	connectionId, clientId := event.Indexed[1], event.Indexed[2]
	counterpartyConnectionId, counterpartyClientId := event.Indexed[3], event.Indexed[4]

	co.ConnID = string(connectionId[:])
	co.ClientID = string(clientId[:])
	co.CounterpartyConnID = string(counterpartyConnectionId[:])
	co.CounterpartyClientID = string(counterpartyClientId[:])
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
	}
}

// eventType_signature  ,rlpPacket
func (cl *clientInfo) parseAttrs(log *zap.Logger, event types.EventLog) {
	clientId := event.Indexed[1]
	height := string(event.Indexed[3][:])

	revisionSplit := strings.Split(height, "-")
	if len(revisionSplit) != 2 {
		log.Error("Error parsing client consensus height",
			zap.String("client_id", cl.clientID),
			zap.String("value", height),
		)
		return
	}
	revisionNumberString := revisionSplit[0]
	revisionNumber, err := strconv.ParseUint(revisionNumberString, 10, 64)
	if err != nil {
		log.Error("Error parsing client consensus height revision number",
			zap.Error(err),
		)
		return
	}
	revisionHeightString := revisionSplit[1]
	revisionHeight, err := strconv.ParseUint(revisionHeightString, 10, 64)
	if err != nil {
		log.Error("Error parsing client consensus height revision height",
			zap.Error(err),
		)
		return
	}

	cl.consensusHeight = clienttypes.Height{
		RevisionHeight: revisionHeight,
		RevisionNumber: revisionNumber,
	}
	cl.clientID = string(clientId[:])
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
	return indexed[0]
}

func _parsePacket(str []byte) (*types.Packet, error) {
	p := types.Packet{}
	e := rlpDecodeHex(str, &p)
	if e != nil {
		return nil, e
	}
	fmt.Printf("packetData decoded: %v \n", p)
	return &p, nil
}

func rlpDecodeHex(input []byte, out interface{}) error {
	// str = strings.TrimPrefix(str, "0x")
	// input, err := hex.DecodeString(str)
	// if err != nil {
	// 	return errors.Wrap(err, "hex.DecodeString ")
	// }
	_, err := codec.RLP.UnmarshalFromBytes(input, out)
	if err != nil {
		return errors.Wrap(err, "rlp.Decode ")
	}
	return nil
}
