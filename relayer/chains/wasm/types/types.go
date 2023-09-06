package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type HexBytes string

func (hs HexBytes) Value() ([]byte, error) {
	if hs == "" {
		return nil, nil
	}
	return hex.DecodeString(string(hs[2:]))
}

func NewHexBytes(b []byte) HexBytes {
	return HexBytes("0x" + hex.EncodeToString(b))
}

type ContractCall struct {
	Msg HexBytes `json:"msg"`
}

type CreateClientMsg struct {
	CreateClient ContractCall `json:"create_client"`
}

func (c *CreateClientMsg) Bytes() ([]byte, error) {
	return json.Marshal(c)
}

func GenerateTxnParams(methodName string, value HexBytes) ([]byte, error) {
	if len(methodName) <= 0 {
		return nil, fmt.Errorf("Empty Method Name")
	}
	if len(value) <= 0 {
		return nil, fmt.Errorf("Empty value for %s", methodName)
	}
	m := map[string]interface{}{
		methodName: map[string]HexBytes{
			"msg": value,
		},
	}
	return json.Marshal(m)
}

type ClientState struct {
	ClientId string `json:"client_id"`
}

// / READONLY METHODS
type GetClientState struct {
	ClientState `json:"get_client_state"`
}

func (x *GetClientState) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewClientState(ClientId string) *GetClientState {
	return &GetClientState{
		ClientState{ClientId},
	}
}

type ConsensusStateByHeight struct {
	ClientId string `json:"client_id"`
	Height   uint64 `json:"height"`
}

type GetConsensusStateByHeight struct {
	ConsensusStateByHeight ConsensusStateByHeight `json:"get_consensus_state_by_height"`
}

func (x *GetConsensusStateByHeight) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewConsensusStateByHeight(clientId string, height uint64) *GetConsensusStateByHeight {
	return &GetConsensusStateByHeight{
		ConsensusStateByHeight: ConsensusStateByHeight{
			ClientId: clientId,
			Height:   height,
		},
	}
}

type Connection struct {
	ConnectionId string `json:"connection_id"`
}

type GetConnection struct {
	Connection `json:"get_connection"`
}

func (x *GetConnection) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewConnection(connId string) *GetConnection {
	return &GetConnection{
		Connection: Connection{
			ConnectionId: connId,
		},
	}
}

type Capability struct {
	PortId    string `json:"port_id"`
	ChannelId string `json:"channel_id"`
}

type PacketIdentity struct {
	PortId    string `json:"port_id"`
	ChannelId string `json:"channel_id"`
	Sequence  uint64 `json:"sequence"`
}

type GetChannel struct {
	Channel Capability `json:"get_channel"`
}

func (x *GetChannel) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewChannel(PortId, ChannelId string) *GetChannel {
	return &GetChannel{
		Channel: Capability{PortId, ChannelId},
	}
}

type GetPacketCommitment struct {
	PacketCommitment PacketIdentity `json:"get_packet_commitment"`
}

func (x *GetPacketCommitment) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewPacketCommitment(PortId, ChannelId string, Sequence uint64) *GetPacketCommitment {
	return &GetPacketCommitment{
		PacketCommitment: PacketIdentity{PortId, ChannelId, Sequence},
	}
}

type GetPacketAcknowledgementCommitment struct {
	PacketCommitment PacketIdentity `json:"get_packet_acknowledgement_commitment"`
}

func (x *GetPacketAcknowledgementCommitment) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewPacketAcknowledgementCommitment(PortId, ChannelId string, Sequence uint64) *GetPacketAcknowledgementCommitment {
	return &GetPacketAcknowledgementCommitment{
		PacketCommitment: PacketIdentity{PortId, ChannelId, Sequence},
	}
}

type GetNextSequenceSend struct {
	NextSequenceSend Capability `json:"get_next_sequence_send"`
}

func (x *GetNextSequenceSend) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextSequenceSend(PortId, ChannelId string) *GetNextSequenceSend {
	return &GetNextSequenceSend{
		NextSequenceSend: Capability{PortId, ChannelId},
	}
}

type GetNextSequenceReceive struct {
	NextSequenceReceive Capability `json:"get_next_sequence_receive"`
}

func (x *GetNextSequenceReceive) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextSequenceReceive(PortId, ChannelId string) *GetNextSequenceReceive {
	return &GetNextSequenceReceive{
		NextSequenceReceive: Capability{PortId, ChannelId},
	}
}

type GetNextSequenceAcknowledgement struct {
	NextSequenceAck Capability `json:"get_next_sequence_acknowledgement"`
}

func (x *GetNextSequenceAcknowledgement) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextSequenceAcknowledgement(PortId, ChannelId string) *GetNextSequenceAcknowledgement {
	return &GetNextSequenceAcknowledgement{
		NextSequenceAck: Capability{PortId, ChannelId},
	}
}

type GetPacketReceipt struct {
	PacketReceipt PacketIdentity `json:"get_packet_receipt"`
}

func (x *GetPacketReceipt) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewPacketReceipt(PortId, ChannelId string, Sequence uint64) *GetPacketReceipt {
	return &GetPacketReceipt{
		PacketReceipt: PacketIdentity{PortId, ChannelId, Sequence},
	}
}

type GetNextClientSequence struct {
	Sequence struct{} `json:"get_next_client_sequence"`
}

func (x *GetNextClientSequence) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextClientSequence() *GetNextClientSequence {
	return &GetNextClientSequence{
		Sequence: struct{}{},
	}
}

type GetNextConnectionSequence struct {
	Sequence struct{} `json:"get_next_connection_sequence"`
}

func (x *GetNextConnectionSequence) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextConnectionSequence() *GetNextConnectionSequence {
	return &GetNextConnectionSequence{
		Sequence: struct{}{},
	}
}

type GetNextChannelSequence struct {
	Sequence struct{} `json:"get_next_channel_sequence"`
}

func (x *GetNextChannelSequence) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewNextChannelSequence() *GetNextChannelSequence {
	return &GetNextChannelSequence{
		Sequence: struct{}{},
	}
}

type GetAllPorts struct {
	AllPorts struct{} `json:"get_all_ports"`
}

func (x *GetAllPorts) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewGetAllPorts() *GetAllPorts {
	return &GetAllPorts{
		AllPorts: struct{}{},
	}
}

type GetCommitmentPrefix struct {
	GetCommitment struct{} `json:"get_commitment_prefix"`
}

func (x *GetCommitmentPrefix) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewCommitmentPrefix() *GetCommitmentPrefix {
	return &GetCommitmentPrefix{
		GetCommitment: struct{}{},
	}
}

type GetPrevConsensusStateHeight struct {
	ConsensusStateByHeight ConsensusStateByHeight `json:"get_previous_consensus_state_height"`
}

func (x *GetPrevConsensusStateHeight) Bytes() ([]byte, error) {
	return json.Marshal(x)
}

func NewPrevConsensusStateHeight(clientId string, height uint64) *GetPrevConsensusStateHeight {
	return &GetPrevConsensusStateHeight{
		ConsensusStateByHeight: ConsensusStateByHeight{
			ClientId: clientId,
			Height:   height,
		},
	}
}

type RangeParams struct {
	ChannelId     string `json:"channel_id"`
	PortId        string `json:"port_id"`
	StartSequence uint64 `json:"start_sequence"`
	EndSequence   uint64 `json:"end_sequence"`
}

func NewRangeParams(channelId, portId string, startSequence, endSequence uint64) RangeParams {
	return RangeParams{
		ChannelId:     channelId,
		PortId:        portId,
		StartSequence: startSequence,
		EndSequence:   endSequence,
	}
}

type PacketMissingReceiptsParams struct {
	GetMissingPacketReceipts RangeParams `json:"get_missing_packet_receipts"`
}

func NewPacketMissingReceiptParams(channelId, portId string, startSequence, endSequence uint64) PacketMissingReceiptsParams {
	return PacketMissingReceiptsParams{
		GetMissingPacketReceipts: NewRangeParams(channelId, portId, startSequence, endSequence),
	}
}

type PacketHeightsParams struct {
	GetPacketHeights RangeParams `json:"get_packet_heights"`
}

func NewPacketHeightParams(channelId, portId string, startSequence, endSequence uint64) PacketHeightsParams {
	return PacketHeightsParams{
		GetPacketHeights: NewRangeParams(channelId, portId, startSequence, endSequence),
	}
}
