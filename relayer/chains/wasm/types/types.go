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

func GenerateQueryParams(methodName string, params interface{}) ([]byte, error) {
	queryObj := make(map[string]interface{}, 0)
	queryObj[methodName] = params
	return json.Marshal(queryObj)
}

type ClientState struct {
	ClientId string `json:"client_id"`
}

func NewClientState(ClientId string) ClientState {
	return ClientState{ClientId}
}

type ConsensusStateByHeight struct {
	ClientId string `json:"client_id"`
	Height   uint64 `json:"height"`
}

func NewConsensusStateByHeight(ClientId string, Height uint64) ConsensusStateByHeight {
	return ConsensusStateByHeight{ClientId, Height}
}

type Connection struct {
	ConnectionId string `json:"connection_id"`
}

func NewConnection(ConnectionId string) Connection {
	return Connection{ConnectionId}
}

type Capability struct {
	ChannelId string `json:"channel_id"`
	PortId    string `json:"port_id"`
}

func NewCapability(ChannelId, PortId string) Capability {
	return Capability{ChannelId, PortId}
}

type PacketIdentity struct {
	ChannelId string `json:"channel_id"`
	PortId    string `json:"port_id"`
	Sequence  uint64 `json:"sequence"`
}

func NewPacketIdentity(ChannelId, PortId string, Sequence uint64) PacketIdentity {
	return PacketIdentity{ChannelId, PortId, Sequence}
}

type RangeParams struct {
	ChannelId     string `json:"channel_id"`
	PortId        string `json:"port_id"`
	StartSequence uint64 `json:"start_sequence"`
	EndSequence   uint64 `json:"end_sequence"`
}

func NewRangeParams(ChannelId, PortId string, StartSequence, EndSequence uint64) RangeParams {
	return RangeParams{ChannelId, PortId, StartSequence, EndSequence}
}
