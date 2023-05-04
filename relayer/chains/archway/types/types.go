package types

import "encoding/hex"

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

type GetClientState struct {
	ClientState struct {
		ClientId string `json:"client_id"`
	} `json:"client_state"`
}

type GetConsensusState struct {
	ConsensusState struct {
		ClientId string `json:"client_id"`
		Height   uint64 `json:"height"`
	} `json:"consensus_state"`
}
