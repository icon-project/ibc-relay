package common

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
)

func MustHexStrToBytes(hex_string string) []byte {
	enc, _ := hex.DecodeString(strings.TrimPrefix(hex_string, "0x"))
	return enc
}

// Ensures ~/.relayer/chain_name exists and returns that if no error
func getSnapshotPath(chain_name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("Failed to get home directory")
	}
	snapshot := path.Join(home, ".relayer", chain_name)
	if _, err := os.Stat(snapshot); err != nil {
		if err := os.MkdirAll(snapshot, os.ModePerm); err != nil {
			return "", err
		}
	}
	return snapshot, nil
}

func SnapshotHeight(chain_id string, height int64) error {
	snapshot, err := getSnapshotPath(chain_id)
	if err != nil {
		return fmt.Errorf("Failed to find snapshot path, %w", err)
	}
	f, err := os.Create(fmt.Sprintf("%s/latest_height", snapshot))
	defer f.Close()
	if err != nil {
		return fmt.Errorf("Failed to create file: %w", err)
	}
	_, err = f.WriteString(fmt.Sprintf("%d", height))
	if err != nil {
		return fmt.Errorf("Failed to write to file: %w", err)
	}
	return nil
}

func LoadSnapshotHeight(chain_id string) (int64, error) {
	snapshot, err := getSnapshotPath(chain_id)
	if err != nil {
		return -1, fmt.Errorf("Failed to find snapshot path, %w", err)
	}
	fileName := fmt.Sprintf("%s/latest_height", snapshot)
	content, err := os.ReadFile(fileName)
	if err != nil {
		return -1, fmt.Errorf("Failed reading file, %w", err)
	}
	return strconv.ParseInt(strings.TrimSuffix(string(content), "\n"), 10, 64)
}

func NewHeightWithRevisionOne(height uint64) clienttypes.Height {
	return clienttypes.NewHeight(1, height)
}

func ChangeProof(proof []byte, shouldNeverBeEmpty bool) []byte {
	if proof == nil && shouldNeverBeEmpty {
		return EmptyProofConst
	}
	return proof
}
