package processor

import (
	"math"
	"strings"

	"github.com/cosmos/relayer/v2/relayer/provider"
)

func clientIsIcon(cs provider.ClientState) bool {
	if strings.Contains("icon", cs.ClientID) {
		return true
	}
	return false
}

func findNextGreaterHeight(headercache IBCHeaderCache, prevHeight uint64) (uint64, bool) {
	minDiff := uint64(math.MaxUint64)
	var nextGreaterHeight uint64
	found := false

	for key := range headercache {
		if key > prevHeight && key-prevHeight < minDiff {
			minDiff = key - prevHeight
			nextGreaterHeight = key
			found = true
		}
	}

	if found {
		return nextGreaterHeight, true
	}
	return 0, false
}

func nextIconIBCHeader(heightMap IBCHeaderCache, height uint64) (provider.IBCHeader, bool) {
	var nextHeight uint64
	for h := range heightMap {
		if h > height {
			if nextHeight == 0 || h < nextHeight {
				nextHeight = h
			}
		}
	}
	if nextHeight == 0 {
		return nil, false
	}
	return heightMap[nextHeight], true
}
