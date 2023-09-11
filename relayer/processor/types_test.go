package processor_test

import (
	"testing"

	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"
	"github.com/cosmos/relayer/v2/relayer/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockIBCHeader struct{}

func (h mockIBCHeader) Height() uint64                             { return 0 }
func (h mockIBCHeader) ConsensusState() ibcexported.ConsensusState { return nil }
func (h mockIBCHeader) NextValidatorsHash() []byte                 { return nil }
func (h mockIBCHeader) IsCompleteBlock() bool                      { return true }
func (h mockIBCHeader) ShouldUpdateWithZeroMessage() bool          { return false }

func TestIBCHeaderCachePrune(t *testing.T) {
	cache := make(processor.IBCHeaderCache)

	intermediaryCache1 := make(processor.IBCHeaderCache)
	for i := uint64(0); i < 10; i++ {
		intermediaryCache1[i] = mockIBCHeader{}
	}

	intermediaryCache2 := make(processor.IBCHeaderCache)
	for i := uint64(10); i < 20; i++ {
		intermediaryCache2[i] = mockIBCHeader{}
	}

	cache.Merge(intermediaryCache1)
	require.Len(t, cache, 10)

	// test pruning with keep greater than length
	cache.Prune(15)
	require.Len(t, cache, 10)

	cache.Merge(intermediaryCache2)
	require.Len(t, cache, 20)

	cache.Prune(5)
	require.Len(t, cache, 5)
	require.NotNil(t, cache[uint64(15)], cache[uint64(16)], cache[uint64(17)], cache[uint64(18)], cache[uint64(19)])
}

func TestBtpQueue(t *testing.T) {

	q := processor.NewBtpHeightMapQueue()

	q.Enqueue(20)
	q.Enqueue(30)
	q.Enqueue(40)

	assert.Equal(t, q.Size(), 3)

	q.Dequeue()
	assert.Equal(t, q.Size(), 2)

	// testing getQueue
	h := uint64(40)
	hInfo, err := q.GetHeightInfo(h)
	assert.NoError(t, err)
	assert.Equal(t, processor.BlockInfoHeight{IsProcessing: false, RetryCount: 0}, hInfo)

	replace := processor.BlockInfoHeight{IsProcessing: true, RetryCount: 2}
	q.ReplaceQueue(h, replace)
	hInfo, err = q.GetHeightInfo(h)
	assert.NoError(t, err)
	assert.Equal(t, replace, hInfo)

}
