package cryptoutils

import (
	"encoding/hex"
	"testing"

	"github.com/cosmos/relayer/v2/relayer/chains/icon/types"
	"github.com/cosmos/relayer/v2/relayer/common"
	"github.com/icon-project/IBC-Integration/libraries/go/common/icon"
	"github.com/stretchr/testify/assert"
)

func TestMerkleRoot(t *testing.T) {
	// Test case data
	data := HashedList{
		common.Sha3keccak256([]byte("hello")),
		common.Sha3keccak256([]byte("world")),
		common.Sha3keccak256([]byte("testtt")),
	}
	expectedRoot := "f071961cfd9021ffb0ee8c7b7462bed91140d643b4c39e44f6ced91b0bd1e0fc"

	// Create Merkle tree
	tree := &MerkleHashTree{
		Hashes: data,
	}

	root := tree.MerkleRoot()
	assert.Equal(t, hex.EncodeToString(root), expectedRoot)
}

func TestMerkleProof(t *testing.T) {

	assert := assert.New(t)
	var h = func(b byte) []byte {
		return common.Sha3keccak256([]byte{b})
	}
	testCase := []struct {
		exp  []*icon.MerkleNode
		data [][]byte
		idx  int
	}{
		{
			[]*icon.MerkleNode{},
			[][]byte{h(0)},
			0,
		},
		{
			[]*icon.MerkleNode{{int32(types.DirRight), h(1)}},
			[][]byte{h(0), h(1)},
			0,
		},
		{
			[]*icon.MerkleNode{{int32(types.DirLeft), h(0)}},
			[][]byte{h(0), h(1)},
			1,
		},
		{
			[]*icon.MerkleNode{
				{int32(types.DirRight), h(1)},
				{int32(types.DirRight), h(2)},
			},
			[][]byte{h(0), h(1), h(2)},
			0,
		},
		{
			[]*icon.MerkleNode{
				{int32(types.DirLeft), h(0)},
				{int32(types.DirRight), h(2)},
			},
			[][]byte{h(0), h(1), h(2)},
			1,
		},
		{
			[]*icon.MerkleNode{
				{int32(types.DirRight), nil},
				{int32(types.DirLeft), common.Sha3keccak256(h(0), h(1))},
			},
			[][]byte{h(0), h(1), h(2)},
			2,
		},
		{
			[]*icon.MerkleNode{
				{int32(types.DirRight), h(1)},
				{int32(types.DirRight), common.Sha3keccak256(h(2), h(3))},
				{int32(types.DirRight), h(4)},
			},
			[][]byte{h(0), h(1), h(2), h(3), h(4)},
			0,
		},
		{
			[]*icon.MerkleNode{
				{int32(types.DirRight), nil},
				{int32(types.DirRight), nil},
				{
					int32(types.DirLeft), common.Sha3keccak256(
						common.Sha3keccak256(h(0), h(1)),
						common.Sha3keccak256(h(2), h(3)),
					),
				},
			},
			[][]byte{h(0), h(1), h(2), h(3), h(4)},
			4,
		},
	}

	for i, c := range testCase {
		tree := MerkleHashTree{
			Hashes: c.data,
		}
		assert.EqualValues(c.exp, tree.MerkleProof(c.idx), "case=%d data=%x idx=%d", i, c.data, c.idx)
	}
}

func TestMerkleProofMisMatch(t *testing.T) {
	data := HashedList{
		common.Sha3keccak256([]byte("hello")),
		common.Sha3keccak256([]byte("world")),
		common.Sha3keccak256([]byte("test")),
	}

	failcase := common.Sha3keccak256([]byte("should_fail"))

	tree := &MerkleHashTree{
		Hashes: data,
	}
	root := tree.MerkleRoot()
	proofOfFirstItem := tree.MerkleProof(1)
	proof := make([]*icon.MerkleNode, 0)
	for _, p := range proofOfFirstItem {
		proof = append(proof, p)
	}

	assert.False(t, VerifyMerkleProof(root, failcase, proof))

}

func TestCalculateRootFromMerkleNode(t *testing.T) {
	data := HashedList{
		common.Sha3keccak256([]byte("hello")),
		common.Sha3keccak256([]byte("world")),
		common.Sha3keccak256([]byte("test")),
		common.Sha3keccak256([]byte("tes2")),
		common.Sha3keccak256([]byte("tes3")),
	}
	tree := &MerkleHashTree{
		Hashes: data,
	}

	expectedRoot := tree.MerkleRoot()
	for i, d := range data {
		assert.True(t, VerifyMerkleProof(expectedRoot, d, tree.MerkleProof(i)), "case=%d data=%x idx=%d", i, d)
	}
}
