package merkle

import (
	"encoding/hex"
	"testing"
)

func TestMerkleRoot(t *testing.T) {
	// Test case data
	data := HashedList{
		Sha3keccak256([]byte("hello")),
		Sha3keccak256([]byte("world")),
		Sha3keccak256([]byte("test")),
	}
	expectedRoot := "f071961cfd9021ffb0ee8c7b7462bed91140d643b4c39e44f6ced91b0bd1e0fc"

	// Create Merkle tree
	tree := &MerkleHashTree{
		hashes: data,
	}

	// Calculate Merkle root
	root := tree.MerkleRoot()

	// Compare calculated root with expected root
	if hex.EncodeToString(root) != expectedRoot {
		t.Errorf("Merkle root mismatch. Got %s, expected %s", hex.EncodeToString(root), expectedRoot)
	}
}

func TestMerkleProof(t *testing.T) {
	data := HashedList{
		Sha3keccak256([]byte("hello")),
		Sha3keccak256([]byte("world")),
		Sha3keccak256([]byte("test")),
	}

	tree := &MerkleHashTree{
		hashes: data,
	}
	root := tree.MerkleRoot()
	proofOfFirstItem := tree.MerkleProof(1)

	if !tree.VerifyMerkleProof(root, data[1], proofOfFirstItem) {
		t.Errorf("Merkle proof is not correct")
	}

}

func TestMerkleProofMisMatch(t *testing.T) {
	data := HashedList{
		Sha3keccak256([]byte("hello")),
		Sha3keccak256([]byte("world")),
		Sha3keccak256([]byte("test")),
	}

	failcase := Sha3keccak256([]byte("should_fail"))

	tree := &MerkleHashTree{
		hashes: data,
	}
	root := tree.MerkleRoot()
	proofOfFirstItem := tree.MerkleProof(1)

	if tree.VerifyMerkleProof(root, failcase, proofOfFirstItem) {
		t.Errorf("Merkle proof of data %x should not match data_list", failcase)
	}

}
