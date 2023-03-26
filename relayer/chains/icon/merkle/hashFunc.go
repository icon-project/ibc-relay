package merkle

import "golang.org/x/crypto/sha3"

func appendKeccak256(out []byte, data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(out)
}

func Sha3keccak256(data ...[]byte) []byte {
	return appendKeccak256(nil, data...)
}
