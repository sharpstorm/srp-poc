package srp

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"regexp"
)

var trimRE = regexp.MustCompile(`\s+|\r+\n+`)

func Hex2BigInt(input string) (*big.Int, error) {
	temp, err := hex.DecodeString(trimRE.ReplaceAllLiteralString(input, ""))
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(temp), nil
}

func MustHex2BigInt(input string) *big.Int {
	out, err := Hex2BigInt(input)
	if err != nil {
		panic(fmt.Errorf("failed to decode a hex: %w", err))
	}

	return out
}

func pad(size int, input []byte) []byte {
	if len(input) >= size {
		return input
	}

	diff := size - len(input)
	out := make([]byte, diff+len(input))
	copy(out[diff:], input)

	return out
}

func hash(hashType HashType, inputs ...[]byte) []byte {
	h := newHash(hashType).New()

	for ix := range inputs {
		h.Write(inputs[ix])
	}

	return h.Sum(nil)
}

func newHash(hashType HashType) crypto.Hash {
	switch hashType {
	case SHA1:
		return crypto.SHA1
	case SHA256:
		return crypto.SHA256
	case SHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

func RandomSalt(len int) ([]byte, error) {
	out := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, out)
	return out, err
}

func toBigInt(data []byte) *big.Int {
	return big.NewInt(0).SetBytes(data)
}
