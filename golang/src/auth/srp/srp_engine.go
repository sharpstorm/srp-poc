package srp

import (
	"math/big"
)

type SRPEngine interface {
	Pad(input []byte) []byte
	Hash(inputs ...[]byte) []byte
	GetHashedCreds(salt []byte, username string, password string) []byte
	GetVerifier(salt []byte, username string, password string) []byte
	GetK() *big.Int
	ComputePow(value *big.Int) *big.Int
	ComputePow2(v1 *big.Int, v2 *big.Int) *big.Int
	ModN(value *big.Int) *big.Int

	GetParamsHash() []byte

	NByteLen() int
	RandomSalt() []byte
}

type srpEngine struct {
	nByteLength int
	hashType    HashType

	N *big.Int
	g *big.Int
}

func NewSRPEngine(ivGroup *ConstantGroup, hashType HashType) SRPEngine {
	return &srpEngine{
		nByteLength: ivGroup.NByteLen(),
		hashType:    hashType,
		N:           &ivGroup.N,
		g:           &ivGroup.G,
	}
}

func (engine *srpEngine) Pad(input []byte) []byte {
	return pad(engine.nByteLength, input)
}

func (engine *srpEngine) Hash(inputs ...[]byte) []byte {
	return hash(engine.hashType, inputs...)
}

func (engine *srpEngine) GetHashedCreds(salt []byte, username string, password string) []byte {
	return engine.Hash(salt, engine.representCredentials(username, password))
}

func (engine *srpEngine) GetVerifier(salt []byte, username string, password string) []byte {
	hashedCreds := toBigInt(engine.GetHashedCreds(salt, username, password))
	return big.NewInt(0).Exp(engine.g, hashedCreds, engine.N).Bytes()
}

func (engine *srpEngine) representCredentials(username string, password string) []byte {
	return []byte(username + ":" + password)
}

func (engine *srpEngine) NByteLen() int {
	return engine.nByteLength
}

func (engine *srpEngine) RandomSalt() []byte {
	salt, err := RandomSalt(engine.nByteLength)
	if err != nil {
		return nil
	}

	return salt
}

func (engine *srpEngine) GetK() *big.Int {
	nBytes := engine.N.Bytes()
	gBytes := engine.g.Bytes()
	return toBigInt(engine.Hash(nBytes, engine.Pad(gBytes)))
}

func (engine *srpEngine) ComputePow(value *big.Int) *big.Int {
	return big.NewInt(0).Exp(engine.g, value, engine.N)
}

func (engine *srpEngine) ComputePow2(v1 *big.Int, v2 *big.Int) *big.Int {
	return big.NewInt(0).Exp(v1, v2, engine.N)
}

func (engine *srpEngine) ModN(value *big.Int) *big.Int {
	return big.NewInt(0).Mod(value, engine.N)
}

func (engine *srpEngine) GetParamsHash() []byte {
	return engine.xor(engine.Pad(engine.g.Bytes()), engine.Pad(engine.N.Bytes()))
}

func (engine *srpEngine) xor(b1 []byte, b2 []byte) []byte {
	ret := make([]byte, len(b1))
	for i := range b1 {
		ret[i] = b1[i] ^ b2[i]
	}

	return ret
}
