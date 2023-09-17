package srp

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

type srpVerifier struct {
	engine SRPEngine

	// Params from database
	I string   // User Identity / Username
	s []byte   // User Salt
	v *big.Int // User Verifier

	// Server ephemeral params
	b *big.Int // Server private key
	B *big.Int // Server public key

	A *big.Int // Client public key
	u *big.Int // Random scrambling parameter

	sessionSecret       []byte
	sessionSecretHash   []byte
	expectedClientProof []byte
	serverProof         []byte
}

type SRPVerifier interface {
	InitPublicKey() ([]byte, error)
	SetClientPublicKey(A []byte) error
	IsClientProofValid(proof []byte) bool
	GetSessionSecret() []byte
	GetServerProof() []byte

	RandomSalt() []byte
}

func newSRPVerifier(engine SRPEngine, username string, salt []byte, verifier []byte) SRPVerifier {
	return &srpVerifier{
		engine: engine,

		I: username,
		s: salt,
		v: toBigInt(verifier),
	}
}

func (srp *srpVerifier) InitPublicKey() ([]byte, error) {
	if srp.b == nil {
		if salt := srp.engine.RandomSalt(); salt == nil {
			return nil, errors.New("failed to generate ephemeral server secret b")
		} else {
			srp.b = toBigInt(salt)
		}
	}

	temp1 := big.NewInt(0).Mul(srp.engine.GetK(), srp.v)
	temp1 = temp1.Add(temp1, srp.engine.ComputePow(srp.b))
	srp.B = srp.engine.ModN(temp1)

	return srp.B.Bytes(), nil
}

func (srp *srpVerifier) SetClientPublicKey(A []byte) error {
	srp.A = big.NewInt(0).SetBytes(A)
	srp.u = toBigInt(srp.engine.Hash(srp.engine.Pad(srp.A.Bytes()), srp.engine.Pad(srp.B.Bytes())))

	// The host MUST abort the authentication attempt if A % N is zero.
	if srp.isModZero(srp.A) {
		return errors.New("aborted due to MOD 0")
	} else if srp.u.Sign() == 0 {
		return errors.New("aborted due to u = 0")
	}

	temp1 := srp.engine.ComputePow2(srp.v, srp.u)
	temp1 = temp1.Mul(temp1, srp.A)
	srp.sessionSecret = srp.engine.ComputePow2(temp1, srp.b).Bytes()
	srp.sessionSecretHash = srp.engine.Hash(srp.sessionSecret)

	srp.expectedClientProof = srp.engine.Hash(
		srp.engine.GetParamsHash(),
		srp.engine.Hash([]byte(srp.I)),
		srp.s,
		A,
		srp.B.Bytes(),
		srp.sessionSecretHash,
	)

	srp.serverProof = srp.engine.Hash(A, srp.expectedClientProof, srp.sessionSecretHash)

	return nil
}

func (srp *srpVerifier) IsClientProofValid(proof []byte) bool {
	return subtle.ConstantTimeCompare(proof, srp.expectedClientProof) == 1
}

func (srp *srpVerifier) GetSessionSecret() []byte {
	return srp.sessionSecret
}

func (srp *srpVerifier) GetServerProof() []byte {
	return srp.serverProof
}

func (srp *srpVerifier) isModZero(value *big.Int) bool {
	return srp.engine.ModN(value).Sign() == 0
}

func (srp *srpVerifier) RandomSalt() []byte {
	return srp.engine.RandomSalt()
}
