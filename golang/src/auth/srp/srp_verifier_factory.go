package srp

type srpVerifierFactory struct {
	engine SRPEngine
}

type SRPVerifierFactory interface {
	GetVerifierFor(username string, salt []byte, verifier []byte) SRPVerifier
}

func NewSRPVerifierFactory(ivGroup *ConstantGroup, hashType HashType) SRPVerifierFactory {
	return &srpVerifierFactory{
		engine: NewSRPEngine(ivGroup, hashType),
	}
}

func NewSRPVerifierFactoryFromEngine(engine SRPEngine) SRPVerifierFactory {
	return &srpVerifierFactory{
		engine: engine,
	}
}

func (factory *srpVerifierFactory) GetVerifierFor(
	username string,
	salt []byte,
	verifier []byte) SRPVerifier {
	return newSRPVerifier(factory.engine, username, salt, verifier)
}
