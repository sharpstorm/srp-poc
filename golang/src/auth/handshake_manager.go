package auth

import (
	"log"
	"sharpstorm/srp-auth/auth/credentials"
	"sharpstorm/srp-auth/auth/srp"
	"time"

	"github.com/google/uuid"
)

const signatureValidity = 10 * time.Second // Signatures are only valid for 15 seconds
const handshakeLimit = 3

type HandshakeManager interface {
	GenerateHandshake(username string) (*SrpHandshakeSession, []byte, []byte)
	ConsumeHandshake(username string, handshakeId string) *SrpHandshakeSession
}

type handshakeManager struct {
	credentialManager credentials.CredentialManager
	activeHandshakes  map[string][]*SrpHandshakeSession
	factory           srp.SRPVerifierFactory
	expiryWorkerLock  chan bool
}

type SrpHandshakeSession struct {
	HandshakeId string
	Verifier    srp.SRPVerifier
	publicKey   []byte
	expiryTime  time.Time
}

func NewHandshakeManager(credentialManager credentials.CredentialManager) HandshakeManager {
	mgr := &handshakeManager{
		credentialManager: credentialManager,
		activeHandshakes:  make(map[string][]*SrpHandshakeSession),
		factory:           srp.NewSRPVerifierFactory(SRP_GROUP, SRP_HASH),
		expiryWorkerLock:  make(chan bool, 1),
	}

	mgr.expiryWorkerLock <- true
	return mgr
}

func (cm *handshakeManager) GenerateHandshake(username string) (*SrpHandshakeSession, []byte, []byte) {
	salt, verifier, err := cm.credentialManager.GetUserInfo(username)
	if err != nil {
		return nil, nil, nil
	}

	handshakeId := cm.generateIdentifier()
	newHandshake := &SrpHandshakeSession{
		HandshakeId: handshakeId,
		Verifier:    cm.factory.GetVerifierFor(username, salt, verifier),
		expiryTime:  time.Now().Add(signatureValidity),
	}
	pk, err := newHandshake.Verifier.InitPublicKey()
	if err != nil {
		return nil, nil, nil
	}
	newHandshake.publicKey = pk

	curHandshakes, found := cm.activeHandshakes[username]
	if !found {
		cm.activeHandshakes[username] = []*SrpHandshakeSession{newHandshake}
	} else {
		if len(curHandshakes) < handshakeLimit {
			cm.activeHandshakes[username] = append(curHandshakes, newHandshake)
		} else {
			for i := 0; i < handshakeLimit-1; i++ {
				curHandshakes[i] = curHandshakes[i+1]
			}
			curHandshakes[handshakeLimit-1] = newHandshake
		}
	}

	cm.launchExpireHandshakeWorker()
	return newHandshake, salt, pk
}

func (cm *handshakeManager) generateIdentifier() string {
	return uuid.NewString()
}

func (cm *handshakeManager) ConsumeHandshake(username string, handshakeId string) *SrpHandshakeSession {
	curHandshakes, found := cm.activeHandshakes[username]
	if !found {
		return nil
	}

	handshake, idx := cm.findHandshake(curHandshakes, handshakeId)
	if handshake == nil {
		return nil
	}

	curHandshakes[idx] = curHandshakes[len(curHandshakes)-1]
	newHandshakeArr := curHandshakes[:len(curHandshakes)-1]
	if len(newHandshakeArr) == 0 {
		delete(cm.activeHandshakes, username)
	} else {
		cm.activeHandshakes[username] = newHandshakeArr
	}

	if time.Now().After(handshake.expiryTime) {
		return nil
	}

	return handshake
}

func (cm *handshakeManager) launchExpireHandshakeWorker() {
	select {
	case <-cm.expiryWorkerLock:
		log.Println("[Handshake Mgr] Starting expiry worker")
		time.AfterFunc(signatureValidity, cm.expireHandshake)
	default:
	}
}

func (cm *handshakeManager) expireHandshake() {
	log.Println("[Handshake Mgr] Expiring handshakes")

	if len(cm.activeHandshakes) == 0 {
		cm.expiryWorkerLock <- true
		log.Println("[Handshake Mgr] Expiry worker dying")
		return
	}

	time.AfterFunc(signatureValidity, cm.expireHandshake)
}

func (cm *handshakeManager) findHandshake(handshakes []*SrpHandshakeSession, handshakeId string) (*SrpHandshakeSession, int) {
	for idx, handshake := range handshakes {
		if handshake.HandshakeId == handshakeId {
			return handshake, idx
		}
	}

	return nil, 0
}
