package credentials

import (
	"errors"
	"log"
	"sharpstorm/srp-auth/auth/srp"
)

type CredentialManager interface {
	Init()
	Save()

	AddUser(username string, password string) error
	UpdateUser(username string, password string) error
	DeleteUser(username string) error

	GetUserInfo(username string) ([]byte, []byte, error)
}

type credentialManager struct {
	isInit bool
	users  UserCredList
	engine srp.SRPEngine

	serializer CredentialSerializer
}

var instance *credentialManager = nil

func GetCredentialManager(credentialsPath string, engine srp.SRPEngine) CredentialManager {
	if instance == nil {
		instance = &credentialManager{
			engine:     engine,
			isInit:     false,
			users:      make(UserCredList),
			serializer: GetCredentialSerializer(credentialsPath),
		}
	}
	return instance
}

func (mgr *credentialManager) Init() {
	log.Println("[Credentials] Loading DB from disk")
	data, err := mgr.serializer.Load()
	if err != nil {
		log.Printf("[Credentials] Failed to load DB from disk, err = %s\n", err)
		return
	}

	mgr.isInit = true
	mgr.users = data
}

func (mgr *credentialManager) Save() {
	log.Println("[Credentials] Saving DB to disk")
	err := mgr.serializer.Save(mgr.users)
	if err != nil {
		log.Printf("[Credentials] Failed to save DB to disk, err = %s\n", err)
	}
}

func (mgr *credentialManager) AddUser(username string, password string) error {
	_, found := mgr.users[username]
	if found {
		return errors.New("user already exists")
	}

	mgr.addUserToList(username, password)
	return nil
}

func (mgr *credentialManager) UpdateUser(username string, password string) error {
	_, found := mgr.users[username]
	if !found {
		return errors.New("user does not exist")
	}

	mgr.addUserToList(username, password)
	return nil
}

func (mgr *credentialManager) addUserToList(username string, password string) {
	salt := mgr.engine.RandomSalt()

	mgr.users[username] = &UserCreds{
		Salt:     salt,
		Verifier: mgr.engine.GetVerifier(salt, username, password),
	}
}

func (mgr *credentialManager) DeleteUser(username string) error {
	_, found := mgr.users[username]
	if !found {
		return errors.New("user does not exist")
	}

	delete(mgr.users, username)
	return nil
}

func (mgr *credentialManager) GetUserInfo(username string) ([]byte, []byte, error) {
	userInfo, found := mgr.users[username]
	if !found {
		return nil, nil, errors.New("user does not exist")
	}

	return userInfo.Salt, userInfo.Verifier, nil
}
