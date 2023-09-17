package credentials

import (
	"encoding/json"
	"errors"
	"os"
)

const (
	credDataVersion = 3
)

type CredentialSerializer interface {
	Load() (UserCredList, error)
	Save(UserCredList) error
}

type credentialSerializer struct {
	filePath string
}

func GetCredentialSerializer(filePath string) CredentialSerializer {
	return &credentialSerializer{
		filePath: filePath,
	}
}

func (db *credentialSerializer) Load() (UserCredList, error) {
	dat, err := os.ReadFile(db.filePath)
	if err != nil {
		return nil, err
	}

	var dbContainer UserCredDB
	err = json.Unmarshal(dat, &dbContainer)
	if err != nil {
		return nil, err
	}

	if dbContainer.Version != credDataVersion {
		return nil, errors.New("[Credentials] Credential file has the wrong version")
	}

	return dbContainer.Users, nil
}

func (db *credentialSerializer) Save(users UserCredList) error {
	dbData := &UserCredDB{
		Version: credDataVersion,
		Users:   users,
	}
	dat, err := json.Marshal(dbData)
	if err != nil {
		return err
	}

	err = os.WriteFile(db.filePath, dat, 0644)
	return err
}
