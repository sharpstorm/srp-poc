package credentials

type UserCredDB struct {
	Version int          `json:"version"`
	Users   UserCredList `json:"users"`
}

type UserCredList map[string]*UserCreds

type UserCreds struct {
	Salt     []byte `json:"salt"`
	Verifier []byte `json:"verifier"`
}
