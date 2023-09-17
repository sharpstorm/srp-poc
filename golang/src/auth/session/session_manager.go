package session

import "log"

type Session struct {
	Id     string
	Secret []byte
}

type SessionManager interface {
	IsActive(session string) bool
	RegisterSession(username string, session string, secret []byte)
	RemoveSession(session string)
	GetSession(session string) (*Session, string)
}

type sessionManager struct {
	sessions     map[string]string
	userSessions map[string][]Session
}

func NewSessionManager() SessionManager {
	return &sessionManager{
		sessions:     make(map[string]string),
		userSessions: make(map[string][]Session),
	}
}

func (mgr *sessionManager) IsActive(session string) bool {
	_, found := mgr.sessions[session]
	return found
}

func (mgr *sessionManager) GetSession(session string) (*Session, string) {
	username, found := mgr.sessions[session]
	if !found {
		return nil, ""
	}

	userSessions := mgr.userSessions[username]
	for _, userSession := range userSessions {
		if userSession.Id == session {
			return &userSession, username
		}
	}
	return nil, ""
}

func (mgr *sessionManager) RegisterSession(username string, session string, secret []byte) {
	if mgr.IsActive(session) {
		return
	}

	userSessions, found := mgr.userSessions[username]
	sessionObj := Session{
		Id:     session,
		Secret: secret,
	}
	if found {
		newSessions := userSessions
		if len(userSessions) >= 3 {
			toRevoke := userSessions[0]
			newSessions = userSessions[1:]
			mgr.RemoveSession(toRevoke.Id)
		}
		newSessions = append(newSessions, sessionObj)
		mgr.userSessions[username] = newSessions
	} else {
		mgr.userSessions[username] = []Session{sessionObj}
	}
	mgr.sessions[session] = username
	log.Printf("[Session Control] Issued Key: %s\n", session)
}

func (mgr *sessionManager) RemoveSession(session string) {
	if !mgr.IsActive(session) {
		return
	}

	delete(mgr.sessions, session)
	log.Printf("[Session Control] Revoked Key: %s\n", session)
}
