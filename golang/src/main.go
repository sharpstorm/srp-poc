package main

import (
	"crypto"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sharpstorm/srp-auth/auth"
	"sharpstorm/srp-auth/auth/credentials"
	"sharpstorm/srp-auth/auth/session"
	"sharpstorm/srp-auth/auth/srp"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

type Handlers struct {
	credsManager     credentials.CredentialManager
	handshakeManager auth.HandshakeManager
	sessionManager   session.SessionManager
}

type HandshakeRequest struct {
	Username     string `json:"username"`
	ClientPublic []byte `json:"clientpublic"`
}

type HandshakeResponse struct {
	Salt      []byte `json:"salt"`
	PublicKey []byte `json:"publickey"`
	Hid       string `json:"hid"`
}

type VerifyRequest struct {
	Username    string `json:"username"`
	Hid         string `json:"hid"`
	ClientProof []byte `json:"clientproof"`
}

type VerifyResponse struct {
	Result      bool   `json:"result"`
	ServerProof []byte `json:"serverproof"`
	SessionId   string `json:"sessionid"`
}

type WhoAmIRequest struct {
	SessionId string `json:"sessionid"`
}

type WhoAmIResponse struct {
	Proof []byte `json:"proof"`
}

func main() {
	srpEngine := srp.NewSRPEngine(auth.SRP_GROUP, auth.SRP_HASH)
	credsManager := credentials.GetCredentialManager("./users.json", srpEngine)
	sessionManager := session.NewSessionManager()

	credsManager.AddUser("admin", "password1234")

	handlers := Handlers{
		credsManager:     credsManager,
		handshakeManager: auth.NewHandshakeManager(credsManager),
		sessionManager:   sessionManager,
	}

	router := httprouter.New()
	router.GET("/", handlers.getRoot)
	router.ServeFiles("/assets/*filepath", http.Dir("../../frontend/assets"))
	router.POST("/api/auth/handshake", handlers.startHandshake)
	router.POST("/api/auth/verify", handlers.verifyClient)
	router.POST("/api/auth/whoami", handlers.whoAmI)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"foo.com"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
		AllowCredentials: true,
	})

	log.Fatal(http.ListenAndServe(":8000", c.Handler(router)))
}

func (handlers *Handlers) getRoot(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	data, _ := os.ReadFile("../../frontend/index.html")
	w.Write(data)
}

func (handlers *Handlers) startHandshake(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	var req HandshakeRequest
	err = json.Unmarshal(jsonBody, &req)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	handshake, salt, pk := handlers.handshakeManager.GenerateHandshake(req.Username)
	if handshake == nil || salt == nil || pk == nil {
		w.WriteHeader(400)
		return
	}

	err = handshake.Verifier.SetClientPublicKey(req.ClientPublic)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	result, _ := json.Marshal(HandshakeResponse{
		Salt:      salt,
		PublicKey: pk,
		Hid:       handshake.HandshakeId,
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(result)
}

func (handlers *Handlers) verifyClient(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	var req VerifyRequest
	err = json.Unmarshal(jsonBody, &req)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	handshake := handlers.handshakeManager.ConsumeHandshake(req.Username, req.Hid)
	if handshake == nil {
		w.WriteHeader(400)
		return
	}

	isValid := handshake.Verifier.IsClientProofValid(req.ClientProof)
	result := false
	serverProof := []byte{}
	sessionId := ""
	if isValid {
		result = true
		serverProof = handshake.Verifier.GetServerProof()
		sessionId = uuid.NewString()
		handlers.sessionManager.RegisterSession(req.Username, sessionId, handshake.Verifier.GetSessionSecret())
	}

	respBody, _ := json.Marshal(VerifyResponse{
		Result:      result,
		ServerProof: serverProof,
		SessionId:   sessionId,
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(respBody)
}

func (handlers *Handlers) whoAmI(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	jsonBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	var req WhoAmIRequest
	err = json.Unmarshal(jsonBody, &req)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	if !handlers.sessionManager.IsActive(req.SessionId) {
		w.WriteHeader(403)
		return
	}

	session, username := handlers.sessionManager.GetSession(req.SessionId)
	hasher := crypto.SHA512.New()
	hasher.Write([]byte(username))
	hasher.Write(session.Secret)
	respBody, _ := json.Marshal(WhoAmIResponse{
		Proof: hasher.Sum(nil),
	})

	w.Header().Add("Content-Type", "application/json")
	w.Write(respBody)
}
