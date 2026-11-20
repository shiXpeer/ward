package reportrelay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
)

// Enrollment v1 grants write-only access for one server. Management and reader
// credentials are never returned to the installing host.
type EnrollmentRequest struct {
	ServerID  string `json:"server_id"`
	Recipient string `json:"recipient_public_key"`
}
type EnrollmentGrant struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires_at"`
}
type EnrollmentCredentials struct {
	ServerID  string `json:"server_id"`
	Writer    string `json:"writer_token"`
	Recipient string `json:"recipient_public_key"`
}
type enrollmentTicket struct {
	EnrollmentRequest
	Expires   time.Time `json:"expires_at"`
	NonceHash string    `json:"nonce_hash,omitempty"`
	Writer    string    `json:"writer_token,omitempty"`
}
type enrollmentState struct {
	Version int                         `json:"version"`
	Tickets map[string]enrollmentTicket `json:"tickets"`
	Writers map[string]string           `json:"writers"`
}
type enrollmentStore struct {
	mu     sync.Mutex
	path   string
	state  enrollmentState
	static map[string]string
	now    func() time.Time
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func tokenHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func validRecipient(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32
}
func newEnrollmentStore(dir string, writers map[string]string) (*enrollmentStore, error) {
	s := &enrollmentStore{path: filepath.Join(dir, "enrollment-v1.json"), static: writers, now: time.Now,
		state: enrollmentState{Version: 1, Tickets: map[string]enrollmentTicket{}, Writers: map[string]string{}}}
	if err := atomicfile.ReadJSON(s.path, &s.state, 1<<20); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.state.Version != 1 || s.state.Tickets == nil || s.state.Writers == nil || len(s.state.Tickets) > 64 || len(s.state.Writers) > 64 {
		return nil, errors.New("invalid enrollment state")
	}
	for id, t := range s.state.Writers {
		if !idPattern.MatchString(id) || len(t) != 64 || writers[id] != "" {
			return nil, errors.New("conflicting enrolled server credentials")
		}
	}
	for hash, t := range s.state.Tickets {
		if len(hash) != 64 || !idPattern.MatchString(t.ServerID) || !validRecipient(t.Recipient) {
			return nil, errors.New("invalid enrollment ticket")
		}
	}
	return s, nil
}
func (s *enrollmentStore) writer(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.static[id]; t != "" {
		return t
	}
	return s.state.Writers[id]
}
func (s *enrollmentStore) save(next enrollmentState) error {
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if e = atomicfile.Write(s.path, b, 0600); e != nil {
		return e
	}
	s.state = next
	return nil
}
func (s *enrollmentStore) copyState() enrollmentState {
	n := enrollmentState{Version: 1, Tickets: map[string]enrollmentTicket{}, Writers: map[string]string{}}
	for k, v := range s.state.Tickets {
		if s.now().Before(v.Expires) {
			n.Tickets[k] = v
		}
	}
	for k, v := range s.state.Writers {
		n.Writers[k] = v
	}
	return n
}
func (s *enrollmentStore) routes(mux *http.ServeMux, management string) {
	mux.HandleFunc("POST /v1/enrollments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || management == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+management)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var req EnrollmentRequest
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || !idPattern.MatchString(req.ServerID) || !validRecipient(req.Recipient) {
			http.Error(w, "invalid server or recipient", 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.static[req.ServerID] != "" || s.state.Writers[req.ServerID] != "" {
			http.Error(w, "Server ID is already registered. Choose a new ID; existing credentials will not be replaced.", 409)
			return
		}
		next := s.copyState()
		for hash, t := range next.Tickets {
			if t.ServerID == req.ServerID {
				delete(next.Tickets, hash)
			}
		}
		if len(next.Tickets) >= 64 || len(next.Writers)+len(s.static) >= 64 {
			http.Error(w, "server enrollment limit reached", 409)
			return
		}
		token, e := randomToken()
		if e != nil {
			http.Error(w, "random source unavailable", 500)
			return
		}
		expires := s.now().Add(15 * time.Minute)
		next.Tickets[tokenHash(token)] = enrollmentTicket{EnrollmentRequest: req, Expires: expires}
		if s.save(next) != nil {
			http.Error(w, "cannot save enrollment", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(EnrollmentGrant{Token: token, Expires: expires})
	})
	mux.HandleFunc("POST /v1/enrollments/redeem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		auth := r.Header.Get("Authorization")
		if r.TLS == nil || len(auth) != len("Bearer ")+64 || auth[:7] != "Bearer " {
			http.Error(w, "invalid or expired enrollment", 401)
			return
		}
		var req struct {
			Nonce string `json:"nonce"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req) != nil {
			http.Error(w, "invalid nonce", 400)
			return
		}
		b, e := hex.DecodeString(req.Nonce)
		if e != nil || len(b) != 32 {
			http.Error(w, "invalid nonce", 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		hash := tokenHash(auth[7:])
		ticket, ok := s.state.Tickets[hash]
		if !ok || !s.now().Before(ticket.Expires) {
			http.Error(w, "invalid or expired enrollment", 401)
			return
		}
		nonce := tokenHash(req.Nonce)
		if ticket.NonceHash != "" && ticket.NonceHash != nonce {
			http.Error(w, "enrollment already used by another installation", 409)
			return
		}
		if ticket.NonceHash == "" {
			if len(s.state.Writers)+len(s.static) >= 64 {
				http.Error(w, "server limit reached", 409)
				return
			}
			writer, e := randomToken()
			if e != nil {
				http.Error(w, "random source unavailable", 500)
				return
			}
			ticket.NonceHash = nonce
			ticket.Writer = writer
			next := s.copyState()
			next.Tickets[hash] = ticket
			next.Writers[ticket.ServerID] = writer
			if s.save(next) != nil {
				http.Error(w, "cannot save registration", 500)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EnrollmentCredentials{ServerID: ticket.ServerID, Writer: ticket.Writer, Recipient: ticket.Recipient})
	})
}
