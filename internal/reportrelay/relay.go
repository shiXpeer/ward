package reportrelay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"shixpeer.com/ward/internal/atomicfile"
)

const MaxReport = 32 << 20
const Info = "shixpeer-ward/report/v1"

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func Seal(recipient, report []byte, id string) ([]byte, error) {
	if !idPattern.MatchString(id) || len(report) > MaxReport || !json.Valid(report) {
		return nil, errors.New("invalid server ID or report")
	}
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipient)
	if err != nil {
		return nil, err
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, Info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	header := append([]byte{1}, ephemeral.PublicKey().Bytes()...)
	header = append(header, nonce...)
	return gcm.Seal(header, nonce, report, []byte(id)), nil
}

type Config struct {
	Reader  string            `json:"reader_token"`
	Writers map[string]string `json:"writer_tokens"`
}

func (c Config) Handler(dir string) (http.Handler, error) {
	if len(c.Reader) < 32 || len(c.Writers) == 0 {
		return nil, errors.New("configure a reader and at least one writer with tokens of at least 32 characters")
	}
	seen := map[string]bool{c.Reader: true}
	for id, token := range c.Writers {
		if !idPattern.MatchString(id) || len(token) < 32 || seen[token] {
			return nil, errors.New("invalid ID or missing/reused token")
		}
		seen[token] = true
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	authorized := func(r *http.Request, token string) bool {
		return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/reports", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, c.Reader) {
			http.Error(w, "unauthorized", 401)
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		ids := []string{}
		for _, e := range entries {
			id, ok := strings.CutSuffix(e.Name(), ".sealed")
			if ok && !e.IsDir() && c.Writers[id] != "" {
				ids = append(ids, id)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ids)
	})
	mux.HandleFunc("GET /v1/reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, c.Reader) {
			http.Error(w, "unauthorized", 401)
			return
		}
		id := r.PathValue("id")
		if c.Writers[id] == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, filepath.Join(dir, id+".sealed"))
	})
	mux.HandleFunc("PUT /v1/reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if c.Writers[id] == "" || !authorized(r, c.Writers[id]) {
			http.Error(w, "unauthorized", 401)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxReport+61))
		if err != nil || len(data) < 61 || data[0] != 1 {
			http.Error(w, "invalid encrypted envelope", 400)
			return
		}
		if err := atomicfile.Write(filepath.Join(dir, id+".sealed"), data, 0600); err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		w.WriteHeader(204)
	})
	return mux, nil
}
