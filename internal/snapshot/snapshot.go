// Package snapshot defines the v3 signed, immutable disk database distribution.
package snapshot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"shixpeer.com/ward/internal/compactdb"
	"time"
)

const Version = 3
const MaxManifest = 1 << 20
const MaxObject int64 = 128 << 20
const MaxTotal int64 = 4 << 30

var ArtifactName = regexp.MustCompile(`^db-[a-f0-9]{64}\.wdb$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Object struct {
	Slot   string `json:"slot"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int64  `json:"rows"`
}

func (o Object) Name() string { return "db-" + o.SHA256 + ".wdb" }

type Manifest struct {
	Version    int                      `json:"version"`
	Format     int                      `json:"format"`
	Revision   int64                    `json:"revision"`
	CreatedAt  time.Time                `json:"created_at"`
	ExpiresAt  time.Time                `json:"expires_at"`
	BaseURL    string                   `json:"base_url,omitempty"`
	Profile    compactdb.Profile        `json:"profile"`
	Generation string                   `json:"generation"`
	Sources    []compactdb.SourceStatus `json:"sources"`
	Objects    []Object                 `json:"objects"`
}
type Envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Sign(m Manifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	b, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	return json.Marshal(Envelope{b, ed25519.Sign(key, b)})
}
func Verify(b []byte, key ed25519.PublicKey, now time.Time) (Manifest, error) {
	var m Manifest
	var env Envelope
	if len(b) > MaxManifest || len(key) != ed25519.PublicKeySize {
		return m, errors.New("invalid manifest/key size")
	}
	if json.Unmarshal(b, &env) != nil || !ed25519.Verify(key, env.Payload, env.Signature) {
		return m, errors.New("snapshot signature rejected")
	}
	if e := json.Unmarshal(env.Payload, &m); e != nil {
		return m, e
	}
	if m.Version != Version || m.Format != compactdb.Format || m.Revision < 1 || m.CreatedAt.IsZero() || m.CreatedAt.After(now.Add(5*time.Minute)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.CreatedAt) || m.ExpiresAt.Sub(m.CreatedAt) > 7*24*time.Hour || !digestPattern.MatchString(m.Generation) {
		return m, errors.New("unsupported, expired or invalid snapshot")
	}
	if e := m.Profile.Validate(); e != nil {
		return m, e
	}
	if len(m.Sources) == 0 || len(m.Objects) == 0 || len(m.Objects) > 896 {
		return m, errors.New("missing coverage or invalid object count")
	}
	var total int64
	seen := map[string]bool{}
	for _, o := range m.Objects {
		if !compactdb.ValidSlot(o.Slot) || seen[o.Slot] || !digestPattern.MatchString(o.SHA256) || o.Bytes < compactdb.HeaderSize || o.Bytes > MaxObject || o.Rows < 1 || o.Rows > 4000000 {
			return m, errors.New("invalid database object")
		}
		seen[o.Slot] = true
		total += o.Bytes
		if total > MaxTotal {
			return m, errors.New("snapshot exceeds disk budget")
		}
	}
	return m, nil
}

// PayloadDigest binds revisions to authenticated bytes, independent of envelope whitespace.
func PayloadDigest(raw []byte) string {
	var e Envelope
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	return Digest(e.Payload)
}
