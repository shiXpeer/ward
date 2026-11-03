// Package evidence stores large source-specific JSON losslessly inside a versioned
// compressed JSON envelope. Consumers must call Unpack before interpreting facts.
package evidence

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const MaxBytes = 8 << 20
const Encoding = "shixpeer-ward-gzip-json-v1"

type envelope struct {
	Encoding string `json:"ward_encoding"`
	SHA256   string `json:"sha256"`
	Bytes    int    `json:"expanded_bytes"`
	Data     []byte `json:"data"`
}

func Pack(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) > MaxBytes {
		return nil, errors.New("evidence JSON exceeds limit")
	}
	if len(raw) < 4096 {
		return raw, nil
	}
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
	if _, e := w.Write(raw); e != nil {
		return nil, e
	}
	if e := w.Close(); e != nil {
		return nil, e
	}
	sum := sha256.Sum256(raw)
	result, e := json.Marshal(envelope{Encoding, hex.EncodeToString(sum[:]), len(raw), b.Bytes()})
	if e != nil {
		return nil, e
	}
	if len(result) >= len(raw) {
		return raw, nil
	}
	return result, nil
}
func Unpack(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) > MaxBytes {
		return nil, errors.New("evidence input exceeds limit")
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	if _, ok := fields["ward_encoding"]; !ok {
		return raw, nil
	}
	var v envelope
	if e := json.Unmarshal(raw, &v); e != nil {
		return nil, e
	}
	if v.Encoding != Encoding || v.Bytes < 1 || v.Bytes > MaxBytes {
		return nil, errors.New("unsupported evidence encoding or size")
	}
	r, e := gzip.NewReader(bytes.NewReader(v.Data))
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, int64(v.Bytes)+1))
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	if len(b) != v.Bytes || hex.EncodeToString(sum[:]) != v.SHA256 || !json.Valid(b) {
		return nil, errors.New("invalid packed evidence")
	}
	return b, nil
}
