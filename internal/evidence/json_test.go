package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLosslessEncodingAndTamper(t *testing.T) {
	raw := json.RawMessage(`{"vendor_status":"` + strings.Repeat("affected ", 2000) + `"}`)
	packed, e := Pack(raw)
	if e != nil || len(packed) >= len(raw) {
		t.Fatal(e)
	}
	unpacked, e := Unpack(packed)
	if e != nil || !bytes.Equal(raw, unpacked) {
		t.Fatal("evidence changed", e)
	}
	var env envelope
	json.Unmarshal(packed, &env)
	env.Bytes--
	b, _ := json.Marshal(env)
	if _, e = Unpack(b); e == nil {
		t.Fatal("accepted expanded size mismatch")
	}
	env.Bytes++
	env.SHA256 = strings.Repeat("0", 64)
	b, _ = json.Marshal(env)
	if _, e = Unpack(b); e == nil {
		t.Fatal("accepted wrong digest")
	}
	if _, e = Pack(make([]byte, MaxBytes+1)); e == nil {
		t.Fatal("accepted oversized evidence")
	}
}
