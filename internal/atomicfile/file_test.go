package atomicfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicJSONAndSingleWriter(t *testing.T) {
	dir := t.TempDir()
	unlock, e := Lock(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Lock(dir); e == nil {
		t.Fatal("two writers allowed")
	}
	unlock()
	again, e := Lock(dir)
	if e != nil {
		t.Fatal(e)
	}
	again()
	p := filepath.Join(dir, "x.json")
	if e = JSON(p, map[string]int{"v": 1}); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	var got map[string]int
	if e = ReadJSON(p, &got, 1024); e != nil || got["v"] != 1 {
		t.Fatal(got, e)
	}
	if e = ReadJSON(p, &got, 1); e == nil {
		t.Fatal("ignored read limit")
	}
}

func TestStreamedArraysRoundTripAndRejectTrailingData(t *testing.T) {
	type row struct {
		Value string `json:"value"`
	}
	type state struct {
		Count    int             `json:"count"`
		Rows     []row           `json:"rows"`
		Metadata json.RawMessage `json:"metadata"`
	}
	want := state{Count: 2, Rows: []row{{"one"}, {"two"}}, Metadata: json.RawMessage(`{"status":"unknown"}`)}
	path := filepath.Join(t.TempDir(), "state.json")
	if e := JSON(path, want); e != nil {
		t.Fatal(e)
	}
	var got state
	if e := ReadJSON(path, &got, 1<<20); e != nil {
		t.Fatal(e)
	}
	if len(got.Rows) != 2 || got.Rows[1].Value != "two" || got.Count != 2 {
		t.Fatal(got)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{}`)
	f.Close()
	if e := ReadJSON(path, &got, 1<<20); e == nil {
		t.Fatal("accepted trailing state document")
	}
}
