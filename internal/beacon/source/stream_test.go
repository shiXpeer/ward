package source

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamingJSONEquivalent(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{testOSV, "[" + testOSV + "]", `{"vulns":[` + testOSV + `],"metadata":{}}`} {
		old, e := parseOSVDocument([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		var got []Advisory
		e = streamOSVDocument(strings.NewReader(raw), func(a Advisory) error { got = append(got, a); return nil })
		if e != nil || len(got) != len(old) || !reflect.DeepEqual(got[0].Affected, old[0].Affected) || got[0].ID != old[0].ID {
			t.Fatal(e, got, old)
		}
	}
	raw := `{"openssl":{"CVE-2026-1234":{"releases":{"bookworm":{"status":"resolved","fixed_version":"0"},"trixie":{"status":"resolved","fixed_version":"1:3.0-1+deb13u1","nodsa":"review"}}}}}`
	old, e := parseDebian(ctx, strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	var got []Advisory
	e = streamDebianSmall(ctx, strings.NewReader(raw), func(a Advisory) error { got = append(got, a); return nil })
	if e != nil || !reflect.DeepEqual(got, old) {
		t.Fatal(e, "Debian semantics changed")
	}
	if e = streamDebianSmall(ctx, strings.NewReader(raw+"{}"), func(Advisory) error { return nil }); e == nil {
		t.Fatal("accepted trailing JSON")
	}
	if e = streamOSVDocument(strings.NewReader(`[{"id":"`+strings.Repeat("x", maxEntry+100)+`"}]`), func(Advisory) error { return nil }); e == nil {
		t.Fatal("accepted oversized value")
	}
}
func TestStreamingZIP64AndCorruption(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i := 0; i < 65536; i++ {
		name := fmt.Sprintf("ignored-%d.txt", i)
		if i == 65535 {
			name = "../../advisory.json"
		}
		f, e := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if e != nil {
			t.Fatal(e)
		}
		if i == 65535 {
			io.WriteString(f, testOSV)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	count := 0
	e := streamZIP(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()), func(a Advisory) error {
		count++
		if a.ID == "" {
			t.Fatal("missing ID")
		}
		return nil
	})
	if e != nil || count != 1 {
		t.Fatal(e, count)
	}
	damaged := append([]byte(nil), b.Bytes()...)
	offset := bytes.Index(damaged, []byte(testOSV))
	if offset < 0 {
		t.Fatal("fixture missing")
	}
	damaged[offset] ^= 1
	if e = streamZIP(context.Background(), bytes.NewReader(damaged), int64(len(damaged)), func(Advisory) error { return nil }); e == nil {
		t.Fatal("corrupt ZIP accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = streamZIP(ctx, bytes.NewReader(b.Bytes()), int64(b.Len()), func(Advisory) error { return nil }); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestInputConditionalCache(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 2 {
			if r.Header.Get("If-None-Match") != "\"fixture\"" {
				t.Error("missing ETag")
			}
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", "\"fixture\"")
		io.WriteString(w, testOSV)
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	u, _ := url.Parse(server.URL)
	d := Definition{ID: "fixture", Type: "osv", URL: server.URL, CAFile: ca, AllowedHosts: []string{u.Hostname()}, MaxBytes: 1 << 20}
	src := &documentSource{d}
	first, e := Prepare(context.Background(), src, dir)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Prepare(context.Background(), src, dir)
	if e != nil || first[0].Digest != second[0].Digest {
		t.Fatal(e)
	}
	count := 0
	e = Walk(context.Background(), second[0], func(a Advisory) error { count++; return nil })
	if e != nil || count != 1 {
		t.Fatal(e, count)
	}
}

func TestNVDPrepareUsesBoundedWorkersAndStableYearOrder(t *testing.T) {
	var active, maximum atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		w.Write([]byte("fixture"))
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	u, _ := url.Parse(server.URL)
	src := &documentSource{Definition{ID: "nvd", Type: "nvd-years", URL: server.URL + "/", CAFile: ca, AllowedHosts: []string{u.Hostname()}, MaxBytes: 1024}}
	inputs, e := Prepare(context.Background(), src, filepath.Join(dir, "cache"))
	if e != nil {
		t.Fatal(e)
	}
	if len(inputs) != time.Now().UTC().Year()-2001 || maximum.Load() > 4 {
		t.Fatal(len(inputs), maximum.Load())
	}
	for _, in := range inputs {
		if in.Kind != "nvd-gzip" {
			t.Fatal(in.Kind)
		}
		if _, e = os.Stat(in.Path); e != nil {
			t.Fatal(e)
		}
	}
}
