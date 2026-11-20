package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/reportrelay"
)

func TestEnrollAgentAndUploadTLS(t *testing.T) {
	dir := t.TempDir()
	management := strings.Repeat("m", 32)
	reader := strings.Repeat("r", 32)
	handler, e := (reportrelay.Config{Reader: reader, Enrollment: management}).Handler(filepath.Join(dir, "relay"))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	ca := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	recipient := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	b, _ := json.Marshal(reportrelay.EnrollmentRequest{ServerID: "fixture", Recipient: recipient})
	req, _ := http.NewRequest("POST", server.URL+"/v1/enrollments", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+management)
	resp, e := server.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var grant reportrelay.EnrollmentGrant
	_ = json.NewDecoder(resp.Body).Decode(&grant)
	cfg := enrollmentInput{URL: server.URL, Token: grant.Token, ServerID: "fixture", Recipient: recipient}
	out := filepath.Join(dir, "private", "report-upload.json")
	if err := enrollWith(context.Background(), cfg, out, ""); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if err := enrollWith(context.Background(), cfg, out, ca); err != nil {
		t.Fatal(err)
	}
	var upload uploadConfig
	if err := atomicfile.ReadJSON(out, &upload, 16384); err != nil {
		t.Fatal(err)
	}
	if upload.Token == grant.Token || upload.Token == management || upload.Recipient != recipient || upload.CA != ca {
		t.Fatal("wrong saved config")
	}
	if err := enrollWith(context.Background(), cfg, out, ca); err != nil {
		t.Fatal("repeat installation not idempotent", err)
	}
	cfg.ServerID = "another"
	if err := enrollWith(context.Background(), cfg, out, ca); err == nil {
		t.Fatal("existing agent silently replaced")
	}
	cfg.ServerID = "fixture"
	report := filepath.Join(dir, "report.json")
	plain := []byte(`{"format_version":1,"fixture":true}`)
	_ = os.WriteFile(report, plain, 0600)
	if err := uploadReport(context.Background(), out, report); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", server.URL+"/v1/reports/fixture", nil)
	r.Header.Set("Authorization", "Bearer "+reader)
	downloaded, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer downloaded.Body.Close()
	sealed, _ := io.ReadAll(downloaded.Body)
	if downloaded.StatusCode != 200 || bytes.Contains(sealed, plain) {
		t.Fatal("report not encrypted/delivered")
	}
	info, _ := os.Stat(out)
	if info.Mode().Perm() != 0600 {
		t.Fatal("upload config permissions")
	}
}
