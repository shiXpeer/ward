package reportrelay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrollmentIsolationPersistenceAndRetry(t *testing.T) {
	dir := t.TempDir()
	reader := strings.Repeat("r", 32)
	management := strings.Repeat("m", 32)
	cfg := Config{Reader: reader, Enrollment: management, Writers: map[string]string{"legacy": strings.Repeat("w", 32)}}
	handler, e := cfg.Handler(dir)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	request := func(method, path, token string, body any) (int, []byte) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	input := EnrollmentRequest{ServerID: "web-01", Recipient: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}
	for _, token := range []string{reader, strings.Repeat("w", 32), ""} {
		if code, _ := request("POST", "/v1/enrollments", token, input); code != 401 {
			t.Fatalf("reader/writer could enroll: %d", code)
		}
	}
	if code, _ := request("POST", "/v1/enrollments", management, EnrollmentRequest{ServerID: "../bad", Recipient: input.Recipient}); code != 400 {
		t.Fatal(code)
	}
	if code, _ := request("POST", "/v1/enrollments", management, EnrollmentRequest{ServerID: "legacy", Recipient: input.Recipient}); code != 409 {
		t.Fatal("overwrote static server")
	}
	code, raw := request("POST", "/v1/enrollments", management, input)
	if code != 201 {
		t.Fatalf("create %d %s", code, raw)
	}
	var grant EnrollmentGrant
	if json.Unmarshal(raw, &grant) != nil || len(grant.Token) != 64 {
		t.Fatal("invalid grant")
	}
	code, raw = request("POST", "/v1/enrollments", management, input)
	if code != 201 {
		t.Fatal(code)
	}
	var next EnrollmentGrant
	_ = json.Unmarshal(raw, &next)
	nonce := strings.Repeat("a", 64)
	if code, _ := request("POST", "/v1/enrollments/redeem", grant.Token, map[string]string{"nonce": nonce}); code != 401 {
		t.Fatal("replaced pending grant still works")
	}
	code, raw = request("POST", "/v1/enrollments/redeem", next.Token, map[string]string{"nonce": nonce})
	if code != 200 {
		t.Fatalf("redeem %d %s", code, raw)
	}
	var creds EnrollmentCredentials
	_ = json.Unmarshal(raw, &creds)
	if creds.ServerID != input.ServerID || creds.Recipient != input.Recipient || len(creds.Writer) != 64 || creds.Writer == management || creds.Writer == reader {
		t.Fatal("invalid credentials")
	}
	code, retry := request("POST", "/v1/enrollments/redeem", next.Token, map[string]string{"nonce": nonce})
	if code != 200 || !bytes.Equal(raw, retry) {
		t.Fatal("same-install retry changed credentials")
	}
	if code, _ := request("POST", "/v1/enrollments/redeem", next.Token, map[string]string{"nonce": strings.Repeat("b", 64)}); code != 409 {
		t.Fatal("ticket reused on another installation")
	}
	if code, _ := request("POST", "/v1/enrollments", management, input); code != 409 {
		t.Fatal("overwrote enrolled server")
	}
	if code, _ := request("GET", "/v1/reports", creds.Writer, nil); code != 401 {
		t.Fatal("writer can read")
	}
	sealed, _ := Seal(key.PublicKey().Bytes(), []byte(`{"format_version":1}`), input.ServerID)
	req, _ := http.NewRequest("PUT", server.URL+"/v1/reports/"+input.ServerID, bytes.NewReader(sealed))
	req.Header.Set("Authorization", "Bearer "+creds.Writer)
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	// Reload handler from disk: enrollment must survive a relay restart.
	restored, e := cfg.Handler(dir)
	if e != nil {
		t.Fatal(e)
	}
	check := httptest.NewRequest("GET", "/v1/reports", nil)
	check.Header.Set("Authorization", "Bearer "+reader)
	out := httptest.NewRecorder()
	restored.ServeHTTP(out, check)
	if out.Code != 200 || !strings.Contains(out.Body.String(), input.ServerID) {
		t.Fatal("registered report lost after restart")
	}
	info, e := os.Stat(filepath.Join(dir, "enrollment-v1.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private state permissions")
	}
}
func TestEnrollmentExpiryAndConcurrentClaim(t *testing.T) {
	store, e := newEnrollmentStore(t.TempDir(), nil)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	store.now = func() time.Time { return now }
	mux := http.NewServeMux()
	management := strings.Repeat("z", 32)
	store.routes(mux, management)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	issue := func(id string) EnrollmentGrant {
		b, _ := json.Marshal(EnrollmentRequest{id, pub})
		req, _ := http.NewRequest("POST", server.URL+"/v1/enrollments", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+management)
		resp, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var g EnrollmentGrant
		_ = json.NewDecoder(resp.Body).Decode(&g)
		return g
	}
	grant := issue("expired")
	now = now.Add(16 * time.Minute)
	call := func(token, nonce string) int {
		b, _ := json.Marshal(map[string]string{"nonce": nonce})
		req, _ := http.NewRequest("POST", server.URL+"/v1/enrollments/redeem", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := server.Client().Do(req)
		if e != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if call(grant.Token, strings.Repeat("a", 64)) != 401 {
		t.Fatal("expired token accepted")
	}
	grant = issue("race")
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, nonce := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		wg.Add(1)
		go func(n string) { defer wg.Done(); codes <- call(grant.Token, n) }(nonce)
	}
	wg.Wait()
	close(codes)
	var ok, conflict int
	for code := range codes {
		if code == 200 {
			ok++
		}
		if code == 409 {
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal("concurrent claims did not isolate the first installation")
	}
}
