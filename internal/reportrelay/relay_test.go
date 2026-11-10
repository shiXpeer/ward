package reportrelay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRelayStoresCiphertextAndSeparatesCredentials(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"private":"local inventory"}`)
	sealed, err := Seal(key.PublicKey().Bytes(), plain, "web")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	reader, writer, other := strings.Repeat("r", 32), strings.Repeat("w", 32), strings.Repeat("x", 32)
	handler, err := (Config{Reader: reader, Writers: map[string]string{"web": writer, "db": other}}).Handler(dir)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string, data []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		method, path, token string
		data                []byte
		code                int
	}{
		{http.MethodPut, "/v1/reports/db", writer, sealed, 401},
		{http.MethodPut, "/v1/reports/web", reader, sealed, 401},
		{http.MethodPut, "/v1/reports/web", writer, plain, 400},
		{http.MethodPut, "/v1/reports/web", writer, sealed, 204},
		{http.MethodGet, "/v1/reports/web", writer, nil, 401},
		{http.MethodGet, "/v1/reports/web", reader, nil, 200},
	} {
		result := request(tc.method, tc.path, tc.token, tc.data)
		if result.Code != tc.code {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, result.Code, tc.code)
		}
		if tc.code == 200 && !bytes.Equal(result.Body.Bytes(), sealed) {
			t.Fatal("download differs from encrypted envelope")
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "web.sealed"))
	if err != nil || !bytes.Equal(data, sealed) || bytes.Contains(data, plain) {
		t.Fatal("relay did not persist ciphertext")
	}
}
