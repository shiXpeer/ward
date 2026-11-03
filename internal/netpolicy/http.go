// Package netpolicy prevents silent TLS downgrades and unexpected destinations.
package netpolicy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func URL(raw string, hosts []string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("HTTPS URL without credentials or fragment required")
	}
	for _, h := range hosts {
		if strings.EqualFold(u.Hostname(), h) {
			return nil
		}
	}
	return errors.New("destination hostname is not allowlisted")
}
func Client(caPath string, hosts []string) (*http.Client, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if caPath != "" {
		b, e := os.ReadFile(caPath)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return URL(r.URL.String(), hosts)
	}}, nil
}
