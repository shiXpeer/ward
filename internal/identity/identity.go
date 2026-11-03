// Package identity separates transport identity (TLS) from offline data signing.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func writeNew(path string, body []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(body)
	if e != nil {
		f.Close()
		return e
	}
	return f.Close()
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func privatePEM(k ed25519.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func Init(dir string, hosts []string, now time.Time) error {
	if len(hosts) == 0 {
		return errors.New("at least one TLS hostname/IP is required")
	}
	// A dedicated new directory avoids accidental key replacement and partial reuse.
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	capub, cakey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Shixpeer Ward private CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cader, e := x509.CreateCertificate(rand.Reader, ca, ca, capub, cakey)
	if e != nil {
		return e
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Shixpeer Ward Beacon"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else if h != "" {
			cert.DNSNames = append(cert.DNSNames, h)
		} else {
			return errors.New("empty TLS hostname")
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, pub, cakey)
	if e != nil {
		return e
	}
	signpub, signkey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	pubder, e := x509.MarshalPKIXPublicKey(signpub)
	if e != nil {
		return e
	}
	for name, k := range map[string]ed25519.PrivateKey{"ca.key": cakey, "server.key": key, "signing.key": signkey} {
		b, e := privatePEM(k)
		if e != nil {
			return e
		}
		if e = writeNew(filepath.Join(dir, name), b, 0600); e != nil {
			return e
		}
	}
	for name, b := range map[string][]byte{"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cader}), "server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "feed.pub": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubder})} {
		if e = writeNew(filepath.Join(dir, name), b, 0644); e != nil {
			return e
		}
	}
	success = true
	return nil
}
func Private(path string) (ed25519.PrivateKey, error) {
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key must not be accessible to group/others")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid private key PEM")
	}
	v, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := v.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Ed25519 signing key required")
	}
	return k, nil
}
func Public(path string) (ed25519.PublicKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("invalid public key PEM")
	}
	v, e := x509.ParsePKIXPublicKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	k, ok := v.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Ed25519 public key required")
	}
	return k, nil
}
