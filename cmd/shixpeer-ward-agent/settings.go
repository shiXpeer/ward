package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/paths"
)

// Settings contain only local download policy, never host inventory or private keys.
type settings struct {
	Version int      `json:"version"`
	State   string   `json:"state"`
	URL     string   `json:"feed_url"`
	Key     []byte   `json:"trusted_public_key"`
	CA      string   `json:"ca_file,omitempty"`
	Hosts   []string `json:"allow_hosts,omitempty"`
}

func loadSettings(path string) (settings, error) {
	var s settings
	err := atomicfile.ReadJSON(path, &s, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		if path == paths.Config("agent") {
			if _, legacyErr := os.Stat(paths.LegacyConfig()); legacyErr == nil {
				return s, errors.New("legacy agent settings found; run shixpeer-ward-agent migrate-home before using the new home directory (preserves trust and rollback state)")
			}
		}
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("read settings: %w", err)
	}
	if s.Version != 1 || len(s.Key) != ed25519.PublicKeySize || !filepath.IsAbs(s.State) {
		return s, errors.New("invalid agent settings")
	}
	return s, nil
}
func saveSettings(path, state, raw string, key ed25519.PublicKey, ca, allow string) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("first setup requires a trusted publisher public key (-trusted-key feed.pub); signature verification cannot be disabled")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if err = netpolicy.URL(raw, []string{u.Hostname()}); err != nil {
		return err
	}
	hosts := strings.FieldsFunc(allow, func(r rune) bool { return r == ',' })
	// Constructing the client validates the CA locally; setup makes no requests.
	c, err := netpolicy.Client(ca, hosts)
	if err != nil {
		return err
	}
	c.CloseIdleConnections()
	state, err = filepath.Abs(state)
	if err != nil {
		return err
	}
	if ca != "" {
		ca, err = filepath.Abs(ca)
		if err != nil {
			return err
		}
	}
	if ca != "" && path == paths.Config("agent") {
		raw, err := os.ReadFile(ca)
		if err != nil {
			return err
		}
		if len(raw) > 1<<20 {
			return errors.New("CA exceeds size limit")
		}
		ca = filepath.Join(paths.Root(), "config", "agent-ca.crt")
		if err = atomicfile.Write(ca, raw, 0600); err != nil {
			return err
		}
	}
	// Embed the public signing key so its provisioning file can be removed.
	s := settings{Version: 1, State: state, URL: raw, Key: key, CA: ca, Hosts: hosts}
	if err = atomicfile.JSON(path, s); err != nil {
		return err
	}
	fmt.Println("Saved download settings:", path)
	return nil
}
