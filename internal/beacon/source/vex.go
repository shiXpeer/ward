package source

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/ulikunitz/xz"
	"shixpeer.com/ward/internal/compactdb"
)

const VEXKind = "ubuntu-vex-tar-xz"
const VEXProjectionRevision = 1

func streamUbuntuVEX(ctx context.Context, r io.Reader, emit func(Advisory) error) error {
	xr, err := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(r)
	if err != nil {
		return err
	}
	bounded := &checkedReader{ctx: ctx, r: xr, left: 48 << 30}
	tr := tar.NewReader(bounded)
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(path.Base(h.Name), ".json")
		if h.Typeflag != tar.TypeReg || !strings.HasPrefix(h.Name, "vex/cve/") || !strings.HasSuffix(h.Name, ".json") || !cveID.MatchString(id) {
			continue
		}
		count++
		if h.Size < 1 || h.Size > 512<<20 || count > maxRecords {
			return errors.New("Ubuntu VEX archive exceeds limits")
		}
		advisory, err := parseUbuntuVEX(id, tr)
		if err != nil {
			return fmt.Errorf("Ubuntu VEX %s: %w", id, err)
		}
		if len(advisory.Affected) != 0 {
			if err := emit(advisory); err != nil {
				return err
			}
		}
	}
	if count == 0 {
		return errors.New("Ubuntu VEX archive contains no CVE documents")
	}
	_, err = io.Copy(io.Discard, bounded)
	return err
}

// walkVEXObject streams member values. Each callback consumes exactly one value.
func walkVEXObject(d *streamDecoder, field func(string) error) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("expected VEX object")
	}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid VEX member")
		}
		if err := field(key); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func walkVEXArray(d *streamDecoder, item func() error) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return errors.New("expected VEX array")
	}
	for d.More() {
		if err := item(); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func parseUbuntuVEX(id string, body io.Reader) (Advisory, error) {
	d := newStreamDecoder(body)
	a := Advisory{ID: "UBUNTU-VEX-" + id, Aliases: []string{id}}
	seen := map[string]bool{}
	skip := func() error { var ignored json.RawMessage; return d.Decode(&ignored) }
	err := walkVEXObject(d, func(field string) error {
		if field != "statements" {
			return skip()
		}
		return walkVEXArray(d, func() error {
			var name, status, justification, notes string
			var products []string
			err := walkVEXObject(d, func(field string) error {
				switch field {
				case "status":
					return d.Decode(&status)
				case "status_notes":
					return d.Decode(&notes)
				case "justification":
					return d.Decode(&justification)
				case "vulnerability":
					var v struct{ Name string }
					err := d.Decode(&v)
					name = v.Name
					return err
				case "products":
					return walkVEXArray(d, func() error {
						var p struct {
							ID string `json:"@id"`
						}
						if err := d.Decode(&p); err != nil {
							return err
						}
						if key := ubuntuVEXProduct(p.ID); key != "" {
							if len(products) >= 50000 {
								return errors.New("too many VEX source products")
							}
							products = append(products, key)
						}
						return nil
					})
				default:
					return skip()
				}
			})
			if err != nil || name != id {
				return err
			}
			switch status {
			case "affected", "fixed", "under_investigation", "not_affected":
			default:
				return nil
			}
			// A component missing in a release is not evidence about an installed source version.
			if status == "not_affected" && justification != "vulnerable_code_not_present" {
				status = "under_investigation"
			}
			// Canonical uses under_investigation for both pending triage and
			// known affected releases whose remediation was deferred.
			if status == "under_investigation" && strings.HasPrefix(notes, "This package (for the given release) is vulnerable to the CVE, the problem is understood, but it is currently deferred.") {
				status = "affected_fix_deferred"
			}
			meta, _ := json.Marshal(map[string]string{"status": status})
			for _, key := range products {
				identity := key + "\x00" + status
				if seen[identity] {
					continue
				}
				if len(seen) >= 50000 {
					return errors.New("too many VEX source statements")
				}
				seen[identity] = true
				a.Affected = append(a.Affected, Affected{Ecosystem: compactdb.UbuntuVEX, Name: key, EcosystemSpecific: meta})
			}
			return nil
		})
	})
	if err != nil {
		return Advisory{}, err
	}
	if _, err = d.Token(); err != io.EOF {
		return Advisory{}, errors.New("trailing Ubuntu VEX document data")
	}
	return a, nil
}

func ubuntuVEXProduct(raw string) string {
	body, ok := strings.CutPrefix(raw, "pkg:deb/ubuntu/")
	if !ok {
		return ""
	}
	body, query, ok := strings.Cut(body, "?")
	if !ok {
		return ""
	}
	params, err := url.ParseQuery(query)
	if err != nil || len(params) != 2 || len(params["arch"]) != 1 || params.Get("arch") != "source" || len(params["distro"]) != 1 {
		return ""
	}
	name, version, ok := strings.Cut(body, "@")
	if !ok {
		return ""
	}
	name, err = url.PathUnescape(name)
	if err != nil {
		return ""
	}
	version, err = url.PathUnescape(version)
	if err != nil {
		return ""
	}
	return compactdb.VEXProduct(name, version, params.Get("distro"))
}
