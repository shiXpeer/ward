package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ulikunitz/xz"
)

func TestCanonicalTarLimitsAndCorruption(t *testing.T) {
	var b bytes.Buffer
	x, e := xz.NewWriter(&b)
	if e != nil {
		t.Fatal(e)
	}
	tr := tar.NewWriter(x)
	if e = tr.WriteHeader(&tar.Header{Name: "../../advisory.json", Mode: 0600, Size: int64(len(testOSV))}); e != nil {
		t.Fatal(e)
	}
	tr.Write([]byte(testOSV))
	tr.Close()
	x.Close()
	rows, e := parseOSVTar(context.Background(), bytes.NewReader(b.Bytes()))
	if e != nil || len(rows) != 1 || rows[0].Affected[0].Ecosystem != "Ubuntu:24.04:LTS" {
		t.Fatal(rows, e)
	}
	corrupted := append([]byte(nil), b.Bytes()...)
	corrupted[len(corrupted)-8] ^= 1
	if _, e = parseOSVTar(context.Background(), bytes.NewReader(corrupted)); e == nil {
		t.Fatal("accepted damaged xz footer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = parseOSVTar(ctx, bytes.NewReader(b.Bytes())); e == nil {
		t.Fatal("ignored cancellation")
	}
	r := &checkedReader{ctx: context.Background(), r: strings.NewReader("1234"), left: 3}
	if _, e = io.ReadAll(r); e == nil {
		t.Fatal("accepted expansion overflow")
	}
}
func TestDebianPreservesReleaseStatusAndNotAffected(t *testing.T) {
	raw := `{"openssl":{"CVE-2026-1234":{"description":"fixture","releases":{"bookworm":{"status":"resolved","fixed_version":"0","urgency":"unimportant"},"trixie":{"status":"resolved","fixed_version":"1:3.0-1+deb13u1","nodsa":"minor issue"}}}}}`
	a, e := parseDebian(context.Background(), strings.NewReader(raw))
	if e != nil || len(a) != 1 {
		t.Fatal(a, e)
	}
	if len(a[0].Affected[0].Ranges) != 0 || a[0].Affected[1].Ranges[0].Events[1].Fixed != "1:3.0-1+deb13u1" || !bytes.Contains(a[0].Raw, []byte("nodsa")) {
		t.Fatal("lost distro semantics")
	}
	if !a[0].Modified.IsZero() {
		t.Fatal("invented modified date")
	}
	if _, e = parseDebian(context.Background(), strings.NewReader(raw+`{}`)); e == nil {
		t.Fatal("accepted trailing JSON")
	}
}
func TestSOFADoesNotInferAllOlderBranchesAffected(t *testing.T) {
	a, e := parseSOFA(strings.NewReader(`{"OSVersions":[{"OSVersion":"Test 15","SecurityReleases":[{"ProductVersion":"15.3","Build":"24D1","ReleaseDate":"2026-01-02T00:00:00Z","SecurityInfo":"https://support.apple.com/en-us/123456","CVEs":{"CVE-2026-1234":true}}]}]}`))
	if e != nil || len(a) != 1 {
		t.Fatal(a, e)
	}
	if a[0].KnownExploited || len(a[0].Affected[0].Ranges) != 0 || !bytes.Contains(a[0].Affected[0].EcosystemSpecific, []byte("15.3")) {
		t.Fatal("invented applicability/exploitation verdict")
	}
	if _, e = parseSOFA(strings.NewReader(`{"different_schema":[]}`)); e == nil {
		t.Fatal("accepted schema drift")
	}
}
func TestEPSSMetadataAndInvalidNumbers(t *testing.T) {
	prefix := "#model_version:v1,score_date:2026-10-29T12:03:14Z\ncve,epss,percentile\n"
	a, e := parseEPSS(strings.NewReader(prefix + "CVE-2026-1234,0.8,0.99\n"))
	if e != nil || len(a) != 1 || a[0].Modified.IsZero() || a[0].KnownExploited {
		t.Fatal(a, e)
	}
	for _, row := range []string{"CVE-2026-1234,NaN,0.9\n", "CVE-2026-1234,1.1,0.9\n", "garbage,0.1,0.9\n", "CVE-2026-1234,0.1,0.9\nCVE-2026-1234,0.1,0.9\n"} {
		if _, e = parseEPSS(strings.NewReader(prefix + row)); e == nil {
			t.Fatal("accepted invalid EPSS", row)
		}
	}
}
func TestNVDKeepsCPELogicAndRejection(t *testing.T) {
	raw := `{"vulnerabilities":[{"cve":{"id":"CVE-2026-1234","published":"2026-01-01T00:00:00.000","lastModified":"2026-01-02T00:00:00.000","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"fixture"}],"configurations":[{"operator":"AND","nodes":[]}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"CRITICAL"}}]}}}]}`
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	g.Write([]byte(raw))
	g.Close()
	r, e := gzipReader(context.Background(), &b)
	if e != nil {
		t.Fatal(e)
	}
	a, e := parseNVD(context.Background(), r)
	if e != nil || len(a) != 1 {
		t.Fatal(a, e)
	}
	if !a[0].Withdrawn || a[0].Severity != "CRITICAL" || len(a[0].Affected) != 0 || !bytes.Contains(a[0].Raw, []byte(`"operator":"AND"`)) {
		t.Fatal("lost NVD semantics")
	}
	if _, e = parseNVD(context.Background(), strings.NewReader(`{"resultsPerPage":10}`)); e == nil {
		t.Fatal("accepted absent array")
	}
}

func TestAppleOnlyFetchesSameHostBulletins(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/en-us/100100", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<main><a href="/en-us/123456">release</a><a href="https://other.invalid/en-us/654321">ignore</a><a href="/download.sh">ignore</a></main>`)
	})
	mux.HandleFunc("/en-us/123456", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<main>Kernel impact fixture CVE-2026-1234<script>CVE-2026-9999</script></main>`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	der := srv.Certificate().Raw
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(path, cert, 0600)
	u, _ := url.Parse(srv.URL)
	s := &documentSource{definition: Definition{ID: "apple", Type: "apple-security", URL: srv.URL + "/en-us/100100", CAFile: path, AllowedHosts: []string{u.Hostname()}, MaxBytes: 1 << 20}}
	b, e := s.Sync(context.Background(), "")
	if e != nil || len(b.Advisories) != 1 || b.Advisories[0].Aliases[0] != "CVE-2026-1234" {
		t.Fatal(b, e)
	}
}

func TestCVERepositorySkipsMetadataAndKeepsRejected(t *testing.T) {
	raw := `{"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2026-1234","state":"REJECTED","dateUpdated":"2026-01-02T00:00:00Z"},"containers":{"cna":{"title":"withdrawn","affected":[{"vendor":"fixture","product":"fixture"}]}}}`
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	tr := tar.NewWriter(g)
	for name, body := range map[string]string{"repo/cves/deltaLog.json": "{}", "repo/cves/2026/1xxx/CVE-2026-1234.json": raw} {
		tr.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body))})
		tr.Write([]byte(body))
	}
	tr.Close()
	g.Close()
	a, e := parseRepository(context.Background(), &b, "cve-tar-gzip")
	if e != nil || len(a) != 1 || !a[0].Withdrawn || !bytes.Contains(a[0].Raw, []byte(`"vendor":"fixture"`)) {
		t.Fatal(a, e)
	}
}

func TestOSVOptionalPackageRetainsUnmappedGitEvidence(t *testing.T) {
	a, e := parseOSV([]byte(`{"id":"OSV-GIT-1","modified":"2026-01-02T00:00:00Z","affected":[{"ranges":[{"type":"GIT","repo":"https://example.org/repo","events":[{"introduced":"0"},{"fixed":"abcdef"}]}]}]}`))
	if e != nil || a.UnmappedAffected != 1 || len(a.Affected) != 0 || !bytes.Contains(a.Raw, []byte("abcdef")) {
		t.Fatal(a, e)
	}
}

func TestCanonicalUpstreamAliasesAndSelection(t *testing.T) {
	a, e := parseOSV([]byte(`{"id":"UBUNTU-CVE-2026-1234","upstream":["CVE-2026-1234"],"modified":"2026-01-02T00:00:00Z"}`))
	if e != nil || len(a.Aliases) != 1 || a.Aliases[0] != "CVE-2026-1234" {
		t.Fatal(a, e)
	}
	var b bytes.Buffer
	x, _ := xz.NewWriter(&b)
	tr := tar.NewWriter(x)
	for _, name := range []string{"osv/cve/2026/fixture.json", "osv/usn/fixture.json"} {
		tr.WriteHeader(&tar.Header{Name: name, Size: int64(len(testOSV)), Mode: 0600})
		tr.Write([]byte(testOSV))
	}
	tr.Close()
	x.Close()
	rows, e := parseOSVTarKinds(context.Background(), bytes.NewReader(b.Bytes()), []string{"cve"})
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
}
func TestShippedProfilesLoadWithoutNetwork(t *testing.T) {
	for _, name := range []string{"beacon.default.json", "beacon.extended.json", "beacon.quickstart.json", "beacon.nvd.json", "beacon.repositories.json"} {
		sources, e := Load(filepath.Join("..", "..", "..", "configs", name))
		if e != nil || len(sources) == 0 {
			t.Fatal(name, e)
		}
	}
}

func TestNVDAnnualBootstrapFailsAsAWhole(t *testing.T) {
	var fail atomic.Bool
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/nvdcve-2.0-")
		year, e := strconv.Atoi(strings.TrimSuffix(name, ".json.gz"))
		if e != nil {
			http.NotFound(w, r)
			return
		}
		if fail.Load() && year == 2003 {
			http.Error(w, "unavailable", 503)
			return
		}
		g := gzip.NewWriter(w)
		fmt.Fprintf(g, `{"vulnerabilities":[{"cve":{"id":"CVE-%d-1234","lastModified":"2026-01-02T00:00:00Z"}}]}`, year)
		g.Close()
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
	u, _ := url.Parse(srv.URL)
	src := &documentSource{definition: Definition{ID: "nvd", Type: "nvd-years", URL: srv.URL + "/", CAFile: path, AllowedHosts: []string{u.Hostname()}, MaxBytes: 1 << 20}}
	batch, e := src.Sync(context.Background(), "")
	if e != nil || len(batch.Advisories) != time.Now().UTC().Year()-2002+1 {
		t.Fatal(len(batch.Advisories), e)
	}
	fail.Store(true)
	batch, e = src.Sync(context.Background(), "")
	if e == nil || len(batch.Advisories) != 0 {
		t.Fatal("accepted partial annual history", e)
	}
}
