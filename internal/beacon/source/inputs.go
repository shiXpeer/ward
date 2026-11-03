package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/netpolicy"
	"sort"
	"strings"
	"sync"
	"time"
)

// Input is a bounded local raw cache. Raw documents never enter the agent database.
type Input struct {
	Dependencies             []string // private cached discovery documents retained alongside data inputs
	Path, Digest, Kind, Link string
	Kinds                    []string
	EmptyOK                  bool
}
type cacheMeta struct {
	Digest, ETag, Modified string
	Bytes                  int64
}

func Prepare(ctx context.Context, src Source, cache string) ([]Input, error) {
	s, ok := src.(*documentSource)
	if !ok {
		return nil, errors.New("source lacks streaming adapter")
	}
	d := s.definition
	if e := os.MkdirAll(cache, 0700); e != nil {
		return nil, e
	}
	fetch := func(target string) (Input, error) { return cachedInput(ctx, d, target, cache) }
	if d.Type == "nvd-years" {
		if !strings.HasSuffix(d.URL, "/") {
			return nil, errors.New("NVD needs HTTPS directory URL")
		}
		// Downloads only: four fixed workers bound TLS/buffer memory and latency.
		// Parsing remains sequential and does not multiply decoder memory.
		years := time.Now().UTC().Year() - 2002 + 1
		out := make([]Input, years)
		errs := make([]error, years)
		workCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		jobs := make(chan int)
		var workers sync.WaitGroup
		for w := 0; w < 4; w++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for i := range jobs {
					in, e := cachedInput(workCtx, d, fmt.Sprintf("%snvdcve-2.0-%d.json.gz", d.URL, 2002+i), cache)
					if e != nil {
						errs[i] = e
						cancel()
						continue
					}
					in.Kind = "nvd-gzip"
					out[i] = in
				}
			}()
		}
		for i := 0; i < years; i++ {
			jobs <- i
		}
		close(jobs)
		workers.Wait()
		var total int64
		for i, in := range out {
			if errs[i] != nil {
				return nil, errs[i]
			}
			st, e := os.Stat(in.Path)
			if e != nil {
				return nil, e
			}
			total += st.Size()
			if total > 2<<30 {
				return nil, errors.New("NVD input aggregate exceeds bound")
			}
		}
		return out, nil
	}
	in, e := fetch(d.URL)
	if e != nil {
		return nil, e
	}
	in.Kind = d.Type
	in.Kinds = d.RecordKinds
	if d.Type != "apple-security" {
		return []Input{in}, nil
	}
	f, e := os.Open(in.Path)
	if e != nil {
		return nil, e
	}
	root, e := html.Parse(io.LimitReader(f, 4<<20))
	f.Close()
	if e != nil {
		return nil, e
	}
	base, e := url.Parse(d.URL)
	if e != nil {
		return nil, e
	}
	links := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key != "href" {
					continue
				}
				u, e := url.Parse(a.Val)
				if e != nil {
					continue
				}
				u = base.ResolveReference(u)
				u.Fragment = ""
				u.RawQuery = ""
				if u.Host == base.Host && u.Scheme == "https" && appleArticlePath.MatchString(u.Path) && u.Path != base.Path {
					links[u.String()] = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if len(links) == 0 || len(links) > 512 {
		return nil, errors.New("Apple index schema/count changed")
	}
	ordered := make([]string, 0, len(links))
	for u := range links {
		ordered = append(ordered, u)
	}
	sort.Strings(ordered)
	out := []Input{}
	for _, u := range ordered {
		a, e := fetch(u)
		if e != nil {
			return nil, e
		}
		a.Kind = "apple-article"
		a.Link = u
		a.EmptyOK = true
		out = append(out, a)
	}
	if len(out) > 0 {
		out[0].Dependencies = []string{in.Path}
	}
	return out, nil
}
func cachedInput(ctx context.Context, d Definition, target, cache string) (Input, error) {
	if d.Path != "" {
		f, e := os.Open(d.Path)
		if e != nil {
			return Input{}, e
		}
		defer f.Close()
		h := sha256.New()
		n, e := io.Copy(h, &checkedReader{ctx: ctx, r: f, left: d.MaxBytes})
		if e != nil {
			return Input{}, e
		}
		if n == 0 {
			return Input{}, errors.New("empty source")
		}
		return Input{Path: d.Path, Digest: hex.EncodeToString(h.Sum(nil))}, nil
	}
	if e := netpolicy.URL(target, d.AllowedHosts); e != nil {
		return Input{}, e
	}
	sum := sha256.Sum256([]byte(target))
	id := hex.EncodeToString(sum[:])
	data := filepath.Join(cache, id+".body")
	meta := filepath.Join(cache, id+".json")
	var old cacheMeta
	have := atomicfile.ReadJSON(meta, &old, 8192) == nil
	if st, e := os.Stat(data); e != nil || st.Size() != old.Bytes {
		have = false
	}
	c, e := netpolicy.Client(d.CAFile, d.AllowedHosts)
	if e != nil {
		return Input{}, e
	}
	defer c.CloseIdleConnections()
	c.Timeout = 20 * time.Minute
	req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
	if e != nil {
		return Input{}, e
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "shixpeer-ward-beacon (+https://shixpeer.com)")
	if have {
		if old.ETag != "" {
			req.Header.Set("If-None-Match", old.ETag)
		}
		if old.Modified != "" {
			req.Header.Set("If-Modified-Since", old.Modified)
		}
	}
	resp, e := c.Do(req)
	if e != nil {
		return Input{}, errors.New("source cache request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 && have {
		return Input{Path: data, Digest: old.Digest}, nil
	}
	if resp.StatusCode != 200 {
		return Input{}, fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	tmp, e := os.CreateTemp(cache, "input-*")
	if e != nil {
		return Input{}, e
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(tmp, h), &checkedReader{ctx: ctx, r: resp.Body, left: d.MaxBytes}, make([]byte, 32<<10))
	if e != nil {
		return Input{}, e
	}
	if n == 0 {
		return Input{}, errors.New("empty source")
	}
	if e = tmp.Sync(); e != nil {
		return Input{}, e
	}
	if e = tmp.Close(); e != nil {
		return Input{}, e
	}
	if e = os.Rename(tmp.Name(), data); e != nil {
		return Input{}, e
	}
	m := cacheMeta{hex.EncodeToString(h.Sum(nil)), resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), n}
	if e = atomicfile.JSON(meta, m); e != nil {
		return Input{}, e
	}
	return Input{Path: data, Digest: m.Digest}, nil
}
func Walk(ctx context.Context, in Input, emit func(Advisory) error) error {
	f, e := os.Open(in.Path)
	if e != nil {
		return e
	}
	defer f.Close()
	r := io.Reader(&checkedReader{ctx: ctx, r: f, left: 512 << 20})
	switch in.Kind {
	case "osv-tar-xz":
		return streamOSVTar(ctx, r, in.Kinds, emit)
	case "cve-tar-gzip", "ghsa-tar-gzip":
		return streamRepository(ctx, r, in.Kind, emit)
	case "osv-zip":
		st, e := f.Stat()
		if e != nil {
			return e
		}
		return streamZIP(ctx, f, st.Size(), emit)
	case "debian-tracker":
		return streamDebianSmall(ctx, r, emit)
	case "sofa":
		return streamSOFA(r, emit)
	case "nvd-gzip", "epss-gzip":
		r, e = gzipReader(ctx, r)
		if e != nil {
			return e
		}
		if in.Kind == "nvd-gzip" {
			e = streamNVD(ctx, r, emit)
		} else {
			e = streamEPSS(r, emit)
		}
		if e == nil {
			_, e = io.Copy(io.Discard, r)
		}
		return e
	case "apple-article":
		b, e := io.ReadAll(io.LimitReader(r, 4<<20+1))
		if e != nil {
			return e
		}
		if len(b) > 4<<20 {
			return errors.New("Apple article exceeds bound")
		}
		root, e := html.Parse(bytes.NewReader(b))
		if e != nil {
			return e
		}
		text := articleText(root)
		ids := map[string]bool{}
		for _, id := range appleCVE.FindAllString(text, -1) {
			ids[id] = true
		}
		ordered := make([]string, 0, len(ids))
		for id := range ids {
			ordered = append(ordered, id)
		}
		sort.Strings(ordered)
		for _, id := range ordered {
			if e = emit(Advisory{ID: "APPLE-" + id + ":" + in.Link[strings.LastIndex(in.Link, "/")+1:], Aliases: []string{id}, References: []string{in.Link}}); e != nil {
				return e
			}
		}
		return nil
	case "osv":
		return streamOSVDocument(r, emit)
	case "cisa-kev":
		return streamKEV(r, emit)
	}
	return fmt.Errorf("unsupported streaming source %q", in.Kind)
}
