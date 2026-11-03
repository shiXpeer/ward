package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"shixpeer.com/ward/internal/netpolicy"
)

var appleArticlePath = regexp.MustCompile(`^/(?:en-us/)?[0-9]{6}$`)
var appleCVE = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

// Apple publishes HTML rather than a stable bulk security schema. Discovery is
// restricted to numeric bulletin paths on the explicitly configured index host.
func (s *documentSource) syncApple(ctx context.Context) (Batch, error) {
	d := s.definition
	if d.URL == "" {
		return Batch{}, errors.New("Apple index requires an HTTPS URL")
	}
	base, e := url.Parse(d.URL)
	if e != nil {
		return Batch{}, e
	}
	c, e := netpolicy.Client(d.CAFile, d.AllowedHosts)
	if e != nil {
		return Batch{}, e
	}
	var total int64
	fetch := func(target string) ([]byte, error) {
		if e := netpolicy.URL(target, d.AllowedHosts); e != nil {
			return nil, e
		}
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("User-Agent", "shixpeer-ward-beacon (+https://shixpeer.com)")
		resp, e := c.Do(req)
		if e != nil {
			return nil, errors.New("Apple request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New("Apple returned non-200")
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
		if e != nil {
			return nil, e
		}
		total += int64(len(b))
		if len(b) > 4<<20 || total > d.MaxBytes {
			return nil, errors.New("Apple size limit exceeded")
		}
		return b, nil
	}
	b, e := fetch(d.URL)
	if e != nil {
		return Batch{}, e
	}
	root, e := html.Parse(bytes.NewReader(b))
	if e != nil {
		return Batch{}, e
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
		return Batch{}, errors.New("Apple bulletin discovery count invalid; index schema may have changed")
	}
	targets := make([]string, 0, len(links))
	for link := range links {
		targets = append(targets, link)
	}
	sort.Strings(targets)
	out := []Advisory{}
	for _, target := range targets {
		b, e = fetch(target)
		if e != nil {
			return Batch{}, e
		}
		r, e := html.Parse(bytes.NewReader(b))
		if e != nil {
			return Batch{}, e
		}
		text := articleText(r)
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
			pos := strings.Index(text, id)
			start, end := pos-1200, pos+600
			if start < 0 {
				start = 0
			}
			if end > len(text) {
				end = len(text)
			}
			raw, _ := json.Marshal(map[string]string{"bulletin_url": target, "cve": id, "context": text[start:end], "applicability": "review-vendor-bulletin", "coverage": "current-Apple-security-index"})
			out = append(out, Advisory{ID: "APPLE-" + id + ":" + target[strings.LastIndex(target, "/")+1:], Aliases: []string{id}, Summary: fmt.Sprintf("Apple security bulletin: %s", id), Raw: raw, References: []string{target}})
		}
	}
	out, e = validRows(out, nil)
	if e != nil {
		return Batch{}, e
	}
	return Batch{Full: true, Advisories: out}, nil
}
func articleText(root *html.Node) string {
	var main *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "main" || n.Data == "article") {
			if main == nil {
				main = n
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			find(c)
		}
	}
	find(root)
	if main == nil {
		main = root
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "nav") {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(main)
	return strings.Join(strings.Fields(b.String()), " ")
}
