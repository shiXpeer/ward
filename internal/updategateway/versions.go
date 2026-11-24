package updategateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type VersionQuery struct {
	Bundle       string   `json:"bundle_id"`
	Architecture string   `json:"architecture"`
	Channel      string   `json:"channel,omitempty"`
	URL          string   `json:"url,omitempty"`
	URLs         []string `json:"urls,omitempty"`
	Code         string   `json:"code,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Name         string   `json:"name,omitempty"`
	Quality      string   `json:"quality,omitempty"`
}
type VersionReply struct {
	Version     string `json:"version"`
	Installable bool   `json:"installable"`
}

func (g *Gateway) metadata(r *http.Request, raw, interval string) ([]byte, error) {
	body, _ := json.Marshal(Request{URL: raw, Range: interval})
	out := &metadataResponse{header: http.Header{}, Code: 200}
	req, _ := http.NewRequestWithContext(r.Context(), "POST", "/", bytes.NewReader(body))
	g.ServeHTTP(out, req)
	if out.Code != 200 && out.Code != 206 {
		return nil, errors.New("metadata unavailable")
	}
	return out.Body.Bytes(), nil
}
func safeArchive(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && validURL(u) && (strings.HasSuffix(strings.ToLower(u.Path), ".zip") || strings.HasSuffix(strings.ToLower(u.Path), ".dmg"))
}
func newest(values []string) (string, error) {
	best := ""
	for _, v := range values {
		v = normalizedVersion(v)
		if !versionValue.MatchString(v) {
			continue
		}
		if best == "" || compareVersion(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		return "", errors.New("no comparable version")
	}
	return best, nil
}

var versionTokens = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)

func compareVersion(a, b string) int {
	x, y := versionTokens.FindAllString(a, -1), versionTokens.FindAllString(b, -1)
	for i := 0; i < len(x) || i < len(y); i++ {
		u, v := "0", "0"
		if i < len(x) {
			u = x[i]
		}
		if i < len(y) {
			v = y[i]
		}
		un, ue := strconv.ParseUint(u, 10, 64)
		vn, ve := strconv.ParseUint(v, 10, 64)
		if ue == nil && ve == nil {
			if un > vn {
				return 1
			}
			if un < vn {
				return -1
			}
		} else if u != v {
			return strings.Compare(u, v)
		}
	}
	return 0
}
func (s *Resolver) resolve(r *http.Request, q VersionQuery) (VersionReply, error) {
	var rule *VersionRule
	for i := range s.rules {
		x := &s.rules[i]
		if x.Bundle == q.Bundle && (x.Architecture == "" || x.Architecture == q.Architecture) {
			if rule == nil || x.Architecture != "" {
				rule = x
			}
		}
	}
	if rule != nil {
		raw, e := s.gateway.metadata(r, rule.URL, "")
		if e != nil {
			return VersionReply{}, e
		}
		v, e := extractVersion(raw, *rule)
		return VersionReply{Version: v}, e
	}
	fetch := func(raw string) ([]byte, error) { return s.gateway.metadata(r, raw, "") }
	switch q.Channel {
	case "app_store":
		raw, e := fetch("https://itunes.apple.com/lookup?bundleId=" + url.QueryEscape(q.Bundle))
		if e != nil {
			return VersionReply{}, e
		}
		var d struct {
			Results []struct {
				Bundle  string `json:"bundleId"`
				Version string `json:"version"`
			}
		}
		if json.Unmarshal(raw, &d) != nil {
			return VersionReply{}, errors.New("invalid lookup")
		}
		for _, v := range d.Results {
			if v.Bundle == q.Bundle && versionValue.MatchString(v.Version) {
				return VersionReply{Version: v.Version}, nil
			}
		}
	case "jetbrains":
		if !regexp.MustCompile(`^[A-Z0-9]{2,12}$`).MatchString(q.Code) {
			break
		}
		raw, e := fetch("https://data.services.jetbrains.com/products/releases?code=" + q.Code + "&type=release&latest=true")
		if e != nil {
			return VersionReply{}, e
		}
		var d map[string][]struct {
			Version   string
			Type      string
			Downloads map[string]struct {
				Link string
				Size int64
			}
		}
		if json.Unmarshal(raw, &d) != nil {
			break
		}
		versions := []string{}
		install := map[string]bool{}
		platform := "mac"
		if q.Architecture == "arm64" {
			platform = "macM1"
		}
		for _, v := range d[q.Code] {
			if v.Type == "release" {
				versions = append(versions, v.Version)
				a := v.Downloads[platform]
				install[v.Version] = safeArchive(a.Link) && a.Size > 0 && a.Size <= 4<<30
			}
		}
		v, e := newest(versions)
		return VersionReply{Version: v, Installable: install[v]}, e
	case "docker":
		arch := "amd64"
		if q.Architecture == "arm64" {
			arch = "arm64"
		}
		raw, e := fetch("https://desktop.docker.com/mac/main/" + arch + "/appcast.json")
		if e != nil {
			return VersionReply{}, e
		}
		var d struct {
			Items []struct {
				AppVersion string
				Visibility json.RawMessage
			}
		}
		if json.Unmarshal(raw, &d) != nil {
			break
		}
		versions := []string{}
		for _, v := range d.Items {
			n, _ := strconv.ParseFloat(strings.Trim(string(v.Visibility), `"`), 64)
			if n > 0 {
				versions = append(versions, v.AppVersion)
			}
		}
		v, e := newest(versions)
		return VersionReply{Version: v}, e
	case "vscode":
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(q.Platform) || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`).MatchString(q.Quality) {
			break
		}
		u, e := url.Parse(q.URL)
		if e != nil || !validURL(u) {
			break
		}
		if !regexp.MustCompile(`^[a-z0-9-]{1,40}$`).MatchString(q.Name) {
			break
		}
		u.Path = strings.TrimRight(u.Path, "/") + "/api/update/" + q.Platform + "/" + q.Name + "/0.0.0/shixpeer-ward/" + q.Quality
		u.RawQuery = ""
		raw, e := fetch(u.String())
		if e != nil {
			return VersionReply{}, e
		}
		var d struct{ Name, URL string }
		if json.Unmarshal(raw, &d) != nil || !versionValue.MatchString(d.Name) {
			break
		}
		return VersionReply{Version: d.Name, Installable: safeArchive(d.URL)}, nil
	case "plain":
		raw, e := fetch(q.URL)
		if e != nil {
			return VersionReply{}, e
		}
		tokens := strings.Fields(string(raw))
		if len(tokens) > 0 && versionValue.MatchString(tokens[0]) {
			return VersionReply{Version: tokens[0]}, nil
		}
	case "electron":
		u, e := url.Parse(q.URL)
		if e != nil || !validURL(u) {
			break
		}
		if !strings.HasSuffix(u.Path, ".yml") && !strings.HasSuffix(u.Path, ".yaml") {
			u.Path = strings.TrimRight(u.Path, "/") + "/latest-mac.yml"
		}
		raw, e := fetch(u.String())
		if e != nil {
			return VersionReply{}, e
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if ok {
				fields[k] = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
		if !versionValue.MatchString(fields["version"]) {
			break
		}
		a, e := url.Parse(fields["path"])
		install := e == nil && fields["path"] != "" && safeArchive(u.ResolveReference(a).String())
		if sha := fields["sha512"]; sha != "" {
			b, e := base64.StdEncoding.DecodeString(sha)
			if e != nil || len(b) != 64 {
				return VersionReply{}, errors.New("invalid checksum")
			}
		}
		return VersionReply{Version: fields["version"], Installable: install}, nil
	case "sparkle", "product_xml":
		raw, e := fetch(q.URL)
		if e != nil {
			return VersionReply{}, e
		}
		return xmlVersion(raw, q.Channel)
	case "installer_metadata":
		return s.installerVersion(r, q)
	case "":
		return VersionReply{}, nil
	}
	return VersionReply{}, errors.New("no supported version metadata")
}
func xmlVersion(raw []byte, channel string) (VersionReply, error) {
	if bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) {
		return VersionReply{}, errors.New("XML declarations denied")
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	versions := []string{}
	install := map[string]bool{}
	current, short := "", ""
	archive := false
	field := ""
	text := ""
	for {
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return VersionReply{}, e
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 64 {
				return VersionReply{}, errors.New("XML too deep")
			}
			field = t.Name.Local
			text = ""
			if field == "item" {
				current = ""
				short = ""
				archive = false
			}
			if field == "enclosure" {
				var link, signature string
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "url":
						link = a.Value
					case "edSignature":
						signature = a.Value
					case "shortVersionString":
						short = a.Value
					case "version":
						current = a.Value
					}
				}
				sig, e := base64.StdEncoding.DecodeString(signature)
				archive = safeArchive(link) && e == nil && len(sig) == 64
			}
		case xml.CharData:
			if field == "shortVersionString" || field == "version" || field == "number" {
				text += string(t)
			}
			if len(text) > 4096 {
				return VersionReply{}, errors.New("XML field exceeds limit")
			}
		case xml.EndElement:
			value := strings.TrimSpace(text)
			if channel == "product_xml" && t.Name.Local == "number" && versionValue.MatchString(value) {
				versions = append(versions, value)
			}
			if channel == "sparkle" {
				switch t.Name.Local {
				case "shortVersionString":
					short = value
				case "version":
					if versionValue.MatchString(value) {
						current = value
					}
				case "item":
					v := normalizedVersion(short)
					if v == "" {
						v = current
					}
					versions = append(versions, v)
					install[v] = archive
				}
			}
			depth--
			field = ""
			text = ""
		}
	}
	v, e := newest(versions)
	return VersionReply{Version: v, Installable: install[v]}, e
}

var displayBuild = regexp.MustCompile(`^([0-9][A-Za-z0-9.+_-]{0,79})\s*\([0-9]+\)$`)

func normalizedVersion(v string) string {
	v = strings.TrimSpace(v)
	if m := displayBuild.FindStringSubmatch(v); len(m) == 2 {
		return m[1]
	}
	return v
}
