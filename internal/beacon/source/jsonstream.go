package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

func streamOSVDocument(r io.Reader, emit func(Advisory) error) error {
	d := newStreamDecoder(r)
	first, e := d.Token()
	if e != nil {
		return e
	}
	count := 0
	one := func(raw json.RawMessage) error {
		if len(raw) > maxEntry {
			return errors.New("OSV record exceeds limit")
		}
		a, e := parseOSV(raw)
		if e != nil {
			return e
		}
		count++
		if count > maxRecords {
			return errors.New("OSV count exceeds bound")
		}
		return emit(a)
	}
	array := func() error {
		for d.More() {
			var raw json.RawMessage
			if e := d.Decode(&raw); e != nil {
				return e
			}
			if e := one(raw); e != nil {
				return e
			}
		}
		_, e := d.Token()
		return e
	}
	if first == json.Delim('[') {
		if e = array(); e != nil {
			return e
		}
	} else if first == json.Delim('{') {
		obj := map[string]json.RawMessage{}
		wrapper := false
		aggregate := 0
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name := key.(string)
			if name == "vulns" {
				t, e := d.Token()
				if e != nil || t != json.Delim('[') {
					return errors.New("invalid OSV array")
				}
				if e = array(); e != nil {
					return e
				}
				wrapper = true
			} else {
				var raw json.RawMessage
				if e = d.Decode(&raw); e != nil {
					return e
				}
				if len(raw) > maxEntry {
					return errors.New("OSV field exceeds limit")
				}
				aggregate += len(raw) + len(name)
				if aggregate > maxEntry {
					return errors.New("OSV object exceeds limit")
				}
				obj[name] = raw
			}
		}
		if _, e = d.Token(); e != nil {
			return e
		}
		if !wrapper {
			b, e := json.Marshal(obj)
			if e != nil {
				return e
			}
			if e = one(b); e != nil {
				return e
			}
		}
	} else {
		return errors.New("invalid OSV document")
	}
	return finishJSON(d)
}
func streamKEV(r io.Reader, emit func(Advisory) error) error {
	d := newStreamDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("invalid KEV document")
	}
	count := 0
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return e
		}
		if key != "vulnerabilities" {
			var skip json.RawMessage
			if e = d.Decode(&skip); e != nil {
				return e
			}
			continue
		}
		t, e = d.Token()
		if e != nil || t != json.Delim('[') {
			return errors.New("invalid KEV array")
		}
		for d.More() {
			var raw json.RawMessage
			if e = d.Decode(&raw); e != nil {
				return e
			}
			if len(raw) > maxEntry {
				return errors.New("KEV entry too large")
			}
			b := append([]byte(`{"vulnerabilities":[`), raw...)
			b = append(b, ']', '}')
			a, e := parseKEV(b)
			if e != nil {
				return e
			}
			if e = emit(a[0]); e != nil {
				return e
			}
			count++
			if count > maxRecords {
				return errors.New("KEV count too large")
			}
		}
		if _, e = d.Token(); e != nil {
			return e
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	if e = finishJSON(d); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("KEV contains no records")
	}
	return nil
}
func streamDebianSmall(ctx context.Context, r io.Reader, emit func(Advisory) error) error {
	d := newStreamDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("invalid Debian object")
	}
	count := 0
	for d.More() {
		pkg, e := d.Token()
		if e != nil {
			return e
		}
		t, e = d.Token()
		if e != nil || t != json.Delim('{') {
			return errors.New("invalid Debian package")
		}
		for d.More() {
			if e = ctx.Err(); e != nil {
				return e
			}
			id, e := d.Token()
			if e != nil {
				return e
			}
			var raw json.RawMessage
			if e = d.Decode(&raw); e != nil {
				return e
			}
			if !cveID.MatchString(id.(string)) {
				continue
			}
			if len(raw) > maxEntry {
				return errors.New("Debian row exceeds bound")
			}
			b, e := json.Marshal(map[string]any{pkg.(string): map[string]json.RawMessage{id.(string): raw}})
			if e != nil {
				return e
			}
			a, e := parseDebian(ctx, bytes.NewReader(b))
			if e != nil {
				return e
			}
			if e = emit(a[0]); e != nil {
				return e
			}
			count++
			if count > maxRecords {
				return errors.New("Debian count exceeds bound")
			}
		}
		if _, e = d.Token(); e != nil {
			return e
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	if e = finishJSON(d); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("Debian contains no records")
	}
	return nil
}

// Reset per decoded value. Decoder read-ahead is bounded by the same limit;
// at most one previous buffer and one new value can be resident.
type valueReader struct {
	r    io.Reader
	left int
}

func (r *valueReader) Read(b []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("JSON value exceeds decoding budget")
	}
	if len(b) > r.left {
		b = b[:r.left]
	}
	n, e := r.r.Read(b)
	r.left -= n
	return n, e
}

type streamDecoder struct {
	*json.Decoder
	r *valueReader
}

func newStreamDecoder(r io.Reader) *streamDecoder {
	v := &valueReader{r: r, left: maxEntry}
	return &streamDecoder{json.NewDecoder(v), v}
}
func (d *streamDecoder) Decode(v any) error         { d.r.left = maxEntry; return d.Decoder.Decode(v) }
func (d *streamDecoder) Token() (json.Token, error) { d.r.left = maxEntry; return d.Decoder.Token() }
