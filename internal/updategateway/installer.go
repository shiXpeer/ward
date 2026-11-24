package updategateway

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strconv"
)

func inflateMetadata(raw []byte, size int) ([]byte, error) {
	if size <= 0 || size > 4<<20 {
		return nil, errors.New("invalid metadata size")
	}
	z, e := zlib.NewReader(bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	defer z.Close()
	b, e := io.ReadAll(io.LimitReader(z, int64(size)+1))
	if e != nil || len(b) != size {
		return nil, errors.New("invalid compressed metadata")
	}
	return b, nil
}

type xarFile struct {
	Name  string    `xml:"name"`
	Files []xarFile `xml:"file"`
	Data  struct {
		Offset   int64 `xml:"offset"`
		Length   int   `xml:"length"`
		Size     int   `xml:"size"`
		Encoding struct {
			Style string `xml:"style,attr"`
		} `xml:"encoding"`
	} `xml:"data"`
}

func (s *Resolver) installerVersion(r *http.Request, q VersionQuery) (VersionReply, error) {
	found := map[string]bool{}
	read := func(raw string, start int64, size int) ([]byte, error) {
		if start < 0 || size <= 0 || size > 1<<20 {
			return nil, errors.New("invalid range")
		}
		b, e := s.gateway.metadata(r, raw, "bytes="+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(start+int64(size)-1, 10))
		if e == nil && len(b) != size {
			e = errors.New("short range")
		}
		return b, e
	}
	for _, source := range q.URLs {
		h, e := read(source, 0, 28)
		if e != nil || string(h[:4]) != "xar!" || binary.BigEndian.Uint16(h[4:6]) != 28 || binary.BigEndian.Uint16(h[6:8]) != 1 {
			continue
		}
		length, size := binary.BigEndian.Uint64(h[8:16]), binary.BigEndian.Uint64(h[16:24])
		if length == 0 || length > 1<<20 || size == 0 || size > 4<<20 {
			continue
		}
		packed, e := read(source, 28, int(length))
		if e != nil {
			continue
		}
		toc, e := inflateMetadata(packed, int(size))
		if e != nil || bytes.Contains(bytes.ToUpper(toc), []byte("<!DOCTYPE")) {
			continue
		}
		var index struct {
			Files []xarFile `xml:"toc>file"`
		}
		if !safeMetadataXML(toc) || xml.Unmarshal(toc, &index) != nil {
			continue
		}
		visited := 0
		var walk func([]xarFile, int)
		walk = func(files []xarFile, depth int) {
			if depth > 32 {
				return
			}
			for _, f := range files {
				visited++
				if visited > 4096 {
					return
				}
				if f.Name == "PackageInfo" && f.Data.Offset >= 0 && f.Data.Offset <= 1_000_000_000 && f.Data.Length > 0 && f.Data.Length <= 65536 && f.Data.Size > 0 && f.Data.Size <= 262144 {
					b, e := read(source, 28+int64(length)+f.Data.Offset, f.Data.Length)
					if e != nil {
						continue
					}
					switch f.Data.Encoding.Style {
					case "application/x-gzip":
						b, e = inflateMetadata(b, f.Data.Size)
					case "application/octet-stream":
					default:
						continue
					}
					if e != nil || !safeMetadataXML(b) {
						continue
					}
					decoder := xml.NewDecoder(bytes.NewReader(b))
					for {
						t, e := decoder.Token()
						if e != nil {
							break
						}
						if start, ok := t.(xml.StartElement); ok && start.Name.Local == "bundle" {
							id, v := "", ""
							for _, a := range start.Attr {
								if a.Name.Local == "id" {
									id = a.Value
								}
								if a.Name.Local == "CFBundleShortVersionString" {
									v = a.Value
								}
							}
							if id == q.Bundle && versionValue.MatchString(v) {
								found[v] = true
							}
						}
					}
				}
				walk(f.Files, depth+1)
			}
		}
		walk(index.Files, 0)
	}
	if len(found) != 1 {
		return VersionReply{}, errors.New("no unambiguous installer version")
	}
	for v := range found {
		return VersionReply{Version: v}, nil
	}
	panic("unreachable")
}

func safeMetadataXML(raw []byte) bool {
	if bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	tokens := 0
	for {
		v, e := d.Token()
		if e == io.EOF {
			return depth == 0
		}
		if e != nil {
			return false
		}
		tokens++
		if tokens > 100000 {
			return false
		}
		switch v.(type) {
		case xml.StartElement:
			depth++
			if depth > 64 {
				return false
			}
		case xml.EndElement:
			depth--
		}
	}
}
