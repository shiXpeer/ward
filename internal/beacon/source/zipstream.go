package source

import (
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strings"
)

// streamZIP walks central-directory entries one at a time, including ZIP64.
// archive/zip.NewReader would retain hundreds of thousands of file headers.
func streamZIP(ctx context.Context, r io.ReaderAt, size int64, emit func(Advisory) error) error {
	n := int64(65557)
	if n > size {
		n = size
	}
	tail := make([]byte, n)
	if _, e := r.ReadAt(tail, size-n); e != nil {
		return e
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return errors.New("ZIP end record missing")
	}
	h := tail[end:]
	if binary.LittleEndian.Uint16(h[4:6]) != 0 || binary.LittleEndian.Uint16(h[6:8]) != 0 {
		return errors.New("multi-disk ZIP unsupported")
	}
	count := uint64(binary.LittleEndian.Uint16(h[10:12]))
	off := uint64(binary.LittleEndian.Uint32(h[16:20]))
	if count == 65535 || off == 0xffffffff {
		absolute := size - n + int64(end)
		var loc [20]byte
		if _, e := r.ReadAt(loc[:], absolute-20); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(loc[:]) != 0x07064b50 {
			return errors.New("ZIP64 locator missing")
		}
		if binary.LittleEndian.Uint32(loc[4:8]) != 0 || binary.LittleEndian.Uint32(loc[16:20]) != 1 {
			return errors.New("multi-disk ZIP64 unsupported")
		}
		var z [56]byte
		if _, e := r.ReadAt(z[:], int64(binary.LittleEndian.Uint64(loc[8:16]))); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(z[:]) != 0x06064b50 {
			return errors.New("ZIP64 end missing")
		}
		if binary.LittleEndian.Uint32(z[16:20]) != 0 || binary.LittleEndian.Uint32(z[20:24]) != 0 {
			return errors.New("multi-disk ZIP64 unsupported")
		}
		count = binary.LittleEndian.Uint64(z[32:40])
		off = binary.LittleEndian.Uint64(z[48:56])
	}
	if count > 2000000 || off > uint64(size) {
		return errors.New("ZIP directory limit exceeded")
	}
	accepted := 0
	var total uint64
	for i := uint64(0); i < count; i++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		var c [46]byte
		if _, e := r.ReadAt(c[:], int64(off)); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(c[:]) != 0x02014b50 {
			return errors.New("invalid ZIP directory entry")
		}
		nameLen, extraLen, comment := uint64(binary.LittleEndian.Uint16(c[28:30])), uint64(binary.LittleEndian.Uint16(c[30:32])), uint64(binary.LittleEndian.Uint16(c[32:34]))
		name := make([]byte, nameLen)
		if _, e := r.ReadAt(name, int64(off+46)); e != nil {
			return e
		}
		extra := make([]byte, extraLen)
		if _, e := r.ReadAt(extra, int64(off+46+nameLen)); e != nil {
			return e
		}
		off += 46 + nameLen + extraLen + comment
		if !strings.HasSuffix(string(name), ".json") {
			continue
		}
		compressed, expanded, local := uint64(binary.LittleEndian.Uint32(c[20:24])), uint64(binary.LittleEndian.Uint32(c[24:28])), uint64(binary.LittleEndian.Uint32(c[42:46]))
		if compressed == 0xffffffff || expanded == 0xffffffff || local == 0xffffffff {
			found := false
			for len(extra) >= 4 {
				id, l := binary.LittleEndian.Uint16(extra[:2]), int(binary.LittleEndian.Uint16(extra[2:4]))
				extra = extra[4:]
				if l > len(extra) {
					return errors.New("invalid ZIP extra")
				}
				if id == 1 {
					v := extra[:l]
					read := func() uint64 {
						if len(v) < 8 {
							return ^uint64(0)
						}
						x := binary.LittleEndian.Uint64(v)
						v = v[8:]
						return x
					}
					if expanded == 0xffffffff {
						expanded = read()
					}
					if compressed == 0xffffffff {
						compressed = read()
					}
					if local == 0xffffffff {
						local = read()
					}
					found = true
					break
				}
				extra = extra[l:]
			}
			if !found {
				return errors.New("ZIP64 sizes missing")
			}
		}
		if binary.LittleEndian.Uint16(c[8:10])&1 != 0 || expanded > maxEntry || local > uint64(size) || compressed > uint64(size) {
			return errors.New("ZIP entry limits/encryption invalid")
		}
		total += expanded
		if total > uint64(maxStream) {
			return errors.New("ZIP expansion limit exceeded")
		}
		var lh [30]byte
		if _, e := r.ReadAt(lh[:], int64(local)); e != nil {
			return e
		}
		if binary.LittleEndian.Uint32(lh[:]) != 0x04034b50 {
			return errors.New("ZIP local header invalid")
		}
		start := local + 30 + uint64(binary.LittleEndian.Uint16(lh[26:28])) + uint64(binary.LittleEndian.Uint16(lh[28:30]))
		if start+compressed < start || start+compressed > uint64(size) {
			return errors.New("ZIP entry offset invalid")
		}
		var input io.Reader = io.NewSectionReader(r, int64(start), int64(compressed))
		method := binary.LittleEndian.Uint16(c[10:12])
		var closer io.Closer
		if method == 8 {
			fr := flate.NewReader(input)
			input = fr
			closer = fr
		} else if method != 0 {
			return errors.New("unsupported ZIP compression")
		}
		raw, e := io.ReadAll(io.LimitReader(input, maxEntry+1))
		if closer != nil {
			closer.Close()
		}
		if e != nil {
			return e
		}
		if uint64(len(raw)) != expanded || crc32.ChecksumIEEE(raw) != binary.LittleEndian.Uint32(c[16:20]) {
			return errors.New("ZIP entry size/checksum mismatch")
		}
		a, e := parseOSV(raw)
		if e != nil {
			return e
		}
		if e = emit(a); e != nil {
			return e
		}
		accepted++
	}
	if accepted == 0 {
		return errors.New("ZIP has no OSV records")
	}
	return nil
}
