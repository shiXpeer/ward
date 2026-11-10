package compactdb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const HeaderSize = 40
const BlockBytes = 64 << 10
const MaxBlock = MaxValue + 40
const IndexSize = 48

var magic = [8]byte{'W', 'A', 'R', 'D', 'D', 'B', '0', '3'}

type Item struct {
	Hash  [32]byte
	Value []byte
}

func WriteItem(w io.Writer, it Item) error {
	if len(it.Value) > MaxValue {
		return errors.New("compact value exceeds bound")
	}
	var h [36]byte
	copy(h[:32], it.Hash[:])
	binary.LittleEndian.PutUint32(h[32:], uint32(len(it.Value)))
	if _, e := w.Write(h[:]); e != nil {
		return e
	}
	_, e := w.Write(it.Value)
	return e
}
func ReadItem(r io.Reader) (Item, error) {
	var it Item
	var h [36]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return it, e
	}
	copy(it.Hash[:], h[:32])
	n := binary.LittleEndian.Uint32(h[32:])
	if n > MaxValue {
		return it, errors.New("invalid frame size")
	}
	it.Value = make([]byte, n)
	_, e := io.ReadFull(r, it.Value)
	return it, e
}
func less(a, b Item) bool {
	if n := bytes.Compare(a.Hash[:], b.Hash[:]); n != 0 {
		return n < 0
	}
	return bytes.Compare(a.Value, b.Value) < 0
}

type Builder struct {
	dir     string
	writers map[string]*spoolWriter
	order   []string
}

func NewBuilder(dir string) (*Builder, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	return &Builder{dir: dir, writers: map[string]*spoolWriter{}}, nil
}
func (b *Builder) Put(group, key string, value []byte) error {
	return b.PutHash(Slot(group, key), Item{KeyHash(group, key), value})
}
func (b *Builder) PutHash(slot string, it Item) error {
	if !ValidSlot(slot) {
		return errors.New("invalid bucket")
	}
	slot = slot[:3]
	f := b.writers[slot]
	if f == nil {
		if len(b.writers) >= 64 {
			old := b.order[0]
			b.order = b.order[1:]
			if e := b.writers[old].Close(); e != nil {
				return e
			}
			delete(b.writers, old)
		}
		var e error
		var disk *os.File
		disk, e = os.OpenFile(filepath.Join(b.dir, slot+".stage"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e == nil {
			f = &spoolWriter{f: disk, w: bufio.NewWriterSize(disk, 32<<10)}
		}
		if e != nil {
			return e
		}
		b.writers[slot] = f
		b.order = append(b.order, slot)
	}
	return WriteItem(f.w, it)
}
func (b *Builder) Close() error {
	var err error
	for k, f := range b.writers {
		if e := f.Close(); e != nil {
			err = e
		}
		delete(b.writers, k)
	}
	b.order = nil
	return err
}

type Bucket struct {
	Slot        string `json:"slot"`
	Path        string `json:"-"`
	Rows        int64  `json:"rows"`
	Bytes       int64  `json:"bytes"`
	InputDigest string `json:"input_digest,omitempty"`
}

func ValidSlot(s string) bool {
	if len(s) != 4 || s[1] != '-' || !bytes.ContainsRune([]byte("pvrs"), rune(s[0])) {
		return false
	}
	if s[0] == 's' && s[2] > '7' {
		return false
	}
	for _, c := range s[2:] {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
func (b *Builder) Finish(ctx context.Context, out string) ([]Bucket, error) {
	buckets, _, err := b.FinishIncremental(ctx, out, nil)
	return buckets, err
}

// FinishIncremental compares complete per-shard inputs. Deleted rows change
// the digest, and an empty shard has no spool and is omitted entirely.
func (b *Builder) FinishIncremental(ctx context.Context, out string, previous []Bucket) ([]Bucket, int, error) {
	if e := b.Close(); e != nil {
		return nil, 0, e
	}
	if e := os.MkdirAll(out, 0700); e != nil {
		return nil, 0, e
	}
	if e := partition(ctx, b.dir); e != nil {
		return nil, 0, e
	}
	files, e := filepath.Glob(filepath.Join(b.dir, "*.spool"))
	if e != nil {
		return nil, 0, e
	}
	old := map[string]Bucket{}
	for _, bucket := range previous {
		old[bucket.Slot] = bucket
	}
	var result []Bucket
	reused := 0
	buf := make([]byte, 128<<10)
	for _, p := range files {
		slot := filepath.Base(p)[:4]
		dest := filepath.Join(out, slot+".wdb")
		digest, err := spoolDigest(ctx, p, buf)
		if err != nil {
			return nil, 0, err
		}
		bucket := old[slot]
		if bucket.InputDigest == digest && reuseBucket(bucket, dest) {
			reused++
			bucket.Path = dest
		} else {
			n, err := sortBucket(ctx, p, dest, b.dir)
			if err != nil {
				return nil, 0, err
			}
			st, err := os.Stat(dest)
			if err != nil {
				return nil, 0, err
			}
			bucket = Bucket{Slot: slot, Path: dest, Rows: n, Bytes: st.Size(), InputDigest: digest}
		}
		result = append(result, bucket)
		if err := os.Remove(p); err != nil {
			return nil, 0, err
		}
	}
	return result, reused, nil
}

func reuseBucket(old Bucket, dest string) bool {
	info, err := os.Stat(old.Path)
	if err != nil || info.Size() != old.Bytes {
		return false
	}
	f, err := Open(old.Path)
	if err != nil {
		return false
	}
	valid := f.Rows == uint64(old.Rows)
	f.Close()
	return valid && os.Link(old.Path, dest) == nil
}

func spoolDigest(ctx context.Context, path string, buf []byte) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), nil
		}
		if err != nil {
			return "", err
		}
	}
}

func sortBucket(ctx context.Context, src, dst, temp string) (int64, error) {
	f, e := os.Open(src)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 32<<10)
	var runs []string
	for {
		items := []Item{}
		used := 0
		for used < SortBudget {
			it, e := ReadItem(r)
			if e == io.EOF {
				break
			}
			if e != nil {
				return 0, e
			}
			items = append(items, it)
			used += len(it.Value) + 128
		}
		if len(items) == 0 {
			break
		}
		if e = ctx.Err(); e != nil {
			return 0, e
		}
		sort.Slice(items, func(i, j int) bool { return less(items[i], items[j]) })
		run, e := os.CreateTemp(temp, "sort-*")
		if e != nil {
			return 0, e
		}
		wr := bufio.NewWriterSize(run, 32<<10)
		for i, it := range items {
			if i > 0 && !less(items[i-1], it) {
				continue
			}
			if e = WriteItem(wr, it); e != nil {
				run.Close()
				return 0, e
			}
		}
		if e = wr.Flush(); e != nil {
			run.Close()
			return 0, e
		}
		if e = run.Close(); e != nil {
			return 0, e
		}
		runs = append(runs, run.Name())
	}
	defer func() {
		for _, p := range runs {
			os.Remove(p)
		}
	}()
	// Limit merge fan-in; no descriptor/heap growth with database size.
	for len(runs) > 4 {
		var next []string
		for i := 0; i < len(runs); i += 4 {
			end := i + 4
			if end > len(runs) {
				end = len(runs)
			}
			f, e := os.CreateTemp(temp, "merge-*")
			if e != nil {
				return 0, e
			}
			w := bufio.NewWriterSize(f, 32<<10)
			e = merge(ctx, runs[i:end], func(it Item) error { return WriteItem(w, it) })
			if e == nil {
				e = w.Flush()
			}
			f.Close()
			if e != nil {
				return 0, e
			}
			next = append(next, f.Name())
			for _, p := range runs[i:end] {
				os.Remove(p)
			}
		}
		runs = next
	}
	idx, e := os.CreateTemp(temp, "index-*")
	if e != nil {
		return 0, e
	}
	defer os.Remove(idx.Name())
	defer idx.Close()
	data, e := os.CreateTemp(temp, "data-*")
	if e != nil {
		return 0, e
	}
	defer os.Remove(data.Name())
	defer data.Close()
	iw, dw := bufio.NewWriterSize(idx, 32<<10), bufio.NewWriterSize(data, 32<<10)
	var count, rows, offset uint64
	var block []Item
	size := 0
	z, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	flush := func() error {
		if len(block) == 0 {
			return nil
		}
		h := crc32.NewIEEE()
		counter := &countWriter{w: io.MultiWriter(dw, h)}
		z.Reset(counter)
		for _, it := range block {
			var frame [40]byte
			copy(frame[:32], it.Hash[:])
			binary.LittleEndian.PutUint32(frame[32:36], uint32(len(it.Value)))
			binary.LittleEndian.PutUint32(frame[36:40], crc32.ChecksumIEEE(it.Value))
			if _, e := z.Write(frame[:]); e != nil {
				return e
			}
			if _, e := z.Write(it.Value); e != nil {
				return e
			}
		}
		if e := z.Close(); e != nil {
			return e
		}
		var entry [IndexSize]byte
		copy(entry[:32], block[0].Hash[:])
		binary.LittleEndian.PutUint64(entry[32:40], offset)
		binary.LittleEndian.PutUint32(entry[40:44], uint32(counter.n))
		binary.LittleEndian.PutUint32(entry[44:48], h.Sum32())
		if _, e := iw.Write(entry[:]); e != nil {
			return e
		}
		offset += uint64(counter.n)
		count++
		rows += uint64(len(block))
		block = nil
		size = 0
		return nil
	}
	e = merge(ctx, runs, func(it Item) error {
		if len(block) > 0 && (size+len(it.Value)+40 > BlockBytes) {
			if e := flush(); e != nil {
				return e
			}
		}
		block = append(block, it)
		size += len(it.Value) + 40
		return nil
	})
	if e == nil {
		e = flush()
	}
	if e != nil {
		return 0, e
	}
	if e = iw.Flush(); e != nil {
		return 0, e
	}
	if e = dw.Flush(); e != nil {
		return 0, e
	}
	idx.Seek(0, 0)
	data.Seek(0, 0)
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return 0, e
	}
	defer out.Close()
	var header [HeaderSize]byte
	copy(header[:8], magic[:])
	binary.LittleEndian.PutUint64(header[8:16], count)
	binary.LittleEndian.PutUint64(header[16:24], HeaderSize+count*IndexSize)
	binary.LittleEndian.PutUint64(header[24:32], offset)
	binary.LittleEndian.PutUint64(header[32:40], rows)
	if _, e = out.Write(header[:]); e != nil {
		return 0, e
	}
	if _, e = io.Copy(out, idx); e != nil {
		return 0, e
	}
	if _, e = io.Copy(out, data); e != nil {
		return 0, e
	}
	return int64(rows), out.Sync()
}

type node struct {
	Item Item
	R    *bufio.Reader
	F    *os.File
}
type queue []*node

func (q queue) Len() int           { return len(q) }
func (q queue) Less(i, j int) bool { return less(q[i].Item, q[j].Item) }
func (q queue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(v any)        { *q = append(*q, v.(*node)) }
func (q *queue) Pop() any          { a := *q; n := a[len(a)-1]; *q = a[:len(a)-1]; return n }
func merge(ctx context.Context, paths []string, emit func(Item) error) error {
	q := queue{}
	var opened []*os.File
	defer func() {
		for _, f := range opened {
			f.Close()
		}
	}()
	for _, p := range paths {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		opened = append(opened, f)
		r := bufio.NewReaderSize(f, 32<<10)
		it, e := ReadItem(r)
		if e == io.EOF {
			continue
		}
		if e != nil {
			return e
		}
		heap.Push(&q, &node{it, r, f})
	}
	var previous Item
	have := false
	for len(q) > 0 {
		if e := ctx.Err(); e != nil {
			return e
		}
		n := heap.Pop(&q).(*node)
		if !have || less(previous, n.Item) {
			if e := emit(n.Item); e != nil {
				return e
			}
			previous = n.Item
			have = true
		}
		it, e := ReadItem(n.R)
		if e != io.EOF {
			if e != nil {
				return e
			}
			n.Item = it
			heap.Push(&q, n)
		}
	}
	return nil
}

type File struct {
	f                            *os.File
	Count, DataOffset, DataBytes uint64
	Rows                         uint64
}

func Open(path string) (*File, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*File, error) { f.Close(); return nil, e }
	var h [HeaderSize]byte
	if _, e = io.ReadFull(f, h[:]); e != nil {
		return fail(e)
	}
	if !bytes.Equal(h[:8], magic[:]) {
		return fail(errors.New("unsupported disk database format"))
	}
	count := binary.LittleEndian.Uint64(h[8:16])
	off := binary.LittleEndian.Uint64(h[16:24])
	size := binary.LittleEndian.Uint64(h[24:32])
	rows := binary.LittleEndian.Uint64(h[32:40])
	st, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	if rows > 4000000 || count > rows || count > 4000000 || off != HeaderSize+count*IndexSize || off+size < off || off+size != uint64(st.Size()) {
		return fail(errors.New("invalid database bounds"))
	}
	return &File{f, count, off, size, rows}, nil
}
func (f *File) Close() error { return f.f.Close() }
func (f *File) entry(i uint64) ([IndexSize]byte, error) {
	var b [IndexSize]byte
	if i >= f.Count {
		return b, io.EOF
	}
	_, e := f.f.ReadAt(b[:], int64(HeaderSize+i*IndexSize))
	return b, e
}
func (f *File) Find(ctx context.Context, hash [32]byte, emit func([]byte) error) error {
	lo, hi := uint64(0), f.Count
	for lo < hi {
		mid := (lo + hi) / 2
		b, e := f.entry(mid)
		if e != nil {
			return e
		}
		if bytes.Compare(b[:32], hash[:]) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 {
		lo--
	}
	for i := lo; i < f.Count; i++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, e := f.entry(i)
		if e != nil {
			return e
		}
		if bytes.Compare(b[:32], hash[:]) > 0 {
			break
		}
		if e = f.block(ctx, b, &hash, emit); e != nil {
			return e
		}
	}

	return nil
}
func (f *File) Validate(ctx context.Context) error {
	var last [32]byte
	var end uint64
	r := bufio.NewReaderSize(io.NewSectionReader(f.f, HeaderSize, int64(f.Count*IndexSize)), 32<<10)
	for i := uint64(0); i < f.Count; i++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		var b [IndexSize]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return e
		}
		if i > 0 && bytes.Compare(last[:], b[:32]) > 0 {
			return errors.New("unordered database index")
		}
		copy(last[:], b[:32])
		off := binary.LittleEndian.Uint64(b[32:40])
		n := binary.LittleEndian.Uint32(b[40:44])
		if n > MaxBlock+65536 || off != end || off > f.DataBytes || uint64(n) > f.DataBytes-off {
			return errors.New("invalid index offset")
		}
		end = off + uint64(n)
	}
	if end != f.DataBytes {
		return errors.New("unreferenced data bytes")
	}
	return nil
}
func EncodeVersions(versions []string) ([]byte, error) {
	v := sortedUnique(versions)
	var data bytes.Buffer
	offsets := make([]byte, 4*(len(v)+1))
	for i, s := range v {
		if len(s) > 1024 {
			return nil, errors.New("version string too long")
		}
		binary.LittleEndian.PutUint32(offsets[i*4:], uint32(data.Len()))
		data.WriteString(s)
	}
	binary.LittleEndian.PutUint32(offsets[len(v)*4:], uint32(data.Len()))
	out := make([]byte, 8+len(offsets)+data.Len())
	copy(out, "WVST")
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(v)))
	copy(out[8:], offsets)
	copy(out[8+len(offsets):], data.Bytes())
	if len(out) > MaxValue {
		return nil, errors.New("version set exceeds bound")
	}
	return out, nil
}
func HasVersion(data []byte, version string) (bool, error) {
	if len(data) < 12 || string(data[:4]) != "WVST" {
		return false, errors.New("invalid version set")
	}
	n := int(binary.LittleEndian.Uint32(data[4:8]))
	start := 8 + 4*(n+1)
	if start > len(data) {
		return false, errors.New("invalid version offsets")
	}
	get := func(i int) (string, error) {
		a, b := int(binary.LittleEndian.Uint32(data[8+i*4:])), int(binary.LittleEndian.Uint32(data[12+i*4:]))
		if a > b || start+b > len(data) {
			return "", errors.New("invalid version bounds")
		}
		return string(data[start+a : start+b]), nil
	}
	lo, hi := 0, n
	for lo < hi {
		mid := (lo + hi) / 2
		s, e := get(mid)
		if e != nil {
			return false, e
		}
		if s < version {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo >= n {
		return false, nil
	}
	s, e := get(lo)
	return s == version, e
}

// Scan streams values in index order; intended for explicit publisher operations.
func (f *File) Scan(ctx context.Context, emit func([]byte) error) error {
	r := bufio.NewReaderSize(io.NewSectionReader(f.f, HeaderSize, int64(f.Count*IndexSize)), 32<<10)
	for i := uint64(0); i < f.Count; i++ {
		var b [IndexSize]byte
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return e
		}
		if e := f.block(ctx, b, nil, emit); e != nil {
			return e
		}
	}
	return nil
}

// ScanItems preserves authenticated index keys for publisher-side incremental rebuilding.
func (f *File) ScanItems(ctx context.Context, emit func(Item) error) error {
	for i := uint64(0); i < f.Count; i++ {
		entry, err := f.entry(i)
		if err != nil {
			return err
		}
		if err = f.blockItems(ctx, entry, nil, emit); err != nil {
			return err
		}
	}
	return nil
}
func (f *File) block(ctx context.Context, b [IndexSize]byte, target *[32]byte, emit func([]byte) error) error {
	return f.blockItems(ctx, b, target, func(it Item) error { return emit(it.Value) })
}
func (f *File) blockItems(ctx context.Context, b [IndexSize]byte, target *[32]byte, emit func(Item) error) error {
	off := binary.LittleEndian.Uint64(b[32:40])
	n := binary.LittleEndian.Uint32(b[40:44])
	if n > MaxBlock+65536 || off > f.DataBytes || uint64(n) > f.DataBytes-off {
		return errors.New("invalid compressed block bounds")
	}
	h := crc32.NewIEEE()
	z, e := gzip.NewReader(io.TeeReader(io.NewSectionReader(f.f, int64(f.DataOffset+off), int64(n)), h))
	if e != nil {
		return e
	}
	defer z.Close()
	r := bufio.NewReaderSize(io.LimitReader(z, MaxBlock+1), 32<<10)
	used := 0
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		var header [40]byte
		_, e = io.ReadFull(r, header[:])
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		size := int(binary.LittleEndian.Uint32(header[32:36]))
		used += 40 + size
		if size > MaxValue || used > MaxBlock {
			return errors.New("expanded block exceeds limit")
		}
		value := make([]byte, size)
		if _, e = io.ReadFull(r, value); e != nil {
			return e
		}
		if crc32.ChecksumIEEE(value) != binary.LittleEndian.Uint32(header[36:40]) {
			return errors.New("row checksum mismatch")
		}
		if target == nil || bytes.Equal(header[:32], target[:]) {
			var hash [32]byte
			copy(hash[:], header[:32])
			if e = emit(Item{Hash: hash, Value: value}); e != nil {
				return e
			}
		}
	}
	if h.Sum32() != binary.LittleEndian.Uint32(b[44:48]) {
		return errors.New("block checksum mismatch")
	}
	return nil
}

type countWriter struct {
	w io.Writer
	n int
}

func (w *countWriter) Write(b []byte) (int, error) { n, e := w.w.Write(b); w.n += n; return n, e }

// Two radix passes bound open files and avoid opening a bucket for every row.
type spoolWriter struct {
	f *os.File
	w *bufio.Writer
}

func (w *spoolWriter) Close() error {
	e := w.w.Flush()
	ce := w.f.Close()
	if e != nil {
		return e
	}
	return ce
}
func partition(ctx context.Context, dir string) error {
	stages, e := filepath.Glob(filepath.Join(dir, "*.stage"))
	if e != nil {
		return e
	}
	for _, path := range stages {
		if e = partitionOne(ctx, path, dir); e != nil {
			return e
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	return nil
}
func partitionOne(ctx context.Context, path, dir string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 32<<10)
	writers := map[string]*spoolWriter{}
	defer func() {
		for _, w := range writers {
			w.Close()
		}
	}()
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		it, e := ReadItem(r)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		group := string(filepath.Base(path)[0])
		slot := fmt.Sprintf("%s-%02x", group, slotByte(group, it.Hash[0]))
		w := writers[slot]
		if w == nil {
			disk, e := os.OpenFile(filepath.Join(dir, slot+".spool"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			w = &spoolWriter{disk, bufio.NewWriterSize(disk, 32<<10)}
			writers[slot] = w
		}
		if e = WriteItem(w.w, it); e != nil {
			return e
		}
	}
	for k, w := range writers {
		e := w.Close()
		delete(writers, k)
		if e != nil {
			return e
		}
	}
	return nil
}
