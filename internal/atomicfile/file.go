// Package atomicfile commits private JSON state without a database engine.
package atomicfile

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func Write(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ward-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// JSON streams top-level array fields one item at a time. Large source snapshots
// do not require a second complete marshaled copy in memory.
func JSON(path string, v any) error {
	return Stream(path, func(w io.Writer) error {
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Struct {
			return json.NewEncoder(w).Encode(v)
		}
		enc := json.NewEncoder(w)
		if _, e := io.WriteString(w, "{"); e != nil {
			return e
		}
		first := true
		for i := 0; i < rv.NumField(); i++ {
			sf := rv.Type().Field(i)
			if sf.PkgPath != "" {
				continue
			}
			parts := strings.Split(sf.Tag.Get("json"), ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = sf.Name
			}
			field := rv.Field(i)
			omit := false
			for _, opt := range parts[1:] {
				if opt == "omitempty" && field.IsZero() {
					omit = true
				}
			}
			if omit {
				continue
			}
			if !first {
				if _, e := io.WriteString(w, ","); e != nil {
					return e
				}
			}
			first = false
			key, _ := json.Marshal(name)
			if _, e := w.Write(key); e != nil {
				return e
			}
			if _, e := io.WriteString(w, ":"); e != nil {
				return e
			}
			if field.Kind() == reflect.Slice && field.Type().Elem().Kind() != reflect.Uint8 && !field.IsNil() {
				if _, e := io.WriteString(w, "["); e != nil {
					return e
				}
				for j := 0; j < field.Len(); j++ {
					if j > 0 {
						if _, e := io.WriteString(w, ","); e != nil {
							return e
						}
					}
					if e := enc.Encode(field.Index(j).Interface()); e != nil {
						return e
					}
				}
				if _, e := io.WriteString(w, "]"); e != nil {
					return e
				}
			} else if e := enc.Encode(field.Interface()); e != nil {
				return e
			}
		}
		_, e := io.WriteString(w, "}\n")
		return e
	})
}
func Stream(path string, encode func(io.Writer) error) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".ward-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if e = encode(f); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func ReadJSON(path string, v any, max int64) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() > max {
		return errors.New("state exceeds configured limit")
	}
	d := json.NewDecoder(io.LimitReader(f, max+1))
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return d.Decode(v)
	}
	rv = rv.Elem()
	fields := map[string]int{}
	for i := 0; i < rv.NumField(); i++ {
		sf := rv.Type().Field(i)
		if sf.PkgPath != "" {
			continue
		}
		name := strings.Split(sf.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		fields[name] = i
	}
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("invalid state object")
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return e
		}
		name := key.(string)
		if seen[name] {
			return errors.New("duplicate state field")
		}
		seen[name] = true
		i, ok := fields[name]
		if !ok {
			var skip json.RawMessage
			if e = d.Decode(&skip); e != nil {
				return e
			}
			continue
		}
		field := rv.Field(i)
		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() != reflect.Uint8 {
			t, e := d.Token()
			if e != nil {
				return e
			}
			if t == nil {
				field.SetZero()
				continue
			}
			if t != json.Delim('[') {
				return errors.New("invalid state array")
			}
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			for d.More() {
				item := reflect.New(field.Type().Elem())
				if e = d.Decode(item.Interface()); e != nil {
					return e
				}
				field.Set(reflect.Append(field, item.Elem()))
			}
			if _, e = d.Token(); e != nil {
				return e
			}
		} else if e = d.Decode(field.Addr().Interface()); e != nil {
			return e
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return errors.New("trailing state data")
	}
	return nil
}

// Lock enforces one Beacon writer. A crash leaves the lock for operator recovery;
// it is never automatically stolen from a potentially live process.
func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "writer.lock")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("Beacon writer locked; see recovery documentation")
	}
	if _, err = f.WriteString("single writer; remove only after verifying no Beacon writer is running\n"); err != nil {
		f.Close()
		os.Remove(p)
		return nil, err
	}
	f.Close()
	return func() { _ = os.Remove(p) }, nil
}
