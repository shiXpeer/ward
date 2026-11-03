package agent

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

// RollingLog bounds resident report/error logs to two files inside home state.
// It opens files with the service user's privileges, never via root systemd IO.
type RollingLog struct {
	mu    sync.Mutex
	path  string
	limit int64
	file  *os.File
	size  int64
}

func OpenLog(path string, limit int64) (*RollingLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &RollingLog{path: path, limit: limit, file: f, size: info.Size()}, nil
}
func (l *RollingLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if int64(len(b)) > l.limit {
		return 0, io.ErrShortWrite
	}
	if l.size+int64(len(b)) > l.limit {
		if err := l.file.Close(); err != nil {
			return 0, err
		}
		if err := os.Rename(l.path, l.path+".previous"); err != nil {
			return 0, err
		}
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return 0, err
		}
		l.file = f
		l.size = 0
	}
	n, err := l.file.Write(b)
	l.size += int64(n)
	return n, err
}
func (l *RollingLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
