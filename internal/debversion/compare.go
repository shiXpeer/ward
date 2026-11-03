// Package debversion implements Debian Policy version ordering, including epochs,
// revisions and tilde. It is used only to prove an explicit version list redundant.
package debversion

import (
	"errors"
	"strings"
)

func digit(c byte) bool  { return c >= '0' && c <= '9' }
func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func split(s string) (string, string, string, error) {
	if len(s) == 0 || len(s) > 1024 {
		return "", "", "", errors.New("invalid Debian version")
	}
	epoch := "0"
	if i := strings.IndexByte(s, ':'); i >= 0 {
		epoch = s[:i]
		s = s[i+1:]
		if epoch == "" {
			return "", "", "", errors.New("empty epoch")
		}
		for i := range epoch {
			if !digit(epoch[i]) {
				return "", "", "", errors.New("non-numeric epoch")
			}
		}
	}
	if s == "" || !digit(s[0]) {
		return "", "", "", errors.New("upstream version must start with a digit")
	}
	for i := range s {
		c := s[i]
		if !digit(c) && !letter(c) && !strings.ContainsRune(".+:~-", rune(c)) {
			return "", "", "", errors.New("unsupported version character")
		}
	}
	rev := "0"
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		rev = s[i+1:]
		s = s[:i]
		if rev == "" {
			return "", "", "", errors.New("empty revision")
		}
	}
	for i := range rev {
		if !digit(rev[i]) && !letter(rev[i]) && !strings.ContainsRune(".+~", rune(rev[i])) {
			return "", "", "", errors.New("invalid revision character")
		}
	}
	return strings.TrimLeft(epoch, "0"), s, rev, nil
}
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	if c == '~' {
		return -1
	}
	if digit(c) {
		return 0
	}
	if letter(c) {
		return int(c)
	}
	return int(c) + 256
}
func part(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !digit(a[i]) || j < len(b) && !digit(b[j]) {
			x, y := order(a, i), order(b, j)
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		diff := 0
		for i < len(a) && j < len(b) && digit(a[i]) && digit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && digit(a[i]) {
			return 1
		}
		if j < len(b) && digit(b[j]) {
			return -1
		}
		if diff < 0 {
			return -1
		}
		if diff > 0 {
			return 1
		}
	}
	return 0
}
func Compare(a, b string) (int, error) {
	ea, ua, ra, e := split(a)
	if e != nil {
		return 0, e
	}
	eb, ub, rb, e := split(b)
	if e != nil {
		return 0, e
	}
	if len(ea) < len(eb) {
		return -1, nil
	}
	if len(ea) > len(eb) {
		return 1, nil
	}
	if ea < eb {
		return -1, nil
	}
	if ea > eb {
		return 1, nil
	}
	if n := part(ua, ub); n != 0 {
		return n, nil
	}
	return part(ra, rb), nil
}
