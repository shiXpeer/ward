package debversion

import "testing"

func TestDebianVersionOrder(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		sign int
	}{{"1.0~rc1", "1.0", -1}, {"1:1.0", "9.0", 1}, {"1.0", "1.0-0", 0}, {"1.001", "1.1", 0}, {"1.0-1", "1.0-1+b1", -1}, {"2:1.0-1~bpo12+1", "2:1.0-1", -1}, {"1.0a", "1.0+", -1}, {"1.0~~", "1.0~", -1}} {
		v, e := Compare(tc.a, tc.b)
		if e != nil || v < 0 && tc.sign >= 0 || v > 0 && tc.sign <= 0 || v == 0 && tc.sign != 0 {
			t.Fatal(tc, v, e)
		}
	}
	for _, s := range []string{"", "bad", "1\n2", "x:1", "1:1-1:2"} {
		if _, e := Compare(s, "1"); e == nil {
			t.Fatal("accepted", s)
		}
	}
}
