package version

import "testing"

func TestRangeMatches(t *testing.T) {
	r := Range{StartIncl: "2.0.0", EndExcl: "3.0.0"}
	cases := []struct {
		eco, v string
		want   bool
	}{
		{"npm", "2.5.0", true},
		{"npm", "3.0.0", false},
		{"npm", "1.9.9", false},
		{"npm", "", false},
	}
	for _, c := range cases {
		if got := r.Matches(c.eco, c.v); got != c.want {
			t.Fatalf("Matches(%s,%q) = %v，期望 %v", c.eco, c.v, got, c.want)
		}
	}
}

func TestCompareEcosystems(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		{"deb", "1:1.0-1", "1:1.0-2", -1},
		{"rpm", "1.2.3-1", "1.2.3", 1},
		{"apk", "1.0-r0", "1.0-r1", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"golang", "v0.9.0", "v0.10.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.eco, c.a, c.b); got != c.want {
			t.Fatalf("Compare(%s,%s,%s) = %d，期望 %d", c.eco, c.a, c.b, got, c.want)
		}
	}
}
