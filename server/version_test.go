package main

import "testing"

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		// debian：数字段按数值比较、修订号缺失视为最小
		{"deb", "3.0.11", "3.0.2", 1},
		{"deb", "2.31-13+deb11u5", "2.36-9+deb12u3", -1},
		{"deb", "0.105", "0.105-31+deb11u1", -1},
		{"deb", "1.9.9", "1.9.5p2", 1},
		{"deb", "5.6.1", "5.6.2", -1},
		{"deb", "2.4.49", "2.4.50", -1},
		{"deb", "2.4.52", "2.4.59", -1},
		// rpm
		{"rpm", "1.20.1", "1.21.0", -1},
		{"rpm", "2.0.0~rc1", "2.0.0", -1},
		{"rpm", "1:1.0", "2.0", 1},
		// semver 生态
		{"golang", "v0.10.0", "v0.17.0", -1},
		{"npm", "4.17.20", "4.17.21", -1},
		{"npm", "0.21.1", "0.21.2", -1},
		{"maven", "5.3.17", "5.3.18", -1},
		{"maven", "2.5.26", "2.5.30", -1},
		{"maven", "1.0.0-rc1", "1.0.0", -1},
		{"pypi", "3.2.12", "3.2.14", -1},
		{"nuget", "12.0.3", "12.0.4", -1},
		// apk
		{"apk", "1.2.3-r0", "1.2.3-r1", -1},
		{"apk", "1.2.10-r0", "1.2.9-r2", 1},
		// 未知生态
		{"windows", "7.0.11", "7.0.9", 1},
	}
	for _, c := range cases {
		got := CompareVersion(c.eco, c.a, c.b)
		if sign(got) != c.want {
			t.Fatalf("CompareVersion(%s,%s,%s)=%d, want %d", c.eco, c.a, c.b, got, c.want)
		}
		rev := CompareVersion(c.eco, c.b, c.a)
		if sign(rev) != -c.want {
			t.Fatalf("CompareVersion(%s,%s,%s)=%d, want %d（反向一致性）", c.eco, c.b, c.a, rev, -c.want)
		}
	}
}

func TestAffectedRange(t *testing.T) {
	r := AffectedRange{CveID: "CVE-TEST", Product: "openssl", VersionStartIncl: "1.0.0", VersionEndExcl: "3.0.8"}
	if !r.Matches("deb", "3.0.7") {
		t.Fatal("3.0.7 应命中区间")
	}
	if r.Matches("deb", "3.0.8") {
		t.Fatal("3.0.8 不应命中（右开区间）")
	}
	if r.Matches("deb", "0.9.9") {
		t.Fatal("0.9.9 低于下界，不应命中")
	}
}
