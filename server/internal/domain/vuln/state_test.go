package vuln

import "testing"

func TestStatusValidity(t *testing.T) {
	for _, s := range AllStatuses {
		if !s.Valid() {
			t.Fatalf("%s 应为合法状态", s)
		}
		if s.Label() == string(s) {
			t.Fatalf("%s 缺少中文标签", s)
		}
	}
	if Status("unknown").Valid() {
		t.Fatal("未知状态不应合法")
	}
	if len(AllStatuses) != 8 {
		t.Fatalf("状态应为 8 种，实际 %d", len(AllStatuses))
	}
}

func TestStatusTransitions(t *testing.T) {
	cases := []struct {
		from, to Status
		want     bool
	}{
		{StatusOpen, StatusTriaged, true},
		{StatusFixing, StatusFixed, true},
		{StatusFixed, StatusVerified, true},
		{StatusVerified, StatusOpen, true}, // 版本回退重新打开
		{StatusClosed, StatusOpen, true},
		{StatusVerified, StatusFixing, false},
		{StatusClosed, StatusFixed, false},
		{StatusFalsePositive, StatusRiskAccepted, false},
		{StatusOpen, StatusOpen, true},
	}
	for _, c := range cases {
		if got := c.from.CanTransition(c.to); got != c.want {
			t.Fatalf("%s → %s = %v，期望 %v", c.from, c.to, got, c.want)
		}
	}
}

func TestActiveStatusSQL(t *testing.T) {
	got := ActiveStatusSQL()
	want := "'open','triaged','fixing','fixed','verified'"
	if got != want {
		t.Fatalf("ActiveStatusSQL() = %s，期望 %s", got, want)
	}
}

func TestAffectedRangeMatches(t *testing.T) {
	r := AffectedRange{VersionStartIncl: "1.0.0", VersionEndExcl: "1.4.0"}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.0.0", true},
		{"1.3.9", true},
		{"1.4.0", false},
		{"0.9.9", false},
		{"", false},
	}
	for _, c := range cases {
		if got := r.Matches("npm", c.version); got != c.want {
			t.Fatalf("Matches(%q) = %v，期望 %v", c.version, got, c.want)
		}
	}
	open := AffectedRange{CveID: "CVE-2026-0001"}
	if !open.Matches("golang", "0.0.1") {
		t.Fatal("无边界区间应匹配任意非空版本")
	}
}
