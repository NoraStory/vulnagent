package risk

import "testing"

func TestScoreTable(t *testing.T) {
	p := DefaultPolicy()
	cases := []struct {
		name            string
		cvss, epss      float64
		exploit, expose string
		tier            string
		wantRisk        int
		wantPriority    string
	}{
		{"满分+KEV+公网核心", 10, 0.9, "kev", "public", "core", 98, "P0"},
		{"高危+无情报+内网一般", 7.5, 0, "none", "internal", "normal", 35, "P3"},
		{"中危+高EPSS+内网核心", 5.0, 0.6, "poc", "internal", "core", 56, "P2"},
		{"零分", 0, 0, "none", "isolated", "normal", 2, "P3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, priority, factors := p.Score(c.cvss, c.epss, c.exploit, c.expose, c.tier)
			if got != c.wantRisk {
				t.Fatalf("风险分 = %d，期望 %d", got, c.wantRisk)
			}
			if priority != c.wantPriority {
				t.Fatalf("优先级 = %s，期望 %s", priority, c.wantPriority)
			}
			if len(factors) != 4 {
				t.Fatalf("打分明细应为 4 项，实际 %d", len(factors))
			}
		})
	}
}

func TestPriorityHardRules(t *testing.T) {
	p := DefaultPolicy()
	if _, prio, _ := p.Score(9.8, 0, "poc", "isolated", "normal"); prio != "P0" {
		t.Fatalf("CVSS≥9 且存在 POC 应判 P0，实际 %s", prio)
	}
	if _, prio, _ := p.Score(8.0, 0.55, "none", "internal", "normal"); prio != "P1" {
		t.Fatalf("CVSS≥8 且 EPSS≥0.5 应判 P1，实际 %s", prio)
	}
}

func TestAssetWeight(t *testing.T) {
	cases := []struct {
		exposure, tier string
		want           float64
	}{
		{"public", "core", 1},
		{"internal", "core", 0.6},
		{"public", "normal", 0.5},
		{"isolated", "normal", 0.1},
		{"unknown", "unknown", 0.3},
	}
	for _, c := range cases {
		if got := AssetWeight(c.exposure, c.tier); got != c.want {
			t.Fatalf("AssetWeight(%s,%s) = %v，期望 %v", c.exposure, c.tier, got, c.want)
		}
	}
}

func TestUnmarshalPolicyFallback(t *testing.T) {
	p := UnmarshalPolicy("", "")
	if p.Weights != DefaultPolicy().Weights || p.Thresholds != DefaultPolicy().Thresholds {
		t.Fatal("空配置应回落到默认策略")
	}
	p = UnmarshalPolicy(`{"cvss":0.5,"epss":0.2,"exploit":0.2,"asset":0.1}`, `{"p0":90,"p1":75,"p2":55}`)
	if p.Thresholds.P0 != 90 || p.Weights.Cvss != 0.5 {
		t.Fatalf("自定义策略未生效：%+v", p)
	}
}
