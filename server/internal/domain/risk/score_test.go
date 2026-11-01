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
			got, priority, factors := p.Score(c.cvss, c.epss, c.exploit, c.expose, c.tier, "core")
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
	if _, prio, _ := p.Score(9.8, 0, "poc", "isolated", "normal", "normal"); prio != "P0" {
		t.Fatalf("CVSS≥9 且存在 POC 应判 P0，实际 %s", prio)
	}
	if _, prio, _ := p.Score(8.0, 0.55, "none", "internal", "normal", "normal"); prio != "P1" {
		t.Fatalf("CVSS≥8 且 EPSS≥0.5 应判 P1，实际 %s", prio)
	}
}

func TestAssetWeight(t *testing.T) {
	cases := []struct {
		exposure, tier, business string
		want                     float64
	}{
		{"public", "core", "core", 1},
		{"internal", "core", "core", 0.6},
		{"public", "normal", "core", 0.5},
		{"isolated", "normal", "core", 0.1},
		{"unknown", "unknown", "core", 0.3},
		{"public", "core", "important", 0.9},
		{"public", "core", "normal", 0.8},
		{"public", "core", "", 0.8},
	}
	for _, c := range cases {
		if got := AssetWeight(c.exposure, c.tier, c.business); got != c.want {
			t.Fatalf("AssetWeight(%s,%s,%s) = %v，期望 %v", c.exposure, c.tier, c.business, got, c.want)
		}
	}
}

func TestBusinessTierChangesScore(t *testing.T) {
	p := DefaultPolicy()
	core, _, _ := p.Score(9.8, 0.9, "kev", "public", "core", "core")
	normal, _, _ := p.Score(9.8, 0.9, "kev", "public", "core", "normal")
	if core <= normal {
		t.Fatalf("核心业务系统风险分应高于一般业务：core=%d normal=%d", core, normal)
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
