package harness

import "testing"

func TestArgsHashStable(t *testing.T) {
	a := ArgsHash([]byte(`{"b":2,"a":1}`))
	b := ArgsHash([]byte(`{"a":1,"b":2}`))
	if a != b {
		t.Fatalf("键顺序不应影响指纹：%s != %s", a, b)
	}
	if a == ArgsHash([]byte(`{"a":1,"b":3}`)) {
		t.Fatal("参数变化必须改变指纹")
	}
	if ArgsHash([]byte(`not-json`)) == "" {
		t.Fatal("非法 JSON 也应产生指纹")
	}
}

func TestRiskSemantics(t *testing.T) {
	if RiskLow.NeedsApproval() || RiskLow.NeedsReauth() {
		t.Fatal("low 不需要审批或再认证")
	}
	if !RiskMedium.NeedsApproval() || RiskMedium.NeedsReauth() {
		t.Fatal("medium 需要审批但不需要再认证")
	}
	if !RiskHigh.NeedsApproval() || !RiskHigh.NeedsReauth() {
		t.Fatal("high 需要审批与再认证")
	}
	if Risk("unknown").Valid() {
		t.Fatal("未知风险等级不应合法")
	}
}
