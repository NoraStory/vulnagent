package collect

import "testing"

func TestCollectUsesConfiguredHostname(t *testing.T) {
	t.Setenv("VA_HOSTNAME", "worker-node-a")
	report, err := Collect(Options{MaxComponents: 1})
	if err != nil {
		t.Fatalf("采集失败：%v", err)
	}
	if report.Hostname != "worker-node-a" {
		t.Fatalf("应使用显式节点名，实际 %q", report.Hostname)
	}
}
