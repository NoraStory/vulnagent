package agentexec

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDiagnoseQueryCatalog(t *testing.T) {
	queries := DiagnoseQueries()
	if len(queries) < 15 {
		t.Fatalf("诊断项目过少：%d", len(queries))
	}
	for _, key := range []string{"disk_space", "disk_layout", "mem_info", "net_conn", "service_status", "system_log", "time_sync"} {
		if !SupportedDiagnoseQuery(key) {
			t.Fatalf("应支持诊断项：%s", key)
		}
	}
	if SupportedDiagnoseQuery("rm_rf") {
		t.Fatal("未知诊断项不应被支持")
	}
}

func TestDiagnoseRejectsUnknownQuery(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"query": "rm_rf"})
	if _, err := diagnose(context.Background(), raw, DefaultOptions()); err == nil {
		t.Fatal("未知诊断项应返回错误")
	}
	raw, _ = json.Marshal(map[string]any{"query": "net_ping"})
	if _, err := diagnose(context.Background(), raw, DefaultOptions()); err == nil {
		t.Fatal("net_ping 缺少 target 应返回错误")
	}
	raw, _ = json.Marshal(map[string]any{"query": "net_ping", "target": "example.com; rm -rf /"})
	if _, err := diagnose(context.Background(), raw, DefaultOptions()); err == nil {
		t.Fatal("非法 target 应被拒绝")
	}
}
