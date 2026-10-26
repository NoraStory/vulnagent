package main

import (
	"strings"
	"testing"
	"time"
)

func TestIntelFreshnessThresholds(t *testing.T) {
	t.Setenv("VA_SYNC_INTERVAL", "")
	warn, fail := intelFreshnessThresholds()
	if warn != 18 || fail != 24 {
		t.Fatalf("默认 12h 周期阈值应为 18/24，实际 %.0f/%.0f", warn, fail)
	}

	t.Setenv("VA_SYNC_INTERVAL", "off")
	warn, fail = intelFreshnessThresholds()
	if warn != 24 || fail != 48 {
		t.Fatalf("关闭定时同步后阈值应为 24/48，实际 %.0f/%.0f", warn, fail)
	}
}

func TestSelfcheckReportsCVESyncFailure(t *testing.T) {
	app, db, _ := newTicketTestApp(t)
	last := fmtT(nowT().Add(-time.Hour))
	if _, err := db.Exec(`INSERT INTO sync_cursors(source, last_run_at, status, count, error)
		VALUES('cve',?,?,?,?) ON CONFLICT(source) DO UPDATE SET last_run_at = excluded.last_run_at,
		status = excluded.status, count = excluded.count, error = excluded.error`,
		last, "fail", 0, "情报请求失败: dial tcp: 网络不可达"); err != nil {
		t.Fatalf("写入同步游标失败：%v", err)
	}

	run, err := app.runSelfcheck("测试")
	if err != nil {
		t.Fatalf("执行自检失败：%v", err)
	}
	var found bool
	for _, check := range run.Checks {
		if check.ID != "intel.cve_lag" {
			continue
		}
		found = true
		if check.Status != "fail" {
			t.Fatalf("同步失败时自检应为 fail，实际 %s：%s", check.Status, check.Detail)
		}
		if !strings.Contains(check.Detail, "网络不可达") {
			t.Fatalf("自检详情应包含同步错误：%s", check.Detail)
		}
	}
	if !found {
		t.Fatal("自检缺少 intel.cve_lag 项")
	}
}
