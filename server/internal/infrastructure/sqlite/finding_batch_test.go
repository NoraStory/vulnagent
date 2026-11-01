package sqlite

import (
	"context"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/asset"
)

func TestUpsertMatchesBatch(t *testing.T) {
	base := newTestDB(t)
	repo := NewFindingRepo(base.db)
	ctx := context.Background()
	if _, err := base.db.Exec(`INSERT INTO cves(cve_id, title) VALUES('CVE-BATCH-A','A'),('CVE-BATCH-B','B')`); err != nil {
		t.Fatalf("写入 CVE 失败：%v", err)
	}

	inputs := []ports.MatchInput{
		{
			AssetID: 1, Component: asset.Component{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Eco: "npm"},
			CVEID: "CVE-BATCH-A", CVSS: 9.8, Risk: 99, Priority: "P0", Breakdown: "[]", Now: "2026-11-01T10:00:00+08:00",
		},
		{
			AssetID: 1, Component: asset.Component{PURL: "pkg:npm/b@2.0.0", Name: "b", Version: "2.0.0", Eco: "npm"},
			CVEID: "CVE-BATCH-B", CVSS: 7.5, Risk: 70, Priority: "P1", Breakdown: "[]", Now: "2026-11-01T10:00:00+08:00",
		},
	}
	flags, err := repo.UpsertMatches(ctx, inputs)
	if err != nil || len(flags) != 2 || !flags[0] || !flags[1] {
		t.Fatalf("首次批量写入应全部新增：flags=%v err=%v", flags, err)
	}

	inputs[0].Risk = 88
	inputs[0].Priority = "P1"
	flags, err = repo.UpsertMatches(ctx, inputs)
	if err != nil || flags[0] || flags[1] {
		t.Fatalf("二次批量写入应全部更新：flags=%v err=%v", flags, err)
	}

	items, total, err := repo.List(ctx, ports.FindingFilter{Limit: 10})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("批量写入后列表异常：total=%d len=%d err=%v", total, len(items), err)
	}
}

func TestMarkStatusBatch(t *testing.T) {
	base := newTestDB(t)
	repo := NewFindingRepo(base.db)
	ctx := context.Background()
	if _, err := base.db.Exec(`INSERT INTO cves(cve_id, title) VALUES('CVE-ST-A','A'),('CVE-ST-B','B')`); err != nil {
		t.Fatalf("写入 CVE 失败：%v", err)
	}
	inputs := []ports.MatchInput{
		{
			AssetID: 1, Component: asset.Component{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Eco: "npm"},
			CVEID: "CVE-ST-A", Risk: 90, Priority: "P0", Breakdown: "[]", Now: "2026-11-01T10:00:00+08:00",
		},
		{
			AssetID: 1, Component: asset.Component{PURL: "pkg:npm/b@2.0.0", Name: "b", Version: "2.0.0", Eco: "npm"},
			CVEID: "CVE-ST-B", Risk: 60, Priority: "P2", Breakdown: "[]", Now: "2026-11-01T10:00:00+08:00",
		},
	}
	if _, err := repo.UpsertMatches(ctx, inputs); err != nil {
		t.Fatalf("准备数据失败：%v", err)
	}
	rows, err := repo.ActiveForReconcile(ctx, 1)
	if err != nil || len(rows) != 2 {
		t.Fatalf("读取待收敛记录异常：len=%d err=%v", len(rows), err)
	}

	err = repo.MarkStatusBatch(ctx, []ports.StatusUpdate{
		{ID: rows[0].ID, Status: "closed", Now: "2026-11-01T11:00:00+08:00", Event: "rescan", Actor: "系统", Detail: "已修复"},
		{ID: rows[1].ID, Status: "closed", Now: "2026-11-01T11:00:00+08:00", Event: "rescan", Actor: "系统", Detail: "组件移除"},
	})
	if err != nil {
		t.Fatalf("批量收敛失败：%v", err)
	}
	remaining, err := repo.ActiveForReconcile(ctx, 1)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("收敛后不应再有活动记录：len=%d err=%v", len(remaining), err)
	}
	var events int
	if err := base.db.QueryRow(`SELECT COUNT(*) FROM finding_events`).Scan(&events); err != nil || events != 2 {
		t.Fatalf("处置事件数量异常：%d err=%v", events, err)
	}
}
