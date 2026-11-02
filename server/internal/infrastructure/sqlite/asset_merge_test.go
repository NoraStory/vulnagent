package sqlite

import (
	"context"
	"testing"
)

// 合并后的资产不应再接收上报，也不能作为新的合并目标
func TestMergeRedirectsReportsAndRejectsMergedTarget(t *testing.T) {
	base := newTestDB(t)
	repo := NewAssetRepo(base.db)
	ctx := context.Background()
	if _, err := base.db.Exec(`INSERT INTO assets(hostname, exposure, tier, source)
		VALUES('merge-a','internal','normal','agent'),('merge-b','internal','normal','agent'),('merge-c','internal','normal','agent')`); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	var aID, bID, cID int64
	if err := base.db.QueryRow(`SELECT id FROM assets WHERE hostname = 'merge-a'`).Scan(&aID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if err := base.db.QueryRow(`SELECT id FROM assets WHERE hostname = 'merge-b'`).Scan(&bID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if err := base.db.QueryRow(`SELECT id FROM assets WHERE hostname = 'merge-c'`).Scan(&cID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if _, err := base.db.Exec(`INSERT INTO discovery_candidates(job_id, ip, asset_id) VALUES(1, '10.0.0.9', ?)`, aID); err != nil {
		t.Fatalf("写入候选资产失败：%v", err)
	}

	if _, err := repo.Merge(ctx, aID, bID, "测试"); err != nil {
		t.Fatalf("首次合并失败：%v", err)
	}

	var candidateAsset int64
	if err := base.db.QueryRow(`SELECT asset_id FROM discovery_candidates WHERE ip = '10.0.0.9'`).Scan(&candidateAsset); err != nil {
		t.Fatalf("读取候选资产失败：%v", err)
	}
	if candidateAsset != bID {
		t.Fatalf("候选资产应迁移到合并目标，实际 %d", candidateAsset)
	}

	id, err := repo.UpsertReported(ctx, "merge-a", "10.0.0.9", "linux", "Ubuntu 22.04", "agent", "online", "2026-11-02T10:00:00+08:00")
	if err != nil {
		t.Fatalf("合并后上报失败：%v", err)
	}
	if id != bID {
		t.Fatalf("合并后上报应落到目标资产 %d，实际 %d", bID, id)
	}
	var mergedInto int64
	var status string
	if err := base.db.QueryRow(`SELECT merged_into, status FROM assets WHERE id = ?`, aID).Scan(&mergedInto, &status); err != nil {
		t.Fatalf("读取源资产失败：%v", err)
	}
	if mergedInto != bID || status != "merged" {
		t.Fatalf("源资产应保持已合并状态：merged_into=%d status=%s", mergedInto, status)
	}

	resolved, found, err := repo.FindByHostname(ctx, "merge-a")
	if err != nil || !found || resolved != bID {
		t.Fatalf("按主机名应解析到合并目标：id=%d found=%v err=%v", resolved, found, err)
	}

	if _, err := repo.Merge(ctx, cID, aID, "测试"); err == nil {
		t.Fatal("目标资产已合并时应拒绝合并")
	}
	if _, err := repo.Merge(ctx, aID, cID, "测试"); err == nil {
		t.Fatal("源资产已合并时应拒绝再次合并")
	}

	gauges, err := NewStatsRepo(base.db).Gauges(ctx)
	if err != nil {
		t.Fatalf("读取统计失败：%v", err)
	}
	// newTestDB 预置 1 台，加上 merge-b / merge-c，已合并的 merge-a 不计入
	if gauges.Assets != 3 {
		t.Fatalf("已合并资产不应计入总数，实际 %d", gauges.Assets)
	}
}
