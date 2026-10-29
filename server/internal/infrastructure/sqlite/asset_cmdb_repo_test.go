package sqlite

import (
	"context"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func TestAssetUpdateFieldsRecordsChanges(t *testing.T) {
	repo := newTestDB(t)
	ctx := context.Background()

	changes, err := repo.UpdateFields(ctx, 1, map[string]string{
		"owner":          "张三",
		"businessSystem": "交易系统",
		"tier":           "important",
	}, "管理员", "manual")
	if err != nil {
		t.Fatalf("更新资产失败：%v", err)
	}
	if len(changes) != 3 {
		t.Fatalf("应记录 3 条变更，实际 %d", len(changes))
	}

	detail, err := repo.Detail(ctx, 1)
	if err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	if detail.Owner != "张三" || detail.BusinessSystem != "交易系统" || detail.Tier != "important" {
		t.Fatalf("字段未更新：%+v", detail)
	}

	history, err := repo.Changes(ctx, 1, 10)
	if err != nil || len(history) != 3 {
		t.Fatalf("变更历史异常：len=%d err=%v", len(history), err)
	}

	// 写入相同值不应产生新的变更
	again, err := repo.UpdateFields(ctx, 1, map[string]string{"owner": "张三"}, "管理员", "manual")
	if err != nil {
		t.Fatalf("重复更新失败：%v", err)
	}
	if len(again) != 0 {
		t.Fatalf("相同值不应记录变更，实际 %d", len(again))
	}
}

func TestAssetTagsAndIdentifiers(t *testing.T) {
	repo := newTestDB(t)
	ctx := context.Background()

	if err := repo.SetTags(ctx, 1, []string{" prod ", "core", "prod", "|bad"}, "管理员", "manual"); err != nil {
		t.Fatalf("设置标签失败：%v", err)
	}
	tags, err := repo.Tags(ctx, 1)
	if err != nil {
		t.Fatalf("读取标签失败：%v", err)
	}
	if len(tags) != 2 || tags[0] != "core" || tags[1] != "prod" {
		t.Fatalf("标签清洗异常：%v", tags)
	}

	if err := repo.AddIdentifiers(ctx, 1, "mac", "manual", []string{"AA:BB:CC:DD:EE:FF"}); err != nil {
		t.Fatalf("写入标识失败：%v", err)
	}
	id, ok, err := repo.FindByIdentity(ctx, "mac", "AA:BB:CC:DD:EE:FF")
	if err != nil || !ok || id != 1 {
		t.Fatalf("标识查找失败：id=%d ok=%v err=%v", id, ok, err)
	}
}

func TestUpsertReportedRegistersIdentifiers(t *testing.T) {
	repo := newTestDB(t)
	ctx := context.Background()

	id, err := repo.UpsertReported(ctx, "agent-host", "10.9.9.9", "linux", "debian12", "agent", "online", "2026-10-29T10:00:00+08:00")
	if err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	for _, item := range []struct {
		kind  string
		value string
	}{
		{"hostname", "agent-host"},
		{"ip", "10.9.9.9"},
	} {
		got, ok, err := repo.FindByIdentity(ctx, item.kind, item.value)
		if err != nil || !ok || got != id {
			t.Fatalf("%s 标识未登记：id=%d ok=%v err=%v", item.kind, got, ok, err)
		}
	}
}

func TestAssetListFilters(t *testing.T) {
	repo := newTestDB(t)
	ctx := context.Background()

	if _, err := repo.UpsertReported(ctx, "prod-db", "10.0.0.5", "linux", "rocky9", "agent", "online", "2026-10-29T10:00:00+08:00"); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	if _, err := repo.UpdateFields(ctx, 2, map[string]string{
		"businessSystem": "订单",
		"status":         "maintenance",
	}, "管理员", "manual"); err != nil {
		t.Fatalf("更新资产失败：%v", err)
	}

	items, total, err := repo.List(ctx, ports.AssetFilter{BusinessSystem: "订单"}, 20, 0)
	if err != nil || total != 1 || len(items) != 1 || items[0].Hostname != "prod-db" {
		t.Fatalf("业务系统筛选异常：total=%d len=%d err=%v", total, len(items), err)
	}
	if _, total, err = repo.List(ctx, ports.AssetFilter{Status: "maintenance"}, 20, 0); err != nil || total != 1 {
		t.Fatalf("状态筛选异常：total=%d err=%v", total, err)
	}
	if _, total, err = repo.List(ctx, ports.AssetFilter{Query: "订单"}, 20, 0); err != nil || total != 1 {
		t.Fatalf("关键词筛选业务系统异常：total=%d err=%v", total, err)
	}
}

func TestAssetMergeMovesRelatedData(t *testing.T) {
	repo := newTestDB(t)
	ctx := context.Background()
	db := repo.db

	targetID, err := repo.UpsertReported(ctx, "host-02", "10.0.0.2", "linux", "debian12", "agent", "online", "2026-10-29T10:00:00+08:00")
	if err != nil {
		t.Fatalf("写入目标资产失败：%v", err)
	}
	if _, err := db.Exec(`INSERT INTO components(asset_id, purl, eco, name, version) VALUES(1,'pkg:npm/lodash@4.17.20','npm','lodash','4.17.20')`); err != nil {
		t.Fatalf("写入组件失败：%v", err)
	}
	if _, err := db.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, cve_id)
		VALUES(1,'pkg:npm/lodash@4.17.20','lodash','4.17.20','CVE-2026-0001')`); err != nil {
		t.Fatalf("写入漏洞失败：%v", err)
	}
	if err := repo.SetTags(ctx, 1, []string{"legacy"}, "管理员", "manual"); err != nil {
		t.Fatalf("设置标签失败：%v", err)
	}
	if err := repo.AddIdentifiers(ctx, 1, "mac", "manual", []string{"AA:BB:CC:00:11:22"}); err != nil {
		t.Fatalf("写入标识失败：%v", err)
	}

	stats, err := repo.Merge(ctx, 1, targetID, "管理员")
	if err != nil {
		t.Fatalf("合并失败：%v", err)
	}
	if stats.Components != 1 || stats.Findings != 1 || stats.Identifiers < 1 || stats.Tags != 1 {
		t.Fatalf("合并统计异常：%+v", stats)
	}

	detail, err := repo.Detail(ctx, 1)
	if err != nil {
		t.Fatalf("读取源资产失败：%v", err)
	}
	if detail.Status != "merged" || detail.MergedInto != targetID {
		t.Fatalf("源资产未标记合并：%+v", detail)
	}
	if detail.Components != 0 || detail.Findings != 0 {
		t.Fatalf("源资产关联数据未搬空：%+v", detail)
	}

	target, err := repo.Detail(ctx, targetID)
	if err != nil {
		t.Fatalf("读取目标资产失败：%v", err)
	}
	if target.Components != 1 || target.Findings != 1 {
		t.Fatalf("目标资产未接收数据：%+v", target)
	}

	// 默认列表不再展示已合并资产
	items, total, err := repo.List(ctx, ports.AssetFilter{}, 20, 0)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("合并后列表异常：total=%d len=%d err=%v", total, len(items), err)
	}
	if items[0].ID != targetID {
		t.Fatalf("列表应只剩目标资产，实际 %+v", items)
	}
}
