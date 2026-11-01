package sqlite

import (
	"context"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func TestBusinessRepoListAndUpsert(t *testing.T) {
	base := newTestDB(t)
	repo := NewBusinessRepo(base.db)
	ctx := context.Background()

	if _, err := base.db.Exec(`INSERT INTO assets(hostname, business_system, source) VALUES
		('web-01','交易系统','agent'), ('web-02','交易系统','agent'), ('db-01','订单系统','agent')`); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	items, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("查询业务系统失败：%v", err)
	}
	if len(items) != 2 {
		t.Fatalf("应返回 2 个业务系统，实际 %d：%+v", len(items), items)
	}
	if items[0].Name != "交易系统" && items[1].Name != "交易系统" {
		t.Fatalf("缺少交易系统：%+v", items)
	}
	for _, item := range items {
		if item.Tier != "normal" {
			t.Fatalf("未登记业务系统应默认一般：%+v", item)
		}
		if item.Name == "交易系统" && item.AssetCount != 2 {
			t.Fatalf("交易系统资产数应为 2，实际 %d", item.AssetCount)
		}
	}

	if err := repo.Upsert(ctx, ports.BusinessSystem{Name: "交易系统", Tier: "core", Owner: "张三"}, "2026-11-01T10:00:00+08:00"); err != nil {
		t.Fatalf("保存业务系统失败：%v", err)
	}
	tier, err := repo.GetTier(ctx, "交易系统")
	if err != nil || tier != "core" {
		t.Fatalf("业务系统重要性未更新：%s err=%v", tier, err)
	}
	if tier, _ := repo.GetTier(ctx, "未知系统"); tier != "normal" {
		t.Fatalf("未知业务系统应返回 normal，实际 %s", tier)
	}

	if err := repo.Delete(ctx, "交易系统"); err != nil {
		t.Fatalf("删除业务系统失败：%v", err)
	}
	if err := repo.Delete(ctx, "交易系统"); err != ports.ErrNotFound {
		t.Fatalf("重复删除应返回 ErrNotFound，实际 %v", err)
	}
	// 删除登记后仍会按资产档案补回一般业务
	items, _ = repo.List(ctx)
	if len(items) != 2 {
		t.Fatalf("删除后应按资产档案补回：%+v", items)
	}
}

func TestRelationRepoCRUD(t *testing.T) {
	base := newTestDB(t)
	ctx := context.Background()
	targetID, err := base.UpsertReported(ctx, "host-02", "10.0.0.2", "linux", "debian12", "agent", "online", "2026-11-01T10:00:00+08:00")
	if err != nil {
		t.Fatalf("写入目标资产失败：%v", err)
	}

	id, err := base.CreateRelation(ctx, 1, targetID, "depends_on", "2026-11-01T10:01:00+08:00")
	if err != nil || id == 0 {
		t.Fatalf("创建关系失败：id=%d err=%v", id, err)
	}
	again, err := base.CreateRelation(ctx, 1, targetID, "depends_on", "2026-11-01T10:02:00+08:00")
	if err != nil || again != id {
		t.Fatalf("重复创建关系应幂等：id=%d again=%d err=%v", id, again, err)
	}

	fromRelations, err := base.Relations(ctx, 1)
	if err != nil || len(fromRelations) != 1 {
		t.Fatalf("源资产关系异常：len=%d err=%v", len(fromRelations), err)
	}
	if fromRelations[0].Direction != "out" || fromRelations[0].Asset.Hostname != "host-02" {
		t.Fatalf("出方向关系不正确：%+v", fromRelations[0])
	}
	toRelations, err := base.Relations(ctx, targetID)
	if err != nil || len(toRelations) != 1 || toRelations[0].Direction != "in" {
		t.Fatalf("入方向关系不正确：%+v err=%v", toRelations, err)
	}

	if _, err := base.db.Exec(`INSERT INTO asset_relations(from_asset_id, to_asset_id, relation, created_at)
		VALUES(?,?, 'merged_into','')`, 1, targetID); err != nil {
		t.Fatalf("写入合并关系失败：%v", err)
	}
	edges, err := base.RelationEdges(ctx)
	if err != nil || len(edges) != 1 || edges[0].Relation != "depends_on" {
		t.Fatalf("拓扑边应排除 merged_into：%+v err=%v", edges, err)
	}

	if err := base.DeleteRelation(ctx, id); err != nil {
		t.Fatalf("删除关系失败：%v", err)
	}
	if err := base.DeleteRelation(ctx, id); err != ports.ErrNotFound {
		t.Fatalf("重复删除应返回 ErrNotFound，实际 %v", err)
	}
	if relations, _ := base.Relations(ctx, 1); len(relations) != 1 {
		t.Fatalf("删除后应只剩合并关系：%+v", relations)
	}
}

func TestGovernanceRepoSummaryAndList(t *testing.T) {
	base := newTestDB(t)
	repo := NewGovernanceRepo(base.db)
	ctx := context.Background()
	now := "2026-11-01T10:00:00+08:00"
	staleCutoff := "2026-10-25T10:00:00+08:00"
	changeCutoff := "2026-10-02T10:00:00+08:00"

	// 新增一台责任人齐全、最近上报的资产
	if _, err := base.db.Exec(`INSERT INTO assets(hostname, ip, owner, source, last_seen_at)
		VALUES('web-02','10.0.0.2','张三','agent',?)`, now); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	// 两台共享 IP 的疑似重复资产（责任人与时间齐全，避免干扰其他统计）
	if _, err := base.db.Exec(`INSERT INTO assets(hostname, ip, owner, source, last_seen_at) VALUES
		('dup-a','10.0.0.50','李四','agent',?), ('dup-b','10.0.0.50','李四','agent',?)`, now, now); err != nil {
		t.Fatalf("写入重复资产失败：%v", err)
	}
	if _, err := base.db.Exec(`INSERT INTO asset_changes(asset_id, field, old_value, new_value, actor, source, created_at)
		VALUES(2,'exposure','internal','public','管理员','manual',?)`, now); err != nil {
		t.Fatalf("写入变更记录失败：%v", err)
	}

	summary, err := repo.Summary(ctx, staleCutoff, changeCutoff)
	if err != nil {
		t.Fatalf("统计治理待办失败：%v", err)
	}
	if summary.OwnerMissing != 1 || summary.Stale != 1 || summary.Duplicate != 1 || summary.ExposureChanged != 1 {
		t.Fatalf("治理统计异常：%+v", summary)
	}

	ownerItems, total, err := repo.List(ctx, "owner_missing", staleCutoff, changeCutoff, 10, 0)
	if err != nil || total != 1 || len(ownerItems) != 1 || ownerItems[0].Hostname != "host-01" {
		t.Fatalf("责任人缺失列表异常：total=%d items=%+v err=%v", total, ownerItems, err)
	}
	staleItems, total, err := repo.List(ctx, "stale", staleCutoff, changeCutoff, 10, 0)
	if err != nil || total != 1 || len(staleItems) != 1 {
		t.Fatalf("失联列表异常：total=%d items=%+v err=%v", total, staleItems, err)
	}
	dupItems, total, err := repo.List(ctx, "duplicate", staleCutoff, changeCutoff, 10, 0)
	if err != nil || total != 1 || len(dupItems) != 1 || len(dupItems[0].Related) != 2 {
		t.Fatalf("重复资产列表异常：total=%d items=%+v err=%v", total, dupItems, err)
	}
	changeItems, total, err := repo.List(ctx, "exposure_changed", staleCutoff, changeCutoff, 10, 0)
	if err != nil || total != 1 || len(changeItems) != 1 || changeItems[0].NewValue != "public" {
		t.Fatalf("暴露面变化列表异常：total=%d items=%+v err=%v", total, changeItems, err)
	}
}
