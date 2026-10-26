package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func openTicketDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "ticket.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sampleTicket(id string, findingID int64, status, assignee, updatedAt string) ports.Ticket {
	return ports.Ticket{
		ID:        id,
		FindingID: findingID,
		CVEID:     "CVE-TEST-0001",
		AssetID:   1,
		Priority:  "P1",
		Status:    status,
		Assignee:  assignee,
		CreatedBy: "李维",
		Note:      "测试工单",
		CreatedAt: "2026-01-01T09:00:00+08:00",
		UpdatedAt: updatedAt,
	}
}

func TestTicketRepoCreateAndByFinding(t *testing.T) {
	db := openTicketDB(t)
	repo := NewTicketRepo(db)
	ctx := context.Background()

	want := sampleTicket("VA-2026-0001", 42, "fixing", "李维", "2026-01-02T10:00:00+08:00")
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("创建工单失败：%v", err)
	}

	got, found, err := repo.ByFinding(ctx, 42)
	if err != nil {
		t.Fatalf("按漏洞读取工单失败：%v", err)
	}
	if !found {
		t.Fatal("已创建的工单应能查到")
	}
	if got.ID != want.ID || got.CVEID != want.CVEID || got.AssetID != want.AssetID ||
		got.Priority != want.Priority || got.Status != want.Status || got.Assignee != want.Assignee ||
		got.CreatedBy != want.CreatedBy || got.Note != want.Note ||
		got.CreatedAt != want.CreatedAt || got.UpdatedAt != want.UpdatedAt {
		t.Fatalf("工单字段不一致：%+v", got)
	}

	if _, found, err := repo.ByFinding(ctx, 404); err != nil || found {
		t.Fatalf("不存在的漏洞应返回 found=false：found=%v err=%v", found, err)
	}

	if err := repo.Create(ctx, sampleTicket("VA-2026-0001", 43, "open", "", "")); err == nil {
		t.Fatal("重复工单号应被主键约束拒绝")
	}
}

func TestTicketRepoListAndUpdateStatus(t *testing.T) {
	db := openTicketDB(t)
	repo := NewTicketRepo(db)
	ctx := context.Background()

	items := []ports.Ticket{
		sampleTicket("VA-2026-0001", 1, "fixing", "李维", "2026-01-01T10:00:00+08:00"),
		sampleTicket("VA-2026-0002", 2, "fixed", "王倩", "2026-01-03T10:00:00+08:00"),
		sampleTicket("VA-2026-0003", 3, "fixing", "陈可", "2026-01-02T10:00:00+08:00"),
	}
	for _, item := range items {
		if err := repo.Create(ctx, item); err != nil {
			t.Fatalf("创建工单 %s 失败：%v", item.ID, err)
		}
	}

	all, err := repo.List(ctx, "", 10)
	if err != nil {
		t.Fatalf("查询工单列表失败：%v", err)
	}
	if len(all) != 3 {
		t.Fatalf("应返回 3 张工单，实际 %d", len(all))
	}
	if all[0].ID != "VA-2026-0002" || all[1].ID != "VA-2026-0003" || all[2].ID != "VA-2026-0001" {
		t.Fatalf("应按 updated_at 倒序：%+v", []string{all[0].ID, all[1].ID, all[2].ID})
	}

	fixing, err := repo.List(ctx, "fixing", 10)
	if err != nil || len(fixing) != 2 {
		t.Fatalf("按状态过滤失败：len=%d err=%v", len(fixing), err)
	}
	for _, item := range fixing {
		if item.Status != "fixing" {
			t.Fatalf("过滤结果包含非 fixing 工单：%+v", item)
		}
	}

	limited, err := repo.List(ctx, "", 2)
	if err != nil || len(limited) != 2 {
		t.Fatalf("limit 未生效：len=%d err=%v", len(limited), err)
	}

	if err := repo.UpdateStatus(ctx, "VA-2026-0001", "verified", "李维", "2026-01-04T10:00:00+08:00"); err != nil {
		t.Fatalf("同步工单状态失败：%v", err)
	}
	got, found, err := repo.ByFinding(ctx, 1)
	if err != nil || !found {
		t.Fatalf("同步后读取失败：found=%v err=%v", found, err)
	}
	if got.Status != "verified" || got.Assignee != "李维" || got.UpdatedAt != "2026-01-04T10:00:00+08:00" {
		t.Fatalf("状态同步未生效：%+v", got)
	}
}
