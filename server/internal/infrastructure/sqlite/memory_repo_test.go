package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func TestMemoryRepoSearchAndDelete(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewMemoryRepo(db)
	ctx := context.Background()

	id, err := repo.Save(ctx, ports.Memory{
		Scope: "global", Content: "web-01 使用 nginx 1.24",
		CreatedAt: "2026-01-01T10:00:00+08:00", UpdatedAt: "2026-01-01T10:00:00+08:00",
	})
	if err != nil || id == 0 {
		t.Fatalf("写入记忆失败：id=%d err=%v", id, err)
	}
	if _, err := repo.Save(ctx, ports.Memory{
		Scope: "asset", ScopeKey: "asset:1", Content: "该主机运行 Rocky Linux 9",
		CreatedAt: "2026-01-01T11:00:00+08:00", UpdatedAt: "2026-01-01T11:00:00+08:00",
	}); err != nil {
		t.Fatal(err)
	}

	global, err := repo.Search(ctx, "global", "", "nginx", 10)
	if err != nil || len(global) != 1 || global[0].Content == "" {
		t.Fatalf("记忆检索异常：%+v err=%v", global, err)
	}
	scoped, err := repo.Search(ctx, "asset", "asset:1", "", 10)
	if err != nil || len(scoped) != 1 {
		t.Fatalf("作用域检索异常：%+v err=%v", scoped, err)
	}
	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("删除失败：%v", err)
	}
	if _, err := repo.Search(ctx, "global", "", "nginx", 10); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, id); err == nil {
		t.Fatal("重复删除应返回错误")
	}
}
