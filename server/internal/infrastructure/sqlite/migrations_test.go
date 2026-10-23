package sqlite

import (
	"path/filepath"
	"testing"
)

func TestMigrateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("首次打开失败：%v", err)
	}
	var versions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("读取迁移记录失败：%v", err)
	}
	if versions < 2 {
		t.Fatalf("迁移记录应至少有 2 条，实际 %d", versions)
	}
	// 基线表与新增索引都必须存在
	var name string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='findings'`).Scan(&name); err != nil {
		t.Fatalf("findings 表不存在：%v", err)
	}
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_findings_priority'`).Scan(&name); err != nil {
		t.Fatalf("idx_findings_priority 索引不存在：%v", err)
	}
	if _, err := db.Exec(`INSERT INTO app_meta(key, value, updated_at) VALUES('k','v','')`); err != nil {
		t.Fatalf("写数据失败：%v", err)
	}
	db.Close()

	// 第二次打开不应重复执行迁移，也不应清空数据
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("二次打开失败：%v", err)
	}
	defer db2.Close()
	var after int
	if err := db2.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != versions {
		t.Fatalf("重复迁移：%d → %d", versions, after)
	}
	var value string
	if err := db2.QueryRow(`SELECT value FROM app_meta WHERE key='k'`).Scan(&value); err != nil || value != "v" {
		t.Fatalf("既有数据丢失：value=%q err=%v", value, err)
	}
}

func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	rw, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rw.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("打开只读连接失败：%v", err)
	}
	defer ro.Close()
	if _, err := ro.Exec(`INSERT INTO app_meta(key, value, updated_at) VALUES('x','y','')`); err == nil {
		t.Fatal("只读连接不应允许写入")
	}
}
