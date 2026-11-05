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

func TestMigrateJobIdempotencyUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate-jobs.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('legacy-host','internal','normal','agent')`); err != nil {
		t.Fatal(err)
	}
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname='legacy-host'`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	if err := NewJobRepo(db).Create(t.Context(), sampleJob("JOB-LEGACY-1", assetID, "legacy-key", "2026-01-01T10:00:00+08:00")); err != nil {
		t.Fatal(err)
	}
	// 模拟 0028 之前的结构与迁移记录，验证升级而不是仅验证全新数据库。
	if _, err := db.Exec(`DROP INDEX idx_host_jobs_idem`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX idx_host_jobs_idem ON host_jobs(idempotency_key) WHERE idempotency_key <> ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM schema_migrations WHERE version='0028_job_idempotency'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("旧库升级失败：%v", err)
	}
	defer upgraded.Close()
	if err := NewJobRepo(upgraded).Create(t.Context(), sampleJob("JOB-LEGACY-2", assetID, "legacy-key", "2026-01-01T10:11:00+08:00")); err != nil {
		t.Fatalf("升级后同键历史不应阻止新作业：%v", err)
	}
	var count int
	if err := upgraded.QueryRow(`SELECT COUNT(*) FROM host_jobs WHERE idempotency_key='legacy-key'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("升级后历史作业保留异常：count=%d err=%v", count, err)
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
