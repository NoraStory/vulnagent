package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func openJobDB(t *testing.T) (*JobRepo, int64) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO assets(hostname, exposure, tier, source) VALUES('job-host','internal','normal','agent')`); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	var assetID int64
	if err := db.QueryRow(`SELECT id FROM assets WHERE hostname = 'job-host'`).Scan(&assetID); err != nil {
		t.Fatalf("读取资产失败：%v", err)
	}
	return NewJobRepo(db), assetID
}

func sampleJob(id string, assetID int64, key, created string) ports.HostJob {
	return ports.HostJob{
		ID: id, AssetID: assetID, Action: "run_command", Params: `{"argv":["whoami"]}`,
		Risk: "high", Status: "pending", RequestedBy: "李维", IdempotencyKey: key,
		MaxAttempts: 3, CreatedAt: created,
	}
}

func TestJobRepoDueClaimComplete(t *testing.T) {
	repo, assetID := openJobDB(t)
	ctx := context.Background()

	job := sampleJob("JOB-1", assetID, "key-1", "2026-01-01T10:00:00+08:00")
	if err := repo.Create(ctx, job); err != nil {
		t.Fatalf("创建作业失败：%v", err)
	}
	due, err := repo.DueForHost(ctx, "job-host", "2026-01-01T10:05:00+08:00", 5)
	if err != nil || len(due) != 1 || due[0].ID != "JOB-1" {
		t.Fatalf("到期作业查询异常：%+v err=%v", due, err)
	}

	claimed, ok, err := repo.Claim(ctx, "JOB-1", "job-host", "2026-01-01T10:06:00+08:00")
	if err != nil || !ok {
		t.Fatalf("抢占失败：ok=%v err=%v", ok, err)
	}
	if claimed.Attempts != 1 || claimed.Status != "running" {
		t.Fatalf("抢占后状态异常：%+v", claimed)
	}
	if _, ok, _ := repo.Claim(ctx, "JOB-1", "job-host", "2026-01-01T10:06:01+08:00"); ok {
		t.Fatal("同一作业不应被重复抢占")
	}
	if _, ok, _ := repo.Claim(ctx, "JOB-1", "other-host", "2026-01-01T10:06:01+08:00"); ok {
		t.Fatal("其他主机不应抢占该作业")
	}

	if err := repo.Complete(ctx, "JOB-1", "succeeded", "ok output", "", 0, "2026-01-01T10:07:00+08:00", ""); err != nil {
		t.Fatalf("写入结果失败：%v", err)
	}
	got, _, _ := repo.ByID(ctx, "JOB-1")
	if got.Status != "succeeded" || got.Output != "ok output" || got.FinishedAt == "" {
		t.Fatalf("结果未落库：%+v", got)
	}
}

func TestJobRepoRetryAndIdempotency(t *testing.T) {
	repo, assetID := openJobDB(t)
	ctx := context.Background()

	job := sampleJob("JOB-R", assetID, "key-retry", "2026-01-01T10:00:00+08:00")
	if err := repo.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.Claim(ctx, "JOB-R", "job-host", "2026-01-01T10:01:00+08:00"); err != nil || !ok {
		t.Fatalf("抢占失败：%v", err)
	}
	if err := repo.Complete(ctx, "JOB-R", "pending", "", "临时网络错误", -1,
		"2026-01-01T10:02:00+08:00", "2026-01-01T10:02:10+08:00"); err != nil {
		t.Fatalf("安排重试失败：%v", err)
	}
	got, _, _ := repo.ByID(ctx, "JOB-R")
	if got.Status != "pending" || got.NextRunAt == "" || got.FinishedAt != "" {
		t.Fatalf("重试状态异常：%+v", got)
	}
	if due, _ := repo.DueForHost(ctx, "job-host", "2026-01-01T10:02:05+08:00", 5); len(due) != 0 {
		t.Fatalf("未到重试时间不应返回：%+v", due)
	}
	if due, _ := repo.DueForHost(ctx, "job-host", "2026-01-01T10:02:11+08:00", 5); len(due) != 1 {
		t.Fatalf("到重试时间应返回：%+v", due)
	}

	if existing, found, err := repo.ExistingByIdempotency(ctx, "key-retry", "2026-01-01T09:55:00+08:00"); err != nil || !found || existing.ID != "JOB-R" {
		t.Fatalf("幂等查询异常：found=%v job=%+v err=%v", found, existing, err)
	}
	if _, found, _ := repo.ExistingByIdempotency(ctx, "key-retry", "2026-01-02T00:00:00+08:00"); found {
		t.Fatal("超出窗口不应命中幂等")
	}

	second := sampleJob("JOB-2", assetID, "key-2", "2026-01-01T10:03:00+08:00")
	second.Action = "write_file"
	if err := repo.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	list, err := repo.ListByAsset(ctx, assetID, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("资产作业列表异常：len=%d err=%v", len(list), err)
	}
	if list[0].ID != "JOB-2" {
		t.Fatalf("应按创建时间倒序：%+v", list)
	}
}
