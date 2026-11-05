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

func TestJobRepoCreateIdempotentWindowAndTerminalStates(t *testing.T) {
	repo, assetID := openJobDB(t)
	ctx := context.Background()
	since := "2026-01-01T09:55:00+08:00"

	first := sampleJob("JOB-IDEM-1", assetID, "key-window", "2026-01-01T10:00:00+08:00")
	stored, created, err := repo.CreateIdempotent(ctx, first, since)
	if err != nil || !created || stored.ID != first.ID {
		t.Fatalf("首次创建失败：created=%v job=%+v err=%v", created, stored, err)
	}
	duplicate := sampleJob("JOB-IDEM-DUP", assetID, "key-window", "2026-01-01T10:01:00+08:00")
	stored, created, err = repo.CreateIdempotent(ctx, duplicate, since)
	if err != nil || created || stored.ID != first.ID {
		t.Fatalf("窗口内应返回原作业：created=%v job=%+v err=%v", created, stored, err)
	}

	if _, err := repo.db.Exec(`UPDATE host_jobs SET status='failed', finished_at=created_at WHERE id=?`, first.ID); err != nil {
		t.Fatal(err)
	}
	second := sampleJob("JOB-IDEM-2", assetID, "key-window", "2026-01-01T10:02:00+08:00")
	stored, created, err = repo.CreateIdempotent(ctx, second, since)
	if err != nil || !created || stored.ID != second.ID {
		t.Fatalf("失败后应允许新建：created=%v job=%+v err=%v", created, stored, err)
	}

	if _, err := repo.db.Exec(`UPDATE host_jobs SET status='canceled', finished_at=created_at WHERE id=?`, second.ID); err != nil {
		t.Fatal(err)
	}
	third := sampleJob("JOB-IDEM-3", assetID, "key-window", "2026-01-01T10:03:00+08:00")
	stored, created, err = repo.CreateIdempotent(ctx, third, since)
	if err != nil || !created || stored.ID != third.ID {
		t.Fatalf("取消后应允许新建：created=%v job=%+v err=%v", created, stored, err)
	}

	if _, err := repo.db.Exec(`UPDATE host_jobs SET status='succeeded', finished_at=created_at WHERE id=?`, third.ID); err != nil {
		t.Fatal(err)
	}
	fourth := sampleJob("JOB-IDEM-4", assetID, "key-window", "2026-01-01T10:21:00+08:00")
	stored, created, err = repo.CreateIdempotent(ctx, fourth, "2026-01-01T10:11:00+08:00")
	if err != nil || !created || stored.ID != fourth.ID {
		t.Fatalf("超出窗口应允许新建：created=%v job=%+v err=%v", created, stored, err)
	}
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM host_jobs WHERE idempotency_key=?`, "key-window").Scan(&count); err != nil || count != 4 {
		t.Fatalf("历史作业应全部保留：count=%d err=%v", count, err)
	}
}

func TestJobRepoCompleteOnceRejectsDuplicate(t *testing.T) {
	repo, assetID := openJobDB(t)
	ctx := context.Background()
	job := sampleJob("JOB-ONCE", assetID, "key-once", "2026-01-01T10:00:00+08:00")
	if err := repo.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.Claim(ctx, job.ID, "job-host", "2026-01-01T10:01:00+08:00"); err != nil || !ok {
		t.Fatalf("抢占失败：ok=%v err=%v", ok, err)
	}
	applied, err := repo.CompleteOnce(ctx, job.ID, 1, "succeeded", "first", "", 0, "2026-01-01T10:02:00+08:00", "")
	if err != nil || !applied {
		t.Fatalf("首次完成失败：applied=%v err=%v", applied, err)
	}
	applied, err = repo.CompleteOnce(ctx, job.ID, 1, "succeeded", "duplicate", "", 0, "2026-01-01T10:03:00+08:00", "")
	if err != nil || applied {
		t.Fatalf("重复完成应被忽略：applied=%v err=%v", applied, err)
	}
	got, _, _ := repo.ByID(ctx, job.ID)
	if got.Output != "first" {
		t.Fatalf("重复结果覆盖了首次结果：%+v", got)
	}
	var attempts int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM host_job_attempts WHERE job_id=?`, job.ID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("重复完成不应新增尝试记录：count=%d err=%v", attempts, err)
	}
}

func TestJobRepoLeaseRecovery(t *testing.T) {
	repo, assetID := openJobDB(t)
	ctx := context.Background()
	job := sampleJob("JOB-LEASE", assetID, "key-lease", "2026-01-01T10:00:00+08:00")
	if err := repo.Create(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.Claim(ctx, job.ID, "job-host", "2026-01-01T10:00:30+08:00"); err != nil || !ok {
		t.Fatalf("抢占失败：ok=%v err=%v", ok, err)
	}
	if n, err := repo.RecoverExpired(ctx, "2026-01-01T10:01:00+08:00", "2026-01-01T09:59:00+08:00"); err != nil || n != 0 {
		t.Fatalf("未到期作业不应回收：n=%d err=%v", n, err)
	}
	if n, err := repo.RecoverExpired(ctx, "2026-01-01T10:04:00+08:00", "2026-01-01T10:01:00+08:00"); err != nil || n != 1 {
		t.Fatalf("到期作业应回收：n=%d err=%v", n, err)
	}
	got, _, _ := repo.ByID(ctx, job.ID)
	if got.Status != "pending" || got.NextRunAt == "" {
		t.Fatalf("租约回收后应重新排队：%+v", got)
	}
	if applied, err := repo.CompleteOnce(ctx, job.ID, 1, "succeeded", "late", "", 0, "2026-01-01T10:04:30+08:00", ""); err != nil || applied {
		t.Fatalf("过期尝试的迟到结果应被忽略：applied=%v err=%v", applied, err)
	}

	if _, ok, err := repo.Claim(ctx, job.ID, "job-host", "2026-01-01T10:05:00+08:00"); err != nil || !ok {
		t.Fatalf("第二次抢占失败：ok=%v err=%v", ok, err)
	}
	if n, err := repo.RecoverExpired(ctx, "2026-01-01T10:09:00+08:00", "2026-01-01T10:06:00+08:00"); err != nil || n != 1 {
		t.Fatalf("第二次租约回收失败：n=%d err=%v", n, err)
	}
	if _, ok, err := repo.Claim(ctx, job.ID, "job-host", "2026-01-01T10:10:00+08:00"); err != nil || !ok {
		t.Fatalf("第三次抢占失败：ok=%v err=%v", ok, err)
	}
	if n, err := repo.RecoverExpired(ctx, "2026-01-01T10:14:00+08:00", "2026-01-01T10:11:00+08:00"); err != nil || n != 1 {
		t.Fatalf("第三次租约回收失败：n=%d err=%v", n, err)
	}
	got, _, _ = repo.ByID(ctx, job.ID)
	if got.Status != "failed" || got.FinishedAt == "" {
		t.Fatalf("超过最大尝试次数后应失败：%+v", got)
	}
	var expired int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM host_job_attempts WHERE job_id=? AND status='expired'`, job.ID).Scan(&expired); err != nil || expired != 3 {
		t.Fatalf("每次租约回收都应留痕：count=%d err=%v", expired, err)
	}
}
