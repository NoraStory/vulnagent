package sqlite

import (
	"context"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func TestDiscoveryJobLifecycle(t *testing.T) {
	base := newTestDB(t)
	repo := NewDiscoveryRepo(base.db)
	ctx := context.Background()

	jobID, err := repo.CreateJob(ctx, ports.DiscoveryJob{
		Name: "测试发现", CIDRs: "10.0.0.0/30", Ports: "22,80", Status: "pending",
		Total: 4, Options: "{}", CreatedBy: "管理员", CreatedAt: "2026-11-01T10:00:00+08:00",
	})
	if err != nil {
		t.Fatalf("创建任务失败：%v", err)
	}
	job, err := repo.GetJob(ctx, jobID)
	if err != nil || job.Total != 4 || job.Status != "pending" {
		t.Fatalf("读取任务异常：%+v err=%v", job, err)
	}
	if running, err := repo.CountRunningJobs(ctx); err != nil || running != 1 {
		t.Fatalf("运行中任务统计异常：%d err=%v", running, err)
	}
	if count, err := repo.CountJobsSince(ctx, "2026-01-01T00:00:00+08:00"); err != nil || count != 1 {
		t.Fatalf("限流统计异常：%d err=%v", count, err)
	}

	if err := repo.UpdateJobProgress(ctx, jobID, 2, 1); err != nil {
		t.Fatalf("更新进度失败：%v", err)
	}
	job, _ = repo.GetJob(ctx, jobID)
	if job.Scanned != 2 || job.Found != 1 {
		t.Fatalf("进度未更新：%+v", job)
	}

	if err := repo.RequestCancel(ctx, jobID); err != nil {
		t.Fatalf("取消任务失败：%v", err)
	}
	if requested, err := repo.CancelRequested(ctx, jobID); err != nil || !requested {
		t.Fatalf("取消标记异常：%v err=%v", requested, err)
	}

	if err := repo.FinishJob(ctx, jobID, "cancelled", "", "2026-11-01T10:05:00+08:00"); err != nil {
		t.Fatalf("结束任务失败：%v", err)
	}
	job, _ = repo.GetJob(ctx, jobID)
	if job.Status != "cancelled" || job.FinishedAt == "" {
		t.Fatalf("任务结束状态异常：%+v", job)
	}
	if running, _ := repo.CountRunningJobs(ctx); running != 0 {
		t.Fatalf("结束后运行中任务应为 0，实际 %d", running)
	}
}

func TestDiscoveryInterruptUnfinishedJobs(t *testing.T) {
	base := newTestDB(t)
	repo := NewDiscoveryRepo(base.db)
	ctx := context.Background()

	jobID, err := repo.CreateJob(ctx, ports.DiscoveryJob{
		Name: "中断任务", CIDRs: "10.0.0.0/30", Ports: "22", Status: "running", Total: 4,
		CreatedAt: "2026-11-01T10:00:00+08:00",
	})
	if err != nil {
		t.Fatalf("创建任务失败：%v", err)
	}
	n, err := repo.InterruptUnfinishedJobs(ctx)
	if err != nil || n != 1 {
		t.Fatalf("中断任务清理异常：n=%d err=%v", n, err)
	}
	job, _ := repo.GetJob(ctx, jobID)
	if job.Status != "failed" || job.Error == "" {
		t.Fatalf("中断任务未标记失败：%+v", job)
	}
}

func TestDiscoveryCandidates(t *testing.T) {
	base := newTestDB(t)
	repo := NewDiscoveryRepo(base.db)
	ctx := context.Background()
	jobID, err := repo.CreateJob(ctx, ports.DiscoveryJob{
		Name: "候选测试", CIDRs: "10.0.0.0/30", Ports: "22", Status: "completed", Total: 4,
		CreatedAt: "2026-11-01T10:00:00+08:00",
	})
	if err != nil {
		t.Fatalf("创建任务失败：%v", err)
	}

	first, err := repo.InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.1", OpenPorts: "22", Services: "[]", Evidence: "tcp/22 open",
		Decision: "new", Confidence: 0.6, CreatedAt: "2026-11-01T10:01:00+08:00",
	})
	if err != nil {
		t.Fatalf("写入候选失败：%v", err)
	}
	again, err := repo.InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.1", OpenPorts: "22", Decision: "new",
	})
	if err != nil || again != first {
		t.Fatalf("同一 IP 候选应幂等：first=%d again=%d err=%v", first, again, err)
	}
	if _, err := repo.InsertCandidate(ctx, ports.DiscoveryCandidate{
		JobID: jobID, IP: "10.0.0.2", Hostname: "web-01", OpenPorts: "80,443",
		MatchedAssetID: 1, Decision: "existing", Confidence: 0.95,
	}); err != nil {
		t.Fatalf("写入候选失败：%v", err)
	}

	items, total, err := repo.ListCandidates(ctx, ports.DiscoveryCandidateFilter{JobID: jobID}, 10, 0)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("候选列表异常：total=%d len=%d err=%v", total, len(items), err)
	}
	if filtered, total, err := repo.ListCandidates(ctx, ports.DiscoveryCandidateFilter{JobID: jobID, Decision: "existing"}, 10, 0); err != nil || total != 1 || filtered[0].Hostname != "web-01" {
		t.Fatalf("按处置状态筛选异常：total=%d err=%v", total, err)
	}
	if matched, total, err := repo.ListCandidates(ctx, ports.DiscoveryCandidateFilter{Query: "web-01"}, 10, 0); err != nil || total != 1 || matched[0].IP != "10.0.0.2" {
		t.Fatalf("关键词筛选异常：total=%d err=%v", total, err)
	}

	if err := repo.SetCandidateDecision(ctx, first, "approved", 1, "管理员", "2026-11-01T10:02:00+08:00"); err != nil {
		t.Fatalf("更新候选决策失败：%v", err)
	}
	candidate, err := repo.GetCandidate(ctx, first)
	if err != nil || candidate.Decision != "approved" || candidate.AssetID != 1 {
		t.Fatalf("候选决策未更新：%+v err=%v", candidate, err)
	}
	counts, err := repo.CountCandidates(ctx, jobID)
	if err != nil || counts["approved"] != 1 || counts["existing"] != 1 {
		t.Fatalf("候选统计异常：%v err=%v", counts, err)
	}
}
