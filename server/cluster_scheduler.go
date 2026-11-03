package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// startClusterCheckScheduler 按固定间隔对所有含节点的集群执行只读检查，为 SLO 与趋势持续采样。
// VA_CLUSTER_CHECK_INTERVAL 缺省 10m；设为 0/off 关闭。
func (a *App) startClusterCheckScheduler(ctx context.Context) {
	raw := strings.TrimSpace(os.Getenv("VA_CLUSTER_CHECK_INTERVAL"))
	if raw == "" {
		raw = "10m"
	}
	if raw == "0" || strings.EqualFold(raw, "off") {
		slog.Info("集群定时检查未启用", "hint", "VA_CLUSTER_CHECK_INTERVAL=0/off")
		return
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval < time.Minute {
		interval = 10 * time.Minute
	}
	var running atomic.Bool
	slog.Info("集群定时检查已启动", "interval", interval.String())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// 启动后先等待一个短窗口，避免和初始化任务争抢资源。
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		for {
			if !running.Load() {
				running.Store(true)
				go func() {
					defer running.Store(false)
					a.runScheduledClusterChecks(ctx)
				}()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (a *App) runScheduledClusterChecks(ctx context.Context) {
	clusters, err := a.listClusters(ctx, 0)
	if err != nil {
		slog.Warn("集群定时检查读取集群失败", "err", err)
		return
	}
	started := 0
	for _, cluster := range clusters {
		if ctx.Err() != nil {
			return
		}
		if cluster.NodeCount == 0 {
			continue
		}
		var active int
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_jobs
			WHERE cluster_id = ? AND status IN ('queued','running')`, cluster.ID).Scan(&active); err != nil {
			continue
		}
		if active > 0 {
			continue
		}
		if _, err := a.startClusterJob(ctx, cluster.ID, "check", "scheduler"); err != nil {
			slog.Warn("集群定时检查启动失败", "cluster", cluster.Name, "err", err)
			continue
		}
		started++
	}
	// 任务记录保留 30 天，避免长期运行后无限增长。
	cutoff := fmtT(nowT().Add(-30 * 24 * time.Hour))
	if _, err := a.db.ExecContext(ctx, `DELETE FROM cluster_jobs
		WHERE status NOT IN ('queued','running') AND finished_at != '' AND finished_at < ?`, cutoff); err != nil {
		slog.Warn("清理集群历史任务失败", "err", err)
	}
	if started > 0 {
		slog.Info("集群定时检查已排队", "clusters", started)
	}
}
