package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/platform/config"
)

// startIntelSyncScheduler 定时同步 CVE 与 POC 情报（默认每 12 小时），
// 启动时如果距上次成功同步已超过一个周期，先补一次。
func (a *App) startIntelSyncScheduler(ctx context.Context) {
	interval := config.Load().SyncInterval
	if interval <= 0 {
		slog.Info("定时情报同步已关闭", "hint", "VA_SYNC_INTERVAL=12h 可开启")
		return
	}
	slog.Info("定时情报同步已启动", "interval", interval.String())
	go func() {
		if syncLagHours(a.db, "cve") >= interval.Hours() {
			a.syncIntel("系统（启动补同步）")
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.syncIntel("系统（定时）")
			}
		}
	}()
}

// intelFreshnessThresholds 按同步周期给出 CVE 新鲜度的 warn/fail 阈值：
// 12h 周期下为 18h / 24h；关闭定时同步时放宽为 24h / 48h。
func intelFreshnessThresholds() (warnHours, failHours float64) {
	interval := config.Load().SyncInterval
	if interval <= 0 {
		return 24, 48
	}
	hours := interval.Hours()
	return hours + 6, hours * 2
}

// syncIntel 依次同步 CVE 与 POC，每个来源独立超时，互不阻塞。
func (a *App) syncIntel(actor string) {
	client := newCVEClient(intelBaseURLFromEnv(), strings.TrimSpace(os.Getenv("VULNAGENT_CVE_API_KEY")))

	cveCtx, cveCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	cveRes, cveErr := syncCVEFromAPI(cveCtx, a.db, client, 20)
	cveCancel()
	if cveErr != nil {
		slog.Warn("定时 CVE 同步失败", "err", cveErr)
		a.dispatch("sync.failed", map[string]any{"source": "cve", "error": cveErr.Error()})
		a.auditAs(actor, "system", "127.0.0.1", "sync", "sync.cve", "cve", "定时同步失败："+cveErr.Error())
	} else {
		slog.Info("定时 CVE 同步完成", "fetched", cveRes.Fetched,
			"inserted", cveRes.Inserted, "updated", cveRes.Updated)
		a.auditAs(actor, "system", "127.0.0.1", "sync", "sync.cve", "cve",
			"定时同步完成：新增 "+strconv.Itoa(cveRes.Inserted)+" 条，更新 "+strconv.Itoa(cveRes.Updated)+" 条")
	}

	pocCtx, pocCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	pocRes, pocErr := syncPOCFromAPI(pocCtx, a.db, client, 10)
	pocCancel()
	if pocErr != nil {
		slog.Warn("定时 POC 同步失败", "err", pocErr)
		a.dispatch("sync.failed", map[string]any{"source": "poc", "error": pocErr.Error()})
		a.auditAs(actor, "system", "127.0.0.1", "sync", "sync.poc", "poc", "定时同步失败："+pocErr.Error())
	} else {
		slog.Info("定时 POC 同步完成", "fetched", pocRes.Fetched, "inserted", pocRes.Inserted)
		a.auditAs(actor, "system", "127.0.0.1", "sync", "sync.poc", "poc",
			"定时同步完成：新增 "+strconv.Itoa(pocRes.Inserted)+" 条")
	}
}
