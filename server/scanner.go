package main

import (
	"context"
	"log/slog"
	"time"

	"vulnagent/server/internal/platform/config"
)

// scanOutcome 单资产复扫结果
type scanOutcome struct {
	AssetID  int64 `json:"assetId"`
	Skipped  bool  `json:"skipped"`
	Created  int   `json:"created"`
	Updated  int   `json:"updated"`
	Verified int   `json:"verified"`
	Closed   int   `json:"closed"`
	Reopened int   `json:"reopened"`
}

// rescanAsset 对单个资产执行匹配 + 状态收敛。
// 同一资产在防抖窗口内只执行一次，避免重复点击与定时任务叠加。
func (a *App) rescanAsset(assetID int64, actor string) (scanOutcome, error) {
	out := scanOutcome{AssetID: assetID}
	now := time.Now()

	a.scanMu.Lock()
	if a.lastScan == nil {
		a.lastScan = make(map[int64]time.Time)
	}
	if last, ok := a.lastScan[assetID]; ok && a.scanDebounce > 0 && now.Sub(last) < a.scanDebounce {
		a.scanMu.Unlock()
		out.Skipped = true
		return out, nil
	}
	a.lastScan[assetID] = now
	a.scanMu.Unlock()

	created, updated, err := a.matchAssetFindings(loadPolicy(a.db), assetID)
	if err != nil {
		return out, err
	}
	// OSV 覆盖语言生态的精确版本匹配（失败不影响本地区间匹配）
	if _, osvErr := a.osvScanAsset(assetID, actor); osvErr != nil {
		slog.Warn("OSV 匹配失败", "assetId", assetID, "err", osvErr)
	}
	recon, err := a.reconcileFindingStates(assetID, actor)
	if err != nil {
		return out, err
	}
	out.Created, out.Updated = created, updated
	out.Verified, out.Closed, out.Reopened = recon.Verified, recon.Closed, recon.Reopened
	return out, nil
}

// rescanAssets 批量复扫；all 为 true 时覆盖全部资产
func (a *App) rescanAssets(assetIDs []int64, all bool, actor string) ([]scanOutcome, error) {
	ids := assetIDs
	if all {
		list, err := a.assetRepo().IDs(context.Background())
		if err != nil {
			return nil, err
		}
		ids = list
	}
	if len(ids) > 500 {
		ids = ids[:500]
	}
	outcomes := make([]scanOutcome, 0, len(ids))
	for _, id := range ids {
		out, err := a.rescanAsset(id, actor)
		if err != nil {
			slog.Warn("复扫失败", "assetId", id, "err", err)
			continue
		}
		outcomes = append(outcomes, out)
	}
	return outcomes, nil
}

// scanIntervalFromEnv 定时复扫间隔，配置见 internal/platform/config
func scanIntervalFromEnv() time.Duration { return config.Load().RescanInterval }

// scanDebounceFromEnv 同一资产的复扫防抖窗口，配置见 internal/platform/config
func scanDebounceFromEnv() time.Duration { return config.Load().RescanDebounce }

// startScanScheduler 定时对全部资产做复扫（幂等，可随时关闭）
func (a *App) startScanScheduler(ctx context.Context) {
	interval := scanIntervalFromEnv()
	if interval <= 0 {
		slog.Info("定时复扫已关闭", "hint", "VA_RESCAN_INTERVAL=30m 可开启")
		return
	}
	slog.Info("定时复扫已启动", "interval", interval.String(), "debounce", a.scanDebounce.String())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				start := time.Now()
				outcomes, err := a.rescanAssets(nil, true, "系统（定时）")
				if err != nil {
					slog.Warn("定时复扫失败", "err", err)
					continue
				}
				verified, closed, reopened, scanned := 0, 0, 0, 0
				for _, item := range outcomes {
					if item.Skipped {
						continue
					}
					scanned++
					verified += item.Verified
					closed += item.Closed
					reopened += item.Reopened
				}
				slog.Info("定时复扫完成", "assets", scanned, "verified", verified,
					"closed", closed, "reopened", reopened, "elapsedMs", time.Since(start).Milliseconds())
			}
		}
	}()
}
