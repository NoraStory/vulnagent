package main

import (
	"context"
	"log/slog"

	"vulnagent/server/internal/collect"
	"vulnagent/server/internal/domain/asset"
)

// ingestOutcome 一次清单入库的结果
type ingestOutcome struct {
	AssetID    int64
	Components int
	Created    int
	Updated    int
	Verified   int
	Closed     int
	Reopened   int
}

// ingestComponents 统一入库路径：Agent 上报与 SSH 兜底采集共用。
// 流程：upsert 资产 → 整体替换组件 → 版本区间匹配 → 状态收敛。
func (a *App) ingestComponents(hostname, ip, osName, osVersion, source string, components []collect.Component) (ingestOutcome, error) {
	out := ingestOutcome{}
	now := fmtT(nowT())

	agentStatus := "none"
	if source == "agent" {
		agentStatus = "online"
	}

	assetID, err := a.assetRepo().UpsertReported(context.Background(), hostname, ip, osName, osVersion, source, agentStatus, now)
	if err != nil {
		return out, err
	}
	out.AssetID = assetID

	comps := make([]asset.Component, 0, len(components))
	for _, c := range components {
		if c.PURL == "" || c.Name == "" || c.Version == "" {
			continue
		}
		comps = append(comps, asset.Component{
			PURL:    c.PURL,
			Eco:     c.Eco,
			Name:    c.Name,
			Version: c.Version,
			Vendor:  c.Vendor,
			Product: c.Product,
		})
	}
	if err := a.assetRepo().ReplaceComponents(context.Background(), out.AssetID, comps); err != nil {
		return out, err
	}
	out.Components = len(comps)

	out.Created, out.Updated, err = a.matchAssetFindings(loadPolicy(a.db), out.AssetID)
	if err != nil {
		return out, err
	}
	recon, err := a.reconcileFindingStates(out.AssetID, "系统")
	if err != nil {
		slog.Warn("复扫收敛失败", "assetId", out.AssetID, "err", err)
	} else {
		out.Verified, out.Closed, out.Reopened = recon.Verified, recon.Closed, recon.Reopened
	}
	// 上报后异步做一次 OSV 匹配，避免拖慢 Agent 上报
	go func(assetID int64) {
		if _, err := a.osvScanAsset(assetID, "Agent 上报"); err != nil {
			slog.Warn("OSV 匹配失败", "assetId", assetID, "err", err)
		}
	}(out.AssetID)
	return out, nil
}
