package main

import (
	"log/slog"

	"vulnagent/server/internal/application/scan"
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
// 流程：upsert 资产 → 整体替换组件 → 版本区间匹配 → 状态收敛，实现见 application/scan。
func (a *App) ingestComponents(hostname, ip, osName, osVersion, source string, components []collect.Component) (ingestOutcome, error) {
	agentStatus := "none"
	if source == "agent" {
		agentStatus = "online"
	}
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

	res, err := a.scanService(loadPolicy(a.db)).Ingest(scan.IngestInput{
		Hostname:    hostname,
		IP:          ip,
		OSFamily:    osName,
		OSVersion:   osVersion,
		Source:      source,
		AgentStatus: agentStatus,
		Components:  comps,
	})
	if err != nil {
		return ingestOutcome{}, err
	}
	out := ingestOutcome{
		AssetID:    res.AssetID,
		Components: res.Components,
		Created:    res.Created,
		Updated:    res.Updated,
		Verified:   res.Verified,
		Closed:     res.Closed,
		Reopened:   res.Reopened,
	}
	// 上报后异步做一次 OSV 精确匹配并收敛，避免拖慢 Agent 上报
	go func(assetID int64) {
		if _, err := a.osvScanAsset(assetID, "Agent 上报"); err != nil {
			slog.Warn("OSV 匹配失败", "assetId", assetID, "err", err)
			return
		}
		if _, err := a.reconcileFindingStates(assetID, "Agent 上报"); err != nil {
			slog.Warn("OSV 后收敛失败", "assetId", assetID, "err", err)
		}
	}(res.AssetID)
	return out, nil
}
