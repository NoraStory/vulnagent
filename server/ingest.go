package main

import (
	"log/slog"

	"vulnagent/server/internal/collect"
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

	_, err := a.db.Exec(`INSERT INTO assets(hostname, ip, os_family, os_version, env, exposure, tier, owner,
		source, agent_status, last_seen_at) VALUES(?,?,?,?, 'prod', 'internal', 'normal', '', ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET ip = excluded.ip, os_family = excluded.os_family,
		os_version = excluded.os_version,
		source = CASE WHEN assets.source = 'agent' THEN 'agent' ELSE excluded.source END,
		agent_status = CASE WHEN excluded.agent_status = 'online' THEN 'online' ELSE assets.agent_status END,
		last_seen_at = excluded.last_seen_at`,
		hostname, ip, osName, osVersion, source, agentStatus, now)
	if err != nil {
		return out, err
	}
	if err := a.db.QueryRow(`SELECT id FROM assets WHERE hostname = ?`, hostname).Scan(&out.AssetID); err != nil {
		return out, err
	}

	tx, err := a.db.Begin()
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM components WHERE asset_id = ?`, out.AssetID); err != nil {
		return out, err
	}
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO components(asset_id, purl, eco, name, version, vendor, product, inferred)
		VALUES(?,?,?,?,?,?,?,0)`)
	if err != nil {
		return out, err
	}
	for _, c := range components {
		if c.PURL == "" || c.Name == "" || c.Version == "" {
			continue
		}
		if _, err := stmt.Exec(out.AssetID, c.PURL, c.Eco, c.Name, c.Version, c.Vendor, c.Product); err != nil {
			stmt.Close()
			return out, err
		}
		out.Components++
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return out, err
	}

	out.Created, out.Updated, err = a.matchAssetFindings(loadPolicy(a.db), out.AssetID)
	if err != nil {
		return out, err
	}
	recon, err := reconcileFindingStates(a.db, out.AssetID, "系统")
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
