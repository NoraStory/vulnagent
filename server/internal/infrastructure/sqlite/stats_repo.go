package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// StatsRepo 概览与指标的只读统计仓储
type StatsRepo struct {
	db *sql.DB
}

// NewStatsRepo 构造统计仓储
func NewStatsRepo(db *sql.DB) *StatsRepo { return &StatsRepo{db: db} }

var _ ports.StatsRepository = (*StatsRepo)(nil)

// FindingsByPriority 按优先级统计全部漏洞
func (r *StatsRepo) FindingsByPriority(ctx context.Context) ([]ports.PriorityCount, error) {
	return r.priorityCount(ctx, `SELECT priority, COUNT(*) FROM findings GROUP BY priority`)
}

// FindingsByStatus 按状态统计全部漏洞
func (r *StatsRepo) FindingsByStatus(ctx context.Context) ([]ports.StatusCount, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM findings GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.StatusCount
	for rows.Next() {
		var item ports.StatusCount
		if err := rows.Scan(&item.Status, &item.Count); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// PriorityBefore 返回 first_seen 早于 before 的优先级分布
func (r *StatsRepo) PriorityBefore(ctx context.Context, before string) ([]ports.PriorityCount, error) {
	return r.priorityCount(ctx, `SELECT priority, COUNT(*) FROM findings WHERE first_seen < ? GROUP BY priority`, before)
}

// FindingFirstSeen 一次性返回全部漏洞的优先级与首次发现时间（趋势聚合）
func (r *StatsRepo) FindingFirstSeen(ctx context.Context) ([]ports.FindingSeen, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT priority, first_seen FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.FindingSeen, 0, 256)
	for rows.Next() {
		var item ports.FindingSeen
		if err := rows.Scan(&item.Priority, &item.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// TopComponents 返回高风险组件聚合
func (r *StatsRepo) TopComponents(ctx context.Context, limit int) ([]ports.TopComponent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT f.component_name, f.component_version, f.eco,
		COUNT(DISTINCT f.cve_id), MAX(f.risk), COUNT(DISTINCT f.asset_id),
		(SELECT f2.priority FROM findings f2
			WHERE f2.component_name = f.component_name AND f2.component_version = f.component_version
			AND f2.eco = f.eco ORDER BY f2.risk DESC LIMIT 1)
		FROM findings f
		GROUP BY f.component_name, f.component_version, f.eco
		ORDER BY MAX(f.risk) DESC, COUNT(DISTINCT f.cve_id) DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.TopComponent, 0, limit)
	for rows.Next() {
		var item ports.TopComponent
		if err := rows.Scan(&item.Name, &item.Version, &item.Eco, &item.CVECount,
			&item.MaxRisk, &item.AssetCount, &item.Priority); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// AgentSummary 统计 Agent 在线情况（单次条件聚合）
func (r *StatsRepo) AgentSummary(ctx context.Context) (ports.AgentSummary, error) {
	var s ports.AgentSummary
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN agent_status = 'online' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN agent_status = 'offline' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN agent_status = 'stale' THEN 1 ELSE 0 END), 0)
		FROM assets WHERE source = 'agent' AND merged_into = 0`).Scan(&s.Total, &s.Online, &s.Offline, &s.Stale)
	return s, err
}

// RecentFindingEvents 返回最近的漏洞处置事件
func (r *StatsRepo) RecentFindingEvents(ctx context.Context, limit int) ([]ports.FindingEvent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT e.id, e.created_at, e.actor, e.event, c.cve_id, a.hostname, e.detail
		FROM finding_events e
		JOIN findings f ON f.id = e.finding_id
		JOIN cves c ON c.cve_id = f.cve_id
		JOIN assets a ON a.id = f.asset_id
		ORDER BY e.created_at DESC, e.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.FindingEvent, 0, limit)
	for rows.Next() {
		var item ports.FindingEvent
		if err := rows.Scan(&item.ID, &item.Time, &item.Actor, &item.Event, &item.CVEID, &item.Hostname, &item.Detail); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Gauges 返回资产/组件/CVE/Agent/自检的绝对计数（单次查询）
func (r *StatsRepo) Gauges(ctx context.Context) (ports.Gauges, error) {
	var g ports.Gauges
	err := r.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM assets WHERE merged_into = 0),
		(SELECT COUNT(*) FROM components),
		(SELECT COUNT(*) FROM cves),
		(SELECT COUNT(*) FROM assets WHERE source = 'agent' AND agent_status = 'online' AND merged_into = 0),
		COALESCE((SELECT failed FROM selfcheck_runs ORDER BY finished_at DESC LIMIT 1), 0)`).
		Scan(&g.Assets, &g.Components, &g.CVEs, &g.AgentsOnline, &g.SelfcheckFailed)
	return g, err
}

// LatestSelfcheck 返回最近一次自检摘要
func (r *StatsRepo) LatestSelfcheck(ctx context.Context) (ports.SelfcheckSummary, bool, error) {
	var s ports.SelfcheckSummary
	err := r.db.QueryRowContext(ctx, `SELECT run_id, status, finished_at, passed, warnings, failed
		FROM selfcheck_runs ORDER BY finished_at DESC, id DESC LIMIT 1`).
		Scan(&s.RunID, &s.Status, &s.CheckedAt, &s.Passed, &s.Warnings, &s.Failed)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.SelfcheckSummary{}, false, nil
	}
	if err != nil {
		return ports.SelfcheckSummary{}, false, err
	}
	return s, true, nil
}

func (r *StatsRepo) priorityCount(ctx context.Context, query string, args ...any) ([]ports.PriorityCount, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.PriorityCount
	for rows.Next() {
		var item ports.PriorityCount
		if err := rows.Scan(&item.Priority, &item.Count); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
