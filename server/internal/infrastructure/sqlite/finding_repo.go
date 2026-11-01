package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/vuln"
)

// FindingRepo 漏洞记录与处置事件的 SQLite 仓储
type FindingRepo struct {
	db *sql.DB
}

// NewFindingRepo 构造漏洞仓储
func NewFindingRepo(db *sql.DB) *FindingRepo { return &FindingRepo{db: db} }

var _ ports.FindingRepository = (*FindingRepo)(nil)

// UpsertMatch 落库一次匹配命中。已有记录只刷新评分相关字段，
// 保留处置状态、责任人与工单；inferred 只增不减。
func (r *FindingRepo) UpsertMatch(ctx context.Context, in ports.MatchInput) (bool, error) {
	flags, err := r.UpsertMatches(ctx, []ports.MatchInput{in})
	if err != nil {
		return false, err
	}
	return flags[0], nil
}

// UpsertMatches 在单个事务内批量写入匹配结果，显著降低 Agent 上报时的写入开销。
func (r *FindingRepo) UpsertMatches(ctx context.Context, inputs []ports.MatchInput) ([]bool, error) {
	created := make([]bool, len(inputs))
	if len(inputs) == 0 {
		return created, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	insert, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO findings(asset_id, purl, component_name,
		component_version, eco, cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown,
		status, inferred, fixed_version, assignee, ticket_id, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?, '', '', ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer insert.Close()
	update, err := tx.PrepareContext(ctx, `UPDATE findings SET component_name = ?, component_version = ?, eco = ?,
		cvss = ?, epss = ?, exploit = ?, asset_weight = ?, risk = ?, priority = ?, score_breakdown = ?,
		inferred = MAX(inferred, ?), fixed_version = ?, last_seen = ? WHERE asset_id = ? AND purl = ? AND cve_id = ?`)
	if err != nil {
		return nil, err
	}
	defer update.Close()

	for index, in := range inputs {
		comp := in.Component
		inferredFlag := 0
		if in.Inferred {
			inferredFlag = 1
		}
		res, err := insert.ExecContext(ctx, in.AssetID, comp.PURL, comp.Name, comp.Version, comp.Eco, in.CVEID,
			in.CVSS, in.EPSS, in.Exploit, in.AssetWeight, in.Risk, in.Priority, in.Breakdown,
			inferredFlag, in.FixedVersion, in.Now, in.Now)
		if err != nil {
			return nil, err
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			created[index] = true
			continue
		}
		if _, err := update.ExecContext(ctx, comp.Name, comp.Version, comp.Eco, in.CVSS, in.EPSS, in.Exploit,
			in.AssetWeight, in.Risk, in.Priority, in.Breakdown, inferredFlag, in.FixedVersion, in.Now,
			in.AssetID, comp.PURL, in.CVEID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return created, nil
}

// ActiveForReconcile 返回仍处于处置流程中的记录
func (r *FindingRepo) ActiveForReconcile(ctx context.Context, assetID int64) ([]ports.ReconcileRow, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, cve_id, status, fixed_version, component_name, component_version, eco
		FROM findings WHERE asset_id = ? AND status IN (`+vuln.ActiveStatusSQL()+`)`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.ReconcileRow
	for rows.Next() {
		var item ports.ReconcileRow
		if err := rows.Scan(&item.ID, &item.CVEID, &item.Status, &item.FixedVersion,
			&item.ComponentName, &item.ComponentVersion, &item.Eco); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// MarkStatus 更新状态并追加一条处置事件
func (r *FindingRepo) MarkStatus(ctx context.Context, id int64, status, now, event, actor, detail string) error {
	return r.MarkStatusBatch(ctx, []ports.StatusUpdate{{
		ID: id, Status: status, Now: now, Event: event, Actor: actor, Detail: detail,
	}})
}

// MarkStatusBatch 在单个事务内批量收敛状态，复扫时避免逐条自动提交。
func (r *FindingRepo) MarkStatusBatch(ctx context.Context, updates []ports.StatusUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	update, err := tx.PrepareContext(ctx, `UPDATE findings SET status = ?, last_seen = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer update.Close()
	event, err := tx.PrepareContext(ctx, `INSERT INTO finding_events(finding_id, event, actor, detail, created_at)
		VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer event.Close()

	for _, u := range updates {
		if _, err := update.ExecContext(ctx, u.Status, u.Now, u.ID); err != nil {
			return err
		}
		if _, err := event.ExecContext(ctx, u.ID, u.Event, u.Actor, u.Detail, u.Now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListForRecompute 返回重算风险分所需的全部记录
func (r *FindingRepo) ListForRecompute(ctx context.Context) ([]ports.RecomputeRow, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT f.id, f.cvss, f.epss, f.exploit, a.exposure, a.tier,
		COALESCE(bs.tier, 'normal')
		FROM findings f JOIN assets a ON a.id = f.asset_id
		LEFT JOIN business_systems bs ON bs.name = a.business_system`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]ports.RecomputeRow, 0, 64)
	for rows.Next() {
		var it ports.RecomputeRow
		if err := rows.Scan(&it.ID, &it.CVSS, &it.EPSS, &it.Exploit, &it.Exposure, &it.Tier, &it.BusinessTier); err != nil {
			return nil, err
		}
		list = append(list, it)
	}
	return list, rows.Err()
}

// UpsertOSV 落库一次 OSV 命中：只刷新评分与组件字段，不改 EPSS/在野利用
func (r *FindingRepo) UpsertOSV(ctx context.Context, in ports.MatchInput) (bool, error) {
	comp := in.Component
	var existingID int64
	err := r.db.QueryRowContext(ctx, `SELECT id FROM findings WHERE asset_id = ? AND purl = ? AND cve_id = ?`,
		in.AssetID, comp.PURL, in.CVEID).Scan(&existingID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = r.db.ExecContext(ctx, `INSERT INTO findings(asset_id, purl, component_name, component_version, eco,
			cve_id, cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, status, inferred,
			fixed_version, assignee, ticket_id, first_seen, last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'open', 0, ?, '', '', ?, ?)`,
			in.AssetID, comp.PURL, comp.Name, comp.Version, comp.Eco, in.CVEID, in.CVSS, in.EPSS,
			in.Exploit, in.AssetWeight, in.Risk, in.Priority, in.Breakdown, in.FixedVersion, in.Now, in.Now)
		if err != nil {
			return false, err
		}
		return true, nil
	case err != nil:
		return false, err
	}
	_, err = r.db.ExecContext(ctx, `UPDATE findings SET component_name = ?, component_version = ?, eco = ?,
		cvss = ?, risk = ?, priority = ?, score_breakdown = ?, fixed_version = ?, last_seen = ?
		WHERE id = ?`,
		comp.Name, comp.Version, comp.Eco, in.CVSS, in.Risk, in.Priority,
		in.Breakdown, in.FixedVersion, in.Now, existingID)
	if err != nil {
		return false, err
	}
	return false, nil
}

// SyncEPSSSnapshot 把 CVE 的最新 EPSS 同步到漏洞快照
func (r *FindingRepo) SyncEPSSSnapshot(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `UPDATE findings SET epss = COALESCE(
		(SELECT epss FROM cves WHERE cves.cve_id = findings.cve_id), epss)`)
	return err
}

// BulkUpdateScores 在单个事务内批量刷新评分字段
func (r *FindingRepo) BulkUpdateScores(ctx context.Context, updates []ports.ScoreUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `UPDATE findings SET risk = ?, priority = ?, score_breakdown = ?, asset_weight = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range updates {
		if _, err := stmt.ExecContext(ctx, u.Risk, u.Priority, u.Breakdown, u.AssetWeight, u.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
