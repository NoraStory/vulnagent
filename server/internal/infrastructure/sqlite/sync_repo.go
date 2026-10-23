package sqlite

import (
	"context"
	"database/sql"

	"vulnagent/server/internal/application/ports"
)

// SyncRepo 情报同步状态的 SQLite 仓储
type SyncRepo struct {
	db *sql.DB
}

// NewSyncRepo 构造同步状态仓储
func NewSyncRepo(db *sql.DB) *SyncRepo { return &SyncRepo{db: db} }

var _ ports.SyncRepository = (*SyncRepo)(nil)

// Cursors 按 cve、poc、其他 的顺序返回同步状态
func (r *SyncRepo) Cursors(ctx context.Context) ([]ports.SyncCursor, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT source, last_run_at, status, count, error FROM sync_cursors
		ORDER BY CASE source WHEN 'cve' THEN 1 WHEN 'poc' THEN 2 ELSE 3 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.SyncCursor, 0, 3)
	for rows.Next() {
		var it ports.SyncCursor
		if err := rows.Scan(&it.Source, &it.LastRunAt, &it.Status, &it.Count, &it.Error); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// MarkRun 记录一次同步结果，count 由来源对应的表实时统计
func (r *SyncRepo) MarkRun(ctx context.Context, source, status, errMsg, lastRunAt string) error {
	count, _ := r.sourceCount(ctx, source)
	_, err := r.db.ExecContext(ctx, `INSERT INTO sync_cursors(source, last_run_at, status, count, error)
		VALUES(?,?,?,?,?)
		ON CONFLICT(source) DO UPDATE SET last_run_at = excluded.last_run_at, status = excluded.status,
		count = excluded.count, error = excluded.error`,
		source, lastRunAt, status, count, errMsg)
	return err
}

// SetCursor 直接写入游标与计数
func (r *SyncRepo) SetCursor(ctx context.Context, source, lastRunAt, status string, count int, errMsg string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO sync_cursors(source, last_run_at, status, count, error)
		VALUES(?,?,?,?,?)
		ON CONFLICT(source) DO UPDATE SET last_run_at = excluded.last_run_at, status = excluded.status,
		count = excluded.count, error = excluded.error`,
		source, lastRunAt, status, count, errMsg)
	return err
}

// MarkEPSS 记录 EPSS 同步，count 为已有 EPSS 数据的 CVE 数
func (r *SyncRepo) MarkEPSS(ctx context.Context, lastRunAt string) error {
	var covered int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cves WHERE epss > 0`).Scan(&covered); err != nil {
		return err
	}
	return r.SetCursor(ctx, "epss", lastRunAt, "ok", covered, "")
}

// NormalizeCounts 让计数与库内真实条数一致
func (r *SyncRepo) NormalizeCounts(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE sync_cursors SET count = (SELECT COUNT(*) FROM cves) WHERE source IN ('cve','epss')`); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE sync_cursors SET count = (SELECT COUNT(*) FROM cve_poc) WHERE source = 'poc'`)
	return err
}

func (r *SyncRepo) sourceCount(ctx context.Context, source string) (int, error) {
	table := "cves"
	if source == "poc" {
		table = "cve_poc"
	}
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count)
	return count, err
}
