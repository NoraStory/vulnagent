package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// IntegrationRepo 云厂商与外部 CMDB 集成源的 SQLite 仓储
type IntegrationRepo struct {
	db *sql.DB
}

// NewIntegrationRepo 构造集成仓储
func NewIntegrationRepo(db *sql.DB) *IntegrationRepo { return &IntegrationRepo{db: db} }

const integrationSelect = `SELECT id, kind, name, config, secret, enabled, interval_minutes,
	last_run_at, last_status, last_error, last_count, created_at, updated_at FROM integration_sources`

func scanIntegration(sc interface{ Scan(...any) error }) (ports.IntegrationSource, error) {
	var src ports.IntegrationSource
	var enabled int
	err := sc.Scan(&src.ID, &src.Kind, &src.Name, &src.Config, &src.Secret, &enabled,
		&src.IntervalMinutes, &src.LastRunAt, &src.LastStatus, &src.LastError, &src.LastCount,
		&src.CreatedAt, &src.UpdatedAt)
	src.Enabled = enabled != 0
	return src, err
}

// List 返回全部集成源
func (r *IntegrationRepo) List(ctx context.Context) ([]ports.IntegrationSource, error) {
	rows, err := r.db.QueryContext(ctx, integrationSelect+" ORDER BY kind ASC, name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.IntegrationSource, 0, 8)
	for rows.Next() {
		src, err := scanIntegration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// Get 按 ID 读取集成源
func (r *IntegrationRepo) Get(ctx context.Context, id int64) (ports.IntegrationSource, error) {
	src, err := scanIntegration(r.db.QueryRowContext(ctx, integrationSelect+" WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return ports.IntegrationSource{}, ports.ErrNotFound
	}
	return src, err
}

// Create 新建集成源
func (r *IntegrationRepo) Create(ctx context.Context, src ports.IntegrationSource) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO integration_sources(kind, name, config, secret, enabled,
		interval_minutes, last_run_at, last_status, last_error, last_count, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		src.Kind, src.Name, src.Config, src.Secret, boolToInt(src.Enabled), src.IntervalMinutes,
		src.LastRunAt, src.LastStatus, src.LastError, src.LastCount, src.CreatedAt, src.UpdatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update 更新集成源（不含运行状态）
func (r *IntegrationRepo) Update(ctx context.Context, src ports.IntegrationSource) error {
	res, err := r.db.ExecContext(ctx, `UPDATE integration_sources SET name = ?, config = ?, secret = ?,
		enabled = ?, interval_minutes = ?, updated_at = ? WHERE id = ?`,
		src.Name, src.Config, src.Secret, boolToInt(src.Enabled), src.IntervalMinutes, src.UpdatedAt, src.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// Delete 删除集成源
func (r *IntegrationRepo) Delete(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM integration_sources WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// MarkRun 记录一次同步结果
func (r *IntegrationRepo) MarkRun(ctx context.Context, id int64, status string, count int, errText, runAt string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE integration_sources SET last_run_at = ?, last_status = ?,
		last_error = ?, last_count = ? WHERE id = ?`, runAt, status, errText, count, id)
	return err
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
