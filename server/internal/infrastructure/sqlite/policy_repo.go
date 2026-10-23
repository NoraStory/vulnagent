package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// PolicyRepo 风险策略与应用元数据的 SQLite 仓储
type PolicyRepo struct {
	db *sql.DB
}

// NewPolicyRepo 构造策略仓储
func NewPolicyRepo(db *sql.DB) *PolicyRepo { return &PolicyRepo{db: db} }

var _ ports.PolicyRepository = (*PolicyRepo)(nil)

// RiskPolicy 返回库中存储的权重与阈值 JSON
func (r *PolicyRepo) RiskPolicy(ctx context.Context) (string, string, error) {
	var weights, thresholds string
	err := r.db.QueryRowContext(ctx, `SELECT weights, thresholds FROM risk_policy WHERE id = 1`).
		Scan(&weights, &thresholds)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ports.ErrNotFound
	}
	return weights, thresholds, err
}

// SaveRiskPolicy 写入权重与阈值
func (r *PolicyRepo) SaveRiskPolicy(ctx context.Context, weightsJSON, thresholdsJSON, updatedAt string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE risk_policy SET weights = ?, thresholds = ?, updated_at = ? WHERE id = 1`,
		weightsJSON, thresholdsJSON, updatedAt)
	return err
}

// Meta 读取应用元数据
func (r *PolicyRepo) Meta(ctx context.Context, key string) string {
	var value string
	if err := r.db.QueryRowContext(ctx, `SELECT value FROM app_meta WHERE key = ?`, key).Scan(&value); err != nil {
		return ""
	}
	return value
}

// SetMeta 写入应用元数据
func (r *PolicyRepo) SetMeta(ctx context.Context, key, value, updatedAt string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO app_meta(key, value, updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, updatedAt)
	return err
}
