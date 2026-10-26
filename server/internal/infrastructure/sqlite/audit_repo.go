package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// AuditRepo 审计日志的 SQLite 仓储
type AuditRepo struct {
	db *sql.DB
}

// NewAuditRepo 构造审计仓储
func NewAuditRepo(db *sql.DB) *AuditRepo { return &AuditRepo{db: db} }

var _ ports.AuditRepository = (*AuditRepo)(nil)

// Insert 追加一条审计日志
func (r *AuditRepo) Insert(ctx context.Context, e ports.AuditEntry) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_logs(actor, role, action, target, ip, ua, detail, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, e.Actor, e.Role, e.Action, e.Target, e.IP, e.UA, e.Detail, e.CreatedAt)
	return err
}

// List 按时间倒序返回符合条件的日志
func (r *AuditRepo) List(ctx context.Context, filter ports.AuditFilter) ([]ports.AuditEntry, error) {
	where, args := auditWhere(filter)
	args = append(args, filter.Limit, filter.Offset)
	rows, err := r.db.QueryContext(ctx, `SELECT id, created_at, actor, role, action, target, ip, ua, detail
		FROM audit_logs WHERE `+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.AuditEntry, 0, filter.Limit)
	for rows.Next() {
		var e ports.AuditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Actor, &e.Role, &e.Action, &e.Target, &e.IP, &e.UA, &e.Detail); err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, rows.Err()
}

// Count 返回符合条件的总数
func (r *AuditRepo) Count(ctx context.Context, filter ports.AuditFilter) (int, error) {
	where, args := auditWhere(filter)
	var total int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE `+where, args...).Scan(&total)
	return total, err
}

func auditWhere(filter ports.AuditFilter) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	if filter.Action != "" {
		where = append(where, "action LIKE ?")
		args = append(args, "%"+filter.Action+"%")
	}
	if filter.Actor != "" {
		where = append(where, "actor LIKE ?")
		args = append(args, "%"+filter.Actor+"%")
	}
	if filter.Query != "" {
		like := "%" + filter.Query + "%"
		where = append(where, "(actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	if filter.From != "" {
		where = append(where, "created_at >= ?")
		args = append(args, filter.From)
	}
	if filter.To != "" {
		where = append(where, "created_at <= ?")
		args = append(args, filter.To)
	}
	return strings.Join(where, " AND "), args
}
