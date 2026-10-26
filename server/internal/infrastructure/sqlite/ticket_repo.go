package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// TicketRepo 本地工单的 SQLite 仓储
type TicketRepo struct {
	db *sql.DB
}

// NewTicketRepo 构造工单仓储
func NewTicketRepo(db *sql.DB) *TicketRepo { return &TicketRepo{db: db} }

var _ ports.TicketRepository = (*TicketRepo)(nil)

// Create 新建工单
func (r *TicketRepo) Create(ctx context.Context, t ports.Ticket) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO tickets(id, finding_id, cve_id, asset_id, priority, status,
		assignee, created_by, note, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.FindingID, t.CVEID, t.AssetID, t.Priority, t.Status,
		t.Assignee, t.CreatedBy, t.Note, t.CreatedAt, t.UpdatedAt)
	return err
}

// ByFinding 按漏洞读取工单
func (r *TicketRepo) ByFinding(ctx context.Context, findingID int64) (ports.Ticket, bool, error) {
	var t ports.Ticket
	err := r.db.QueryRowContext(ctx, `SELECT id, finding_id, cve_id, asset_id, priority, status, assignee,
		created_by, note, created_at, updated_at FROM tickets WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`, findingID).
		Scan(&t.ID, &t.FindingID, &t.CVEID, &t.AssetID, &t.Priority, &t.Status, &t.Assignee,
			&t.CreatedBy, &t.Note, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.Ticket{}, false, nil
	}
	if err != nil {
		return ports.Ticket{}, false, err
	}
	return t, true, nil
}

// UpdateStatus 同步工单状态与责任人
func (r *TicketRepo) UpdateStatus(ctx context.Context, id, status, assignee, now string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE tickets SET status = ?, assignee = ?, updated_at = ? WHERE id = ?`,
		status, assignee, now, id)
	return err
}

// List 按状态过滤返回工单
func (r *TicketRepo) List(ctx context.Context, status string, limit int) ([]ports.Ticket, error) {
	query := `SELECT id, finding_id, cve_id, asset_id, priority, status, assignee, created_by, note,
		created_at, updated_at FROM tickets`
	args := []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.Ticket, 0, limit)
	for rows.Next() {
		var t ports.Ticket
		if err := rows.Scan(&t.ID, &t.FindingID, &t.CVEID, &t.AssetID, &t.Priority, &t.Status,
			&t.Assignee, &t.CreatedBy, &t.Note, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
