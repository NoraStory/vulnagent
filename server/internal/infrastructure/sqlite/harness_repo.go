package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
)

// HarnessRepo Agent 会话、消息、工具调用与审批的 SQLite 仓储
type HarnessRepo struct {
	db *sql.DB
}

// NewHarnessRepo 构造 Harness 仓储
func NewHarnessRepo(db *sql.DB) *HarnessRepo { return &HarnessRepo{db: db} }

var _ ports.HarnessRepository = (*HarnessRepo)(nil)

// CreateSession 新建会话
func (r *HarnessRepo) CreateSession(ctx context.Context, s harness.Session) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO agent_sessions(id, owner, role, title, created_at, updated_at)
		VALUES(?,?,?,?,?,?)`, s.ID, s.Owner, s.Role, s.Title, s.CreatedAt, s.UpdatedAt)
	return err
}

// GetSession 读取会话
func (r *HarnessRepo) GetSession(ctx context.Context, id string) (harness.Session, error) {
	var s harness.Session
	err := r.db.QueryRowContext(ctx, `SELECT id, owner, role, title, created_at, updated_at
		FROM agent_sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.Owner, &s.Role, &s.Title, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return harness.Session{}, ports.ErrNotFound
	}
	return s, err
}

// ListSessions 按最近更新时间列出某账号的会话
func (r *HarnessRepo) ListSessions(ctx context.Context, owner string, limit int) ([]harness.Session, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, owner, role, title, created_at, updated_at
		FROM agent_sessions WHERE owner = ? ORDER BY updated_at DESC LIMIT ?`, owner, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]harness.Session, 0, limit)
	for rows.Next() {
		var s harness.Session
		if err := rows.Scan(&s.ID, &s.Owner, &s.Role, &s.Title, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// TouchSession 刷新会话更新时间
func (r *HarnessRepo) TouchSession(ctx context.Context, id, at string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE agent_sessions SET updated_at = ? WHERE id = ?`, at, id)
	return err
}

// AppendMessage 追加消息
func (r *HarnessRepo) AppendMessage(ctx context.Context, m harness.Message) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO agent_messages(session_id, role, content, tool_calls, tool_call_id, created_at)
		VALUES(?,?,?,?,?,?)`, m.SessionID, m.Role, m.Content, m.ToolCalls, m.ToolCallID, m.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Messages 返回最近 limit 条消息（按时间正序）
func (r *HarnessRepo) Messages(ctx context.Context, sessionID string, limit int) ([]harness.Message, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, session_id, role, content, tool_calls, tool_call_id, created_at
		FROM agent_messages WHERE session_id = ? ORDER BY id DESC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]harness.Message, 0, limit)
	for rows.Next() {
		var m harness.Message
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.ToolCalls, &m.ToolCallID, &m.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 反转为时间正序
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items, nil
}

// RecordToolCall 记录一次工具调用
func (r *HarnessRepo) RecordToolCall(ctx context.Context, rec harness.ToolCallRecord) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO agent_tool_calls(session_id, tool, args, args_hash, risk, status,
		actor, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		rec.SessionID, rec.Tool, rec.Args, rec.ArgsHash, rec.Risk, rec.Status, rec.Actor, rec.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishToolCall 更新工具调用结果
func (r *HarnessRepo) FinishToolCall(ctx context.Context, id int64, status, result, errMsg, approver, at string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE agent_tool_calls SET status = ?, result = ?, error = ?,
		approver = ?, finished_at = ? WHERE id = ?`, status, result, errMsg, approver, at, id)
	return err
}

// CreateApproval 新建审批
func (r *HarnessRepo) CreateApproval(ctx context.Context, a harness.Approval) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO agent_approvals(id, session_id, tool, args_hash, args, call_id, risk,
		requested_by, status, reason, requested_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.SessionID, a.Tool, a.ArgsHash, a.Args, a.CallID, a.Risk, a.RequestedBy, a.Status, a.Reason, a.RequestedAt, a.ExpiresAt)
	return err
}

// GetApproval 读取审批
func (r *HarnessRepo) GetApproval(ctx context.Context, id string) (harness.Approval, error) {
	var a harness.Approval
	err := r.db.QueryRowContext(ctx, `SELECT id, session_id, tool, args_hash, args, call_id, risk, requested_by, status,
		reason, requested_at, expires_at, decided_at, decided_by, consumed_at FROM agent_approvals WHERE id = ?`, id).
		Scan(&a.ID, &a.SessionID, &a.Tool, &a.ArgsHash, &a.Args, &a.CallID, &a.Risk, &a.RequestedBy, &a.Status,
			&a.Reason, &a.RequestedAt, &a.ExpiresAt, &a.DecidedAt, &a.DecidedBy, &a.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return harness.Approval{}, ports.ErrNotFound
	}
	return a, err
}

// DecideApproval 记录审批结论（仅 pending 状态可改）
func (r *HarnessRepo) DecideApproval(ctx context.Context, id, status, by, at string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE agent_approvals SET status = ?, decided_by = ?, decided_at = ?
		WHERE id = ? AND status = 'pending' AND expires_at > ?`, status, by, at, id, at)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// ConsumeApproval 一次性消费
func (r *HarnessRepo) ConsumeApproval(ctx context.Context, id, at string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE agent_approvals SET consumed_at = ?
		WHERE id = ? AND status = 'approved' AND consumed_at = '' AND expires_at > ?`, at, id, at)
	if err != nil {
		return false, err
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

// HasPendingApproval 会话是否存在未过期且未处理的审批
func (r *HarnessRepo) HasPendingApproval(ctx context.Context, sessionID, at string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_approvals
		WHERE session_id = ? AND status = 'pending' AND expires_at > ?`, sessionID, at).Scan(&count)
	return count > 0, err
}

// PendingApproval 查找同一会话下匹配工具与参数指纹的待审批记录
func (r *HarnessRepo) PendingApproval(ctx context.Context, sessionID, tool, argsHash string) (harness.Approval, bool, error) {
	var a harness.Approval
	err := r.db.QueryRowContext(ctx, `SELECT id, session_id, tool, args_hash, args, call_id, risk, requested_by, status,
		reason, requested_at, expires_at, decided_at, decided_by, consumed_at FROM agent_approvals
		WHERE session_id = ? AND tool = ? AND args_hash = ? AND status = 'pending' ORDER BY requested_at DESC LIMIT 1`,
		sessionID, tool, argsHash).
		Scan(&a.ID, &a.SessionID, &a.Tool, &a.ArgsHash, &a.Args, &a.CallID, &a.Risk, &a.RequestedBy, &a.Status,
			&a.Reason, &a.RequestedAt, &a.ExpiresAt, &a.DecidedAt, &a.DecidedBy, &a.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return harness.Approval{}, false, nil
	}
	if err != nil {
		return harness.Approval{}, false, err
	}
	return a, true, nil
}
