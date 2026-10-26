package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// MemoryRepo Agent 记忆的 SQLite 仓储
type MemoryRepo struct{ db *sql.DB }

// NewMemoryRepo 构造记忆仓储
func NewMemoryRepo(db *sql.DB) *MemoryRepo { return &MemoryRepo{db: db} }

var _ ports.MemoryRepository = (*MemoryRepo)(nil)

// Save 写入一条记忆
func (r *MemoryRepo) Save(ctx context.Context, m ports.Memory) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO agent_memories(scope, scope_key, content, source_session,
		created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		m.Scope, m.ScopeKey, m.Content, m.SourceSession, m.CreatedAt, m.UpdatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Search 按作用域与关键词检索记忆
func (r *MemoryRepo) Search(ctx context.Context, scope, scopeKey, query string, limit int) ([]ports.Memory, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	sqlText := `SELECT id, scope, scope_key, content, source_session, created_at, updated_at
		FROM agent_memories WHERE scope = ?`
	args := []any{scope}
	if scopeKey != "" {
		sqlText += ` AND scope_key = ?`
		args = append(args, scopeKey)
	}
	if strings.TrimSpace(query) != "" {
		sqlText += ` AND content LIKE ?`
		args = append(args, "%"+strings.TrimSpace(query)+"%")
	}
	sqlText += ` ORDER BY updated_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ports.Memory, 0, limit)
	for rows.Next() {
		var m ports.Memory
		if err := rows.Scan(&m.ID, &m.Scope, &m.ScopeKey, &m.Content, &m.SourceSession,
			&m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Delete 删除记忆
func (r *MemoryRepo) Delete(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM agent_memories WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ports.ErrNotFound
	}
	return nil
}
