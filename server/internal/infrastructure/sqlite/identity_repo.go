package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"vulnagent/server/internal/application/ports"
)

// IdentityRepo 账号与 Agent 令牌的 SQLite 仓储
type IdentityRepo struct {
	db *sql.DB
}

// NewIdentityRepo 构造账号仓储
func NewIdentityRepo(db *sql.DB) *IdentityRepo { return &IdentityRepo{db: db} }

var (
	_ ports.IdentityRepository   = (*IdentityRepo)(nil)
	_ ports.AgentTokenRepository = (*IdentityRepo)(nil)
)

// FindAccount 按用户名读取账号
func (r *IdentityRepo) FindAccount(ctx context.Context, username string) (ports.Account, error) {
	var acc ports.Account
	var disabled int
	err := r.db.QueryRowContext(ctx, `SELECT username, name, pwd_hash, role, disabled, last_login
		FROM users WHERE username = ?`, username).
		Scan(&acc.Username, &acc.Name, &acc.PwdHash, &acc.Role, &disabled, &acc.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.Account{}, ports.ErrNotFound
	}
	if err != nil {
		return ports.Account{}, err
	}
	acc.Disabled = disabled != 0
	return acc, nil
}

// PasswordHash 只读取口令摘要
func (r *IdentityRepo) PasswordHash(ctx context.Context, username string) (string, error) {
	var hash string
	err := r.db.QueryRowContext(ctx, `SELECT pwd_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ports.ErrNotFound
	}
	return hash, err
}

// ListAccounts 按创建顺序返回全部账号
func (r *IdentityRepo) ListAccounts(ctx context.Context) ([]ports.Account, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT username, name, role, last_login, disabled
		FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.Account, 0, 8)
	for rows.Next() {
		var acc ports.Account
		var disabled int
		if err := rows.Scan(&acc.Username, &acc.Name, &acc.Role, &acc.LastLogin, &disabled); err != nil {
			return nil, err
		}
		acc.Disabled = disabled != 0
		items = append(items, acc)
	}
	return items, rows.Err()
}

// CreateAccount 新建账号
func (r *IdentityRepo) CreateAccount(ctx context.Context, acc ports.Account) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO users(username, name, pwd_hash, role, disabled, last_login)
		VALUES(?,?,?,?,0,?)`, acc.Username, acc.Name, acc.PwdHash, acc.Role, acc.LastLogin)
	return err
}

// UpdateAccount 更新姓名、角色与停用状态
func (r *IdentityRepo) UpdateAccount(ctx context.Context, username, name, role string, disabled bool) error {
	disabledValue := 0
	if disabled {
		disabledValue = 1
	}
	_, err := r.db.ExecContext(ctx, `UPDATE users SET name = ?, role = ?, disabled = ? WHERE username = ?`,
		name, role, disabledValue, username)
	return err
}

// UpdatePassword 更新口令摘要
func (r *IdentityRepo) UpdatePassword(ctx context.Context, username, hash string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE users SET pwd_hash = ? WHERE username = ?`, hash, username)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ports.ErrNotFound
	}
	return nil
}

// CountByUsername 统计同名账号数
func (r *IdentityRepo) CountByUsername(ctx context.Context, username string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&n)
	return n, err
}

// CountActiveAdmins 统计启用状态的管理员数
func (r *IdentityRepo) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// TouchLogin 记录最近登录时间
func (r *IdentityRepo) TouchLogin(ctx context.Context, username, at string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE username = ?`, at, username)
	return err
}

// SaveTokenHash 幂等写入令牌摘要
func (r *IdentityRepo) SaveTokenHash(ctx context.Context, hash, createdAt string) error {
	_, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO agent_tokens(token_hash, created_at) VALUES(?,?)`,
		hash, createdAt)
	return err
}

// ListTokenHashes 返回全部令牌摘要
func (r *IdentityRepo) ListTokenHashes(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT token_hash FROM agent_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		out = append(out, hash)
	}
	return out, rows.Err()
}

// ReplaceToken 原子替换为唯一令牌
func (r *IdentityRepo) ReplaceToken(ctx context.Context, hash, createdAt string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_tokens`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_tokens(token_hash, created_at) VALUES(?,?)`, hash, createdAt); err != nil {
		return err
	}
	return tx.Commit()
}
