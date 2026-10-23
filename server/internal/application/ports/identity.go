package ports

import "context"

// Account 账号记录（含口令摘要，仅限仓储内部使用）
type Account struct {
	Username  string
	Name      string
	PwdHash   string
	Role      string
	Disabled  bool
	LastLogin string
}

// IdentityRepository 账号读取与写入端口
type IdentityRepository interface {
	// FindAccount 按用户名读取账号，不存在时返回 ErrNotFound
	FindAccount(ctx context.Context, username string) (Account, error)
	// PasswordHash 只读取口令摘要
	PasswordHash(ctx context.Context, username string) (string, error)
	// ListAccounts 按创建顺序返回全部账号
	ListAccounts(ctx context.Context) ([]Account, error)
	CreateAccount(ctx context.Context, acc Account) error
	UpdateAccount(ctx context.Context, username, name, role string, disabled bool) error
	// UpdatePassword 更新口令摘要，账号不存在时返回 ErrNotFound
	UpdatePassword(ctx context.Context, username, hash string) error
	CountByUsername(ctx context.Context, username string) (int, error)
	CountActiveAdmins(ctx context.Context) (int, error)
	TouchLogin(ctx context.Context, username, at string) error
}

// AgentTokenRepository Agent 接入令牌（只存 SHA-256 摘要）
type AgentTokenRepository interface {
	// SaveTokenHash 幂等写入令牌摘要
	SaveTokenHash(ctx context.Context, hash, createdAt string) error
	ListTokenHashes(ctx context.Context) ([]string, error)
	// ReplaceToken 原子替换为唯一令牌，旧令牌立即失效
	ReplaceToken(ctx context.Context, hash, createdAt string) error
}
