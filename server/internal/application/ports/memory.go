package ports

import "context"

// Memory Agent 长期记忆条目
type Memory struct {
	ID            int64  `json:"id"`
	Scope         string `json:"scope"`
	ScopeKey      string `json:"scopeKey"`
	Content       string `json:"content"`
	SourceSession string `json:"sourceSession"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// MemoryRepository 记忆持久化端口
type MemoryRepository interface {
	Save(ctx context.Context, m Memory) (int64, error)
	// Search 按作用域与关键词检索，空 query 返回最近记录
	Search(ctx context.Context, scope, scopeKey, query string, limit int) ([]Memory, error)
	Delete(ctx context.Context, id int64) error
}
