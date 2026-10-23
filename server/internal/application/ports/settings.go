package ports

import "context"

// AuditEntry 一条审计日志
type AuditEntry struct {
	ID        int64
	Actor     string
	Role      string
	Action    string
	Target    string
	IP        string
	UA        string
	Detail    string
	CreatedAt string
}

// AuditRepository 审计日志只追加不修改
type AuditRepository interface {
	Insert(ctx context.Context, entry AuditEntry) error
	// List 按时间倒序返回符合条件的日志
	List(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)
	// Count 返回符合条件的总数
	Count(ctx context.Context, filter AuditFilter) (int, error)
}

// PolicyRepository 风险策略与应用元数据
type PolicyRepository interface {
	// RiskPolicy 返回库中存储的权重与阈值 JSON，缺省时返回 ErrNotFound
	RiskPolicy(ctx context.Context) (weightsJSON, thresholdsJSON string, err error)
	SaveRiskPolicy(ctx context.Context, weightsJSON, thresholdsJSON, updatedAt string) error
	// Meta 读取应用元数据，不存在时返回空串
	Meta(ctx context.Context, key string) string
	SetMeta(ctx context.Context, key, value, updatedAt string) error
}

// NotifySettings Webhook 通知配置
type NotifySettings struct {
	URL        string
	Secret     string
	Events     []string
	LastEvent  string
	LastStatus string
	LastError  string
	LastSentAt string
}

// NotifyRepository 通知配置读写
type NotifyRepository interface {
	// Get 读取配置；记录缺失时返回空配置（Events 为空切片）
	Get(ctx context.Context) (NotifySettings, error)
	Save(ctx context.Context, settings NotifySettings, updatedAt string) error
	// MarkResult 记录最近一次推送结果
	MarkResult(ctx context.Context, event, status, errMsg, at string) error
}

// SyncCursor 同步游标与状态
type SyncCursor struct {
	Source    string
	LastRunAt string
	Status    string
	Count     int
	Error     string
}

// SyncRepository 情报同步状态
type SyncRepository interface {
	// Cursors 按 cve、poc、其他 的顺序返回同步状态
	Cursors(ctx context.Context) ([]SyncCursor, error)
	// MarkRun 记录一次同步结果，count 由来源对应的表实时统计
	MarkRun(ctx context.Context, source, status, errMsg, lastRunAt string) error
	// SetCursor 直接写入游标与计数
	SetCursor(ctx context.Context, source, lastRunAt, status string, count int, errMsg string) error
	// MarkEPSS 记录 EPSS 同步，count 为已有 EPSS 数据的 CVE 数
	MarkEPSS(ctx context.Context, lastRunAt string) error
	// NormalizeCounts 让计数与库内真实条数一致
	NormalizeCounts(ctx context.Context) error
}
