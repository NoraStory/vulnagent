package ports

import "context"

// HostJob 一次主机执行作业
type HostJob struct {
	ID             string `json:"id"`
	AssetID        int64  `json:"assetId"`
	Action         string `json:"action"`
	Params         string `json:"params"`
	Risk           string `json:"risk"`
	Status         string `json:"status"`
	RequestedBy    string `json:"requestedBy"`
	ApprovalID     string `json:"approvalId,omitempty"`
	IdempotencyKey string `json:"-"`
	Attempts       int    `json:"attempts"`
	MaxAttempts    int    `json:"maxAttempts"`
	NextRunAt      string `json:"nextRunAt,omitempty"`
	Output         string `json:"output,omitempty"`
	Error          string `json:"error,omitempty"`
	ExitCode       int    `json:"exitCode"`
	CreatedAt      string `json:"createdAt"`
	StartedAt      string `json:"startedAt,omitempty"`
	FinishedAt     string `json:"finishedAt,omitempty"`
}

// HostJobResult Agent 回传的执行结果
type HostJobResult struct {
	Status     string `json:"status"`
	Output     string `json:"output"`
	Error      string `json:"error"`
	ExitCode   int    `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	Retryable  bool   `json:"retryable"`
}

// JobRepository 主机作业持久化端口
type JobRepository interface {
	// Create 创建作业；idempotencyKey 冲突时由仓储返回既有作业
	Create(ctx context.Context, job HostJob) error
	ByID(ctx context.Context, id string) (HostJob, bool, error)
	// DueForHost 返回指定主机当前可执行的作业（pending 且到期）
	DueForHost(ctx context.Context, hostname string, now string, limit int) ([]HostJob, error)
	// Claim 抢占作业，返回 false 表示已被其他 Agent 取走
	Claim(ctx context.Context, id, hostname, now string) (HostJob, bool, error)
	// Complete 写入结果；nextRunAt 非空表示进入重试
	Complete(ctx context.Context, id, status, output, errText string, exitCode int, now, nextRunAt string) error
	ListByAsset(ctx context.Context, assetID int64, limit int) ([]HostJob, error)
	// ExistingByIdempotency 查找未失效的幂等作业
	ExistingByIdempotency(ctx context.Context, key, since string) (HostJob, bool, error)
}
