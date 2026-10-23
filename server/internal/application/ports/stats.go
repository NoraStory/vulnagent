package ports

import "context"

// PriorityCount 按优先级统计
type PriorityCount struct {
	Priority string
	Count    int
}

// StatusCount 按状态统计
type StatusCount struct {
	Status string
	Count  int
}

// TopComponent 高风险组件聚合
type TopComponent struct {
	Name       string
	Version    string
	Eco        string
	CVECount   int
	MaxRisk    int
	AssetCount int
	Priority   string
}

// AgentSummary Agent 在线情况
type AgentSummary struct {
	Total   int
	Online  int
	Offline int
	Stale   int
}

// FindingEvent 漏洞处置事件（概览展示用）
type FindingEvent struct {
	ID       int64
	Time     string
	Actor    string
	Event    string
	CVEID    string
	Hostname string
	Detail   string
}

// Gauges 指标接口使用的绝对值
type Gauges struct {
	Assets          int
	Components      int
	CVEs            int
	AgentsOnline    int
	SelfcheckFailed int
}

// StatsRepository 概览与指标所需的只读统计端口
type StatsRepository interface {
	FindingsByPriority(ctx context.Context) ([]PriorityCount, error)
	FindingsByStatus(ctx context.Context) ([]StatusCount, error)
	// PriorityBefore 返回 first_seen 早于 before 的优先级分布
	PriorityBefore(ctx context.Context, before string) ([]PriorityCount, error)
	TopComponents(ctx context.Context, limit int) ([]TopComponent, error)
	AgentSummary(ctx context.Context) (AgentSummary, error)
	RecentFindingEvents(ctx context.Context, limit int) ([]FindingEvent, error)
	// Gauges 返回资产/组件/CVE/Agent/自检的绝对计数
	Gauges(ctx context.Context) (Gauges, error)
}

// RecomputeRow 重算风险分所需的一行
type RecomputeRow struct {
	ID       int64
	CVSS     float64
	EPSS     float64
	Exploit  string
	Exposure string
	Tier     string
}

// ScoreUpdate 重算后的落库字段
type ScoreUpdate struct {
	ID          int64
	Risk        int
	Priority    string
	Breakdown   string
	AssetWeight float64
}

// AuditFilter 审计日志查询条件
type AuditFilter struct {
	Action string
	Actor  string
	Limit  int
	Offset int
}
