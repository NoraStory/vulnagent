package ports

import "context"

// Ticket 本地修复工单。控制面自建工单，不依赖外部 ITSM。
type Ticket struct {
	ID        string `json:"id"`
	FindingID int64  `json:"findingId"`
	CVEID     string `json:"cveId"`
	AssetID   int64  `json:"assetId"`
	Priority  string `json:"priority"`
	Status    string `json:"status"`
	Assignee  string `json:"assignee"`
	CreatedBy string `json:"createdBy"`
	Note      string `json:"note"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// TicketRepository 工单持久化端口
type TicketRepository interface {
	Create(ctx context.Context, t Ticket) error
	// ByFinding 按漏洞读取工单，不存在时 found=false
	ByFinding(ctx context.Context, findingID int64) (Ticket, bool, error)
	// UpdateStatus 同步工单状态与责任人
	UpdateStatus(ctx context.Context, id, status, assignee, now string) error
	// List 按状态过滤（空串表示全部），按更新时间倒序
	List(ctx context.Context, status string, limit int) ([]Ticket, error)
}
