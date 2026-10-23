package ports

import "context"

// AssetListItem 资产列表项（含汇总计数）
type AssetListItem struct {
	ID          int64  `json:"id"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	OSFamily    string `json:"osFamily"`
	OSVersion   string `json:"osVersion"`
	Env         string `json:"env"`
	Exposure    string `json:"exposure"`
	Tier        string `json:"tier"`
	Owner       string `json:"owner"`
	Source      string `json:"source"`
	AgentStatus string `json:"agentStatus"`
	LastSeen    string `json:"lastSeen"`
	Components  int    `json:"components"`
	Findings    int    `json:"findings"`
	P0          int    `json:"p0"`
	Risk        int    `json:"risk"`
}

// AssetComponentRow 资产详情中的组件行（含命中数）
type AssetComponentRow struct {
	PURL     string `json:"purl"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Eco      string `json:"ecosystem"`
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Inferred bool   `json:"inferred"`
	Findings int    `json:"findings"`
}

// AssetQueryRepository 资产列表与详情的读取端口
type AssetQueryRepository interface {
	// List 返回当前页资产与总条数
	List(ctx context.Context, query string, limit, offset int) ([]AssetListItem, int, error)
	// Detail 按 ID 读取资产汇总，不存在时返回 ErrNotFound
	Detail(ctx context.Context, id int64) (AssetListItem, error)
	// ComponentRows 返回资产组件清单（按生态、名称排序）
	ComponentRows(ctx context.Context, assetID int64) ([]AssetComponentRow, error)
}
