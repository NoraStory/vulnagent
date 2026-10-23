package ports

import "context"

// AssetListItem 资产列表项（含汇总计数）
type AssetListItem struct {
	ID          int64
	Hostname    string
	IP          string
	OSFamily    string
	OSVersion   string
	Env         string
	Exposure    string
	Tier        string
	Owner       string
	Source      string
	AgentStatus string
	LastSeen    string
	Components  int
	Findings    int
	P0          int
	Risk        int
}

// AssetComponentRow 资产详情中的组件行（含命中数）
type AssetComponentRow struct {
	PURL     string
	Name     string
	Version  string
	Eco      string
	Vendor   string
	Product  string
	Inferred bool
	Findings int
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
