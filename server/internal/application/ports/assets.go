package ports

import "context"

// AssetIdentifier 资产标识（主机名、IP、MAC、序列号、云实例等）
type AssetIdentifier struct {
	ID        int64  `json:"id"`
	AssetID   int64  `json:"assetId"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
}

// AssetChange 资产档案字段变更记录
type AssetChange struct {
	ID        int64  `json:"id"`
	AssetID   int64  `json:"assetId"`
	Field     string `json:"field"`
	OldValue  string `json:"oldValue"`
	NewValue  string `json:"newValue"`
	Actor     string `json:"actor"`
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt"`
}

// AssetFilter 资产列表筛选条件
type AssetFilter struct {
	Query           string
	Env             string
	Exposure        string
	Tier            string
	Status          string
	AssetType       string
	BusinessSystem  string
	Owner           string
	CloudProvider   string
	ClusterID       int64
	IncludeArchived bool
}

// AssetListItem 资产列表项（含汇总计数）
type AssetListItem struct {
	ID             int64             `json:"id"`
	Hostname       string            `json:"hostname"`
	IP             string            `json:"ip"`
	OSFamily       string            `json:"osFamily"`
	OSVersion      string            `json:"osVersion"`
	Env            string            `json:"env"`
	Exposure       string            `json:"exposure"`
	Tier           string            `json:"tier"`
	Owner          string            `json:"owner"`
	Source         string            `json:"source"`
	AgentStatus    string            `json:"agentStatus"`
	LastSeen       string            `json:"lastSeen"`
	AssetType      string            `json:"assetType"`
	Status         string            `json:"status"`
	BusinessSystem string            `json:"businessSystem"`
	Department     string            `json:"department"`
	OwnerEmail     string            `json:"ownerEmail"`
	Location       string            `json:"location"`
	CloudProvider  string            `json:"cloudProvider"`
	CloudAccount   string            `json:"cloudAccount"`
	Region         string            `json:"region"`
	InstanceID     string            `json:"instanceId"`
	MAC            string            `json:"mac"`
	Serial         string            `json:"serial"`
	OSArch         string            `json:"osArch"`
	Kernel         string            `json:"kernel"`
	Virtualized    string            `json:"virtualized"`
	MergedInto     int64             `json:"mergedInto"`
	Tags           []string          `json:"tags"`
	Identifiers    []AssetIdentifier `json:"identifiers,omitempty"`
	Components     int               `json:"components"`
	Findings       int               `json:"findings"`
	P0             int               `json:"p0"`
	Risk           int               `json:"risk"`
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
	List(ctx context.Context, filter AssetFilter, limit, offset int) ([]AssetListItem, int, error)
	// Detail 按 ID 读取资产汇总，不存在时返回 ErrNotFound
	Detail(ctx context.Context, id int64) (AssetListItem, error)
	// ComponentRows 返回资产组件清单（按生态、名称排序）
	ComponentRows(ctx context.Context, assetID int64) ([]AssetComponentRow, error)
}
