package ports

// BusinessSystem 业务系统及其重要性，用于风险评分联动与拓扑分组
type BusinessSystem struct {
	Name        string `json:"name"`
	Tier        string `json:"tier"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updatedAt"`
	AssetCount  int    `json:"assetCount"`
}
