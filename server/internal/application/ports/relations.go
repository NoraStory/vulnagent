package ports

// AssetRelationRef 关系对端的资产摘要
type AssetRelationRef struct {
	ID             int64  `json:"id"`
	Hostname       string `json:"hostname"`
	IP             string `json:"ip"`
	BusinessSystem string `json:"businessSystem"`
	Env            string `json:"env"`
	AssetType      string `json:"assetType"`
	Risk           int    `json:"risk"`
}

// AssetRelation 一条资产关系（方向以当前资产视角给出）
type AssetRelation struct {
	ID          int64            `json:"id"`
	FromAssetID int64            `json:"fromAssetId"`
	ToAssetID   int64            `json:"toAssetId"`
	Relation    string           `json:"relation"`
	Direction   string           `json:"direction"`
	Asset       AssetRelationRef `json:"asset"`
	CreatedAt   string           `json:"createdAt"`
}

// TopologyAsset 拓扑中的资产节点
type TopologyAsset struct {
	ID             int64  `json:"id"`
	Hostname       string `json:"hostname"`
	IP             string `json:"ip"`
	BusinessSystem string `json:"businessSystem"`
	Env            string `json:"env"`
	Tier           string `json:"tier"`
	Exposure       string `json:"exposure"`
	AssetType      string `json:"assetType"`
	Status         string `json:"status"`
	Risk           int    `json:"risk"`
	Findings       int    `json:"findings"`
	Components     int    `json:"components"`
}

// TopologyEdge 拓扑中的资产关系边
type TopologyEdge struct {
	ID          int64  `json:"id"`
	FromAssetID int64  `json:"fromAssetId"`
	ToAssetID   int64  `json:"toAssetId"`
	Relation    string `json:"relation"`
}

// Topology 拓扑聚合结果
type Topology struct {
	Assets    []TopologyAsset `json:"assets"`
	Relations []TopologyEdge  `json:"relations"`
	Truncated bool            `json:"truncated"`
}
