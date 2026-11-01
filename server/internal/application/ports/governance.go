package ports

// GovernanceSummary 治理待办汇总
type GovernanceSummary struct {
	OwnerMissing    int `json:"ownerMissing"`
	Stale           int `json:"stale"`
	Duplicate       int `json:"duplicate"`
	ExposureChanged int `json:"exposureChanged"`
}

// GovernancePeer 重复资产组中的成员
type GovernancePeer struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// GovernanceItem 一条治理待办
type GovernanceItem struct {
	Type           string           `json:"type"`
	AssetID        int64            `json:"assetId"`
	Hostname       string           `json:"hostname"`
	IP             string           `json:"ip"`
	BusinessSystem string           `json:"businessSystem"`
	Owner          string           `json:"owner"`
	Status         string           `json:"status"`
	Source         string           `json:"source"`
	LastSeen       string           `json:"lastSeen"`
	Detail         string           `json:"detail"`
	OldValue       string           `json:"oldValue,omitempty"`
	NewValue       string           `json:"newValue,omitempty"`
	UpdatedAt      string           `json:"updatedAt,omitempty"`
	Related        []GovernancePeer `json:"related,omitempty"`
}
