// Package asset 定义资产与软件成分的值对象。
package asset

// Exposure 暴露面
type Exposure string

const (
	ExposurePublic   Exposure = "public"
	ExposureInternal Exposure = "internal"
	ExposureIsolated Exposure = "isolated"
)

// Valid 是否为已知暴露面
func (e Exposure) Valid() bool {
	switch e {
	case ExposurePublic, ExposureInternal, ExposureIsolated:
		return true
	}
	return false
}

// Tier 业务等级
type Tier string

const (
	TierCore      Tier = "core"
	TierImportant Tier = "important"
	TierNormal    Tier = "normal"
)

// Valid 是否为已知业务等级
func (t Tier) Valid() bool {
	switch t {
	case TierCore, TierImportant, TierNormal:
		return true
	}
	return false
}

// Asset 一台被纳管的主机
type Asset struct {
	ID          int64    `json:"id"`
	Hostname    string   `json:"hostname"`
	IP          string   `json:"ip"`
	OSFamily    string   `json:"osFamily"`
	OSVersion   string   `json:"osVersion"`
	Env         string   `json:"env"`
	Exposure    Exposure `json:"exposure"`
	Tier        Tier     `json:"tier"`
	Owner       string   `json:"owner"`
	Source      string   `json:"source"`
	AgentStatus string   `json:"agentStatus"`
	LastSeenAt  string   `json:"lastSeenAt"`
}

// Component 资产上的一个软件成分
type Component struct {
	ID       int64  `json:"id"`
	AssetID  int64  `json:"assetId"`
	PURL     string `json:"purl"`
	Eco      string `json:"eco"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Inferred bool   `json:"inferred"`
}

// Inventory 某次采集得到的资产快照
type Inventory struct {
	Asset      Asset       `json:"asset"`
	Components []Component `json:"components"`
}
