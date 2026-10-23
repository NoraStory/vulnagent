// Package risk 定义漏洞风险打分的领域模型：
// 四因子加权公式、分档阈值与可解释的打分明细。
// 该包只依赖标准库，不感知数据库、HTTP 或任何基础设施。
package risk

import "encoding/json"

// Weights 四项打分权重，之和应为 1.0
type Weights struct {
	Cvss    float64 `json:"cvss"`
	Epss    float64 `json:"epss"`
	Exploit float64 `json:"exploit"`
	Asset   float64 `json:"asset"`
}

// Thresholds 分档阈值
type Thresholds struct {
	P0 int `json:"p0"`
	P1 int `json:"p1"`
	P2 int `json:"p2"`
}

// Policy 风险策略：权重 + 阈值
type Policy struct {
	Weights    Weights    `json:"weights"`
	Thresholds Thresholds `json:"thresholds"`
}

// DefaultPolicy 返回出厂策略：CVSS 40%、EPSS 20%、在野利用 25%、资产权重 15%
func DefaultPolicy() Policy {
	return Policy{
		Weights:    Weights{Cvss: 0.40, Epss: 0.20, Exploit: 0.25, Asset: 0.15},
		Thresholds: Thresholds{P0: 85, P1: 70, P2: 50},
	}
}

// UnmarshalPolicy 从库中存储的权重/阈值 JSON 还原策略，空值回落到默认值
func UnmarshalPolicy(weightsJSON, thresholdsJSON string) Policy {
	p := DefaultPolicy()
	if weightsJSON != "" {
		_ = json.Unmarshal([]byte(weightsJSON), &p.Weights)
	}
	if thresholdsJSON != "" {
		_ = json.Unmarshal([]byte(thresholdsJSON), &p.Thresholds)
	}
	return p
}

// MarshalBreakdown 把打分明细序列化为库中存储的 JSON 字符串
func MarshalBreakdown(factors []Factor) string {
	raw, err := json.Marshal(factors)
	if err != nil {
		return "[]"
	}
	return string(raw)
}
