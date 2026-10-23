package risk

import (
	"fmt"
	"math"
)

// Factor 打分明细，保证 P0 结论可解释
type Factor struct {
	Factor   string  `json:"factor"`
	Label    string  `json:"label"`
	Value    any     `json:"value"`
	Weight   float64 `json:"weight"`
	Weighted float64 `json:"weighted"`
	Note     string  `json:"note"`
}

// ExposureFactor 暴露面系数
func ExposureFactor(exposure string) float64 {
	switch exposure {
	case "public":
		return 1.0
	case "internal":
		return 0.6
	case "isolated":
		return 0.2
	}
	return 0.6
}

// ExposureCN 暴露面的中文名
func ExposureCN(exposure string) string {
	switch exposure {
	case "public":
		return "公网"
	case "internal":
		return "内网"
	case "isolated":
		return "隔离"
	}
	return "内网"
}

// TierFactor 业务等级系数
func TierFactor(tier string) float64 {
	switch tier {
	case "core":
		return 1.0
	case "important":
		return 0.8
	case "normal":
		return 0.5
	}
	return 0.5
}

// TierCN 业务等级的中文名
func TierCN(tier string) string {
	switch tier {
	case "core":
		return "核心"
	case "important":
		return "重要"
	case "normal":
		return "一般"
	}
	return "一般"
}

// ExploitFactor 在野利用系数
func ExploitFactor(state string) float64 {
	switch state {
	case "kev":
		return 1.0
	case "poc":
		return 0.6
	}
	return 0
}

// AssetWeight 资产权重 = 暴露面系数 × 业务等级系数，上限 1.0
func AssetWeight(exposure, tier string) float64 {
	w := ExposureFactor(exposure) * TierFactor(tier)
	if w > 1.0 {
		w = 1.0
	}
	return round2(w)
}

func cvssNote(cvss float64) string {
	switch {
	case cvss >= 10.0:
		return "满分"
	case cvss >= 9.0:
		return "严重"
	case cvss >= 7.0:
		return "高危"
	case cvss >= 4.0:
		return "中危"
	default:
		return "低危"
	}
}

func epssNote(epss float64) string {
	switch {
	case epss >= 0.5:
		return "高利用概率"
	case epss > 0:
		return "利用概率较低"
	default:
		return "暂无 EPSS 数据"
	}
}

func exploitNote(state string) string {
	switch state {
	case "kev":
		return "CISA KEV 在野利用"
	case "poc":
		return "存在公开 POC"
	}
	return "未见公开利用"
}

// Score 按公式实时计算风险分与优先级，并产出可解释的四项因子
func (p Policy) Score(cvss, epss float64, exploit, exposure, tier string) (int, string, []Factor) {
	aw := AssetWeight(exposure, tier)
	sCvss := cvss / 10
	sEpss := epss
	if sEpss < 0 {
		sEpss = 0
	}
	if sEpss > 1 {
		sEpss = 1
	}
	sExploit := ExploitFactor(exploit)

	raw := p.Weights.Cvss*sCvss + p.Weights.Epss*sEpss + p.Weights.Exploit*sExploit + p.Weights.Asset*aw
	riskScore := int(math.Round(raw * 100))

	priority := p.PriorityOf(riskScore, cvss, epss, exploit, exposure)

	breakdown := []Factor{
		{
			Factor:   "cvss",
			Label:    "CVSS 基础分",
			Value:    round1(cvss),
			Weight:   p.Weights.Cvss,
			Weighted: round1(100 * p.Weights.Cvss * sCvss),
			Note:     cvssNote(cvss),
		},
		{
			Factor:   "epss",
			Label:    "EPSS 利用概率",
			Value:    round1(epss*1000) / 1000,
			Weight:   p.Weights.Epss,
			Weighted: round1(100 * p.Weights.Epss * sEpss),
			Note:     epssNote(epss),
		},
		{
			Factor:   "exploit",
			Label:    "在野利用",
			Value:    exploit,
			Weight:   p.Weights.Exploit,
			Weighted: round1(100 * p.Weights.Exploit * sExploit),
			Note:     exploitNote(exploit),
		},
		{
			Factor:   "asset",
			Label:    "资产权重",
			Value:    aw,
			Weight:   p.Weights.Asset,
			Weighted: round1(100 * p.Weights.Asset * aw),
			Note:     fmt.Sprintf("%s · %s业务", ExposureCN(exposure), TierCN(tier)),
		},
	}
	return riskScore, priority, breakdown
}

// PriorityOf 分档规则：分数阈值 + 硬规则
func (p Policy) PriorityOf(score int, cvss, epss float64, exploit, exposure string) string {
	if score >= p.Thresholds.P0 || (cvss >= 9.0 && exploit != "none") || (exploit == "kev" && exposure == "public") {
		return "P0"
	}
	if score >= p.Thresholds.P1 || (cvss >= 8.0 && epss >= 0.5) {
		return "P1"
	}
	if score >= p.Thresholds.P2 {
		return "P2"
	}
	return "P3"
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

func round2(f float64) float64 { return math.Round(f*100) / 100 }
