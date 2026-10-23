package main

import (
	"encoding/json"
	"fmt"
	"math"
)

// WeightSet 风险打分权重，四项之和须为 1.0
type WeightSet struct {
	Cvss    float64 `json:"cvss"`
	Epss    float64 `json:"epss"`
	Exploit float64 `json:"exploit"`
	Asset   float64 `json:"asset"`
}

// ThresholdSet 分档阈值
type ThresholdSet struct {
	P0 int `json:"p0"`
	P1 int `json:"p1"`
	P2 int `json:"p2"`
}

// RiskPolicy 风险策略
type RiskPolicy struct {
	Weights    WeightSet    `json:"weights"`
	Thresholds ThresholdSet `json:"thresholds"`
}

func defaultPolicy() RiskPolicy {
	return RiskPolicy{
		Weights:    WeightSet{Cvss: 0.40, Epss: 0.20, Exploit: 0.25, Asset: 0.15},
		Thresholds: ThresholdSet{P0: 85, P1: 70, P2: 50},
	}
}

// ScoreFactor 打分明细，保证 P0 结论可解释
type ScoreFactor struct {
	Factor   string  `json:"factor"`
	Label    string  `json:"label"`
	Value    any     `json:"value"`
	Weight   float64 `json:"weight"`
	Weighted float64 `json:"weighted"`
	Note     string  `json:"note"`
}

func exposureFactor(s string) float64 {
	switch s {
	case "public":
		return 1.0
	case "internal":
		return 0.6
	case "isolated":
		return 0.2
	}
	return 0.6
}

func exposureCN(s string) string {
	switch s {
	case "public":
		return "公网"
	case "internal":
		return "内网"
	case "isolated":
		return "隔离"
	}
	return "内网"
}

func tierFactor(s string) float64 {
	switch s {
	case "core":
		return 1.0
	case "important":
		return 0.8
	case "normal":
		return 0.5
	}
	return 0.5
}

func tierCN(s string) string {
	switch s {
	case "core":
		return "核心"
	case "important":
		return "重要"
	case "normal":
		return "一般"
	}
	return "一般"
}

func exploitFactor(s string) float64 {
	switch s {
	case "kev":
		return 1.0
	case "poc":
		return 0.6
	}
	return 0
}

// assetWeight 资产权重 = 暴露面系数 × 业务等级系数，上限 1.0
func assetWeight(exposure, tier string) float64 {
	w := exposureFactor(exposure) * tierFactor(tier)
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

func exploitNote(s string) string {
	switch s {
	case "kev":
		return "CISA KEV 在野利用"
	case "poc":
		return "存在公开 POC"
	}
	return "未见公开利用"
}

// score 按公式实时计算风险分与优先级，并产出可解释的四项因子
func (p RiskPolicy) score(cvss, epss float64, exploit, exposure, tier string) (int, string, []ScoreFactor) {
	aw := assetWeight(exposure, tier)
	sCvss := cvss / 10
	sEpss := epss
	if sEpss < 0 {
		sEpss = 0
	}
	if sEpss > 1 {
		sEpss = 1
	}
	sExploit := exploitFactor(exploit)

	raw := p.Weights.Cvss*sCvss + p.Weights.Epss*sEpss + p.Weights.Exploit*sExploit + p.Weights.Asset*aw
	risk := int(math.Round(raw * 100))

	priority := p.priorityOf(risk, cvss, epss, exploit, exposure)

	breakdown := []ScoreFactor{
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
			Note:     fmt.Sprintf("%s · %s业务", exposureCN(exposure), tierCN(tier)),
		},
	}
	return risk, priority, breakdown
}

// priorityOf 分档规则：分数阈值 + 硬规则
func (p RiskPolicy) priorityOf(risk int, cvss, epss float64, exploit, exposure string) string {
	if risk >= p.Thresholds.P0 || (cvss >= 9.0 && exploit != "none") || (exploit == "kev" && exposure == "public") {
		return "P0"
	}
	if risk >= p.Thresholds.P1 || (cvss >= 8.0 && epss >= 0.5) {
		return "P1"
	}
	if risk >= p.Thresholds.P2 {
		return "P2"
	}
	return "P3"
}

func marshalBreakdown(b []ScoreFactor) string {
	raw, err := json.Marshal(b)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func unmarshalPolicy(weightsJSON, thresholdsJSON string) RiskPolicy {
	p := defaultPolicy()
	if weightsJSON != "" {
		_ = json.Unmarshal([]byte(weightsJSON), &p.Weights)
	}
	if thresholdsJSON != "" {
		_ = json.Unmarshal([]byte(thresholdsJSON), &p.Thresholds)
	}
	return p
}
