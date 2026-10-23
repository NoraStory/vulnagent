// Package vuln 是漏洞领域的核心模型：CVSS 评分、受影响区间、
// 漏洞生命周期状态与业务字典。该包只依赖标准库与同层 version 包。
package vuln

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

// Source 漏洞情报来源
type Source string

const (
	SourceCVE  Source = "cve"
	SourceOSV  Source = "osv"
	SourceSSH  Source = "ssh"
	SourceSeed Source = "seed"
)

// BaseScore 按 CVSS 3.x 规范计算基础分（含 3.1 的 roundup 规则）。
// 情报接口只返回 CVSS 向量，分值与严重级需要本地计算。
func BaseScore(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, errors.New("仅支持 CVSS 3.x 向量")
	}
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		metrics[strings.ToUpper(key)] = strings.ToUpper(value)
	}

	av, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	if !ok {
		return 0, errors.New("无效的 AV 取值")
	}
	ac, ok := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	if !ok {
		return 0, errors.New("无效的 AC 取值")
	}
	ui, ok := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	if !ok {
		return 0, errors.New("无效的 UI 取值")
	}
	changed := metrics["S"] == "C"
	if metrics["S"] != "C" && metrics["S"] != "U" {
		return 0, errors.New("无效的 S 取值")
	}

	pr := 0.0
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if changed {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if changed {
			pr = 0.5
		} else {
			pr = 0.27
		}
	default:
		return 0, errors.New("无效的 PR 取值")
	}

	weight := func(key string) (float64, bool) {
		switch metrics[key] {
		case "H":
			return 0.56, true
		case "L":
			return 0.22, true
		case "N":
			return 0, true
		}
		return 0, false
	}
	c, okC := weight("C")
	i, okI := weight("I")
	a, okA := weight("A")
	if !okC || !okI || !okA {
		return 0, errors.New("无效的 C/I/A 取值")
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * av * ac * pr * ui

	var score float64
	if changed {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return RoundUp1(score), nil
}

// RoundUp1 CVSS 3.1 的向上取整到一位小数
func RoundUp1(value float64) float64 {
	scaled := math.Round(value * 100000)
	if math.Mod(scaled, 10000) == 0 {
		return scaled / 100000
	}
	return (math.Floor(scaled/10000) + 1) / 10
}

// Severity CVSS 严重级
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityOf 按 CVSS 分数分档
func SeverityOf(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ParseScore 从字符串字段解析分值，失败返回 0
func ParseScore(v string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0
	}
	return f
}
