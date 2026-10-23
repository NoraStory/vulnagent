package main

import "vulnagent/server/internal/domain/vuln"

// 兼容包装：领域实现见 internal/domain/vuln。

// BaseScore 按 CVSS 3.x 规范计算基础分
func BaseScore(vector string) (float64, error) { return vuln.BaseScore(vector) }

// SeverityOf 按 CVSS 分数分档
func SeverityOf(score float64) string { return string(vuln.SeverityOf(score)) }
