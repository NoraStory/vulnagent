package main

import "vulnagent/server/internal/domain/version"

// 兼容包装：领域实现见 internal/domain/version。

// CompareVersion 按生态比较两个版本号，返回 -1/0/1
func CompareVersion(eco, a, b string) int { return version.Compare(eco, a, b) }
