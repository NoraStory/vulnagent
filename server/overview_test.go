package main

import (
	"testing"
	"time"

	"vulnagent/server/internal/application/ports"
)

func TestBuildPriorityTrend(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, cst)
	trend := buildPriorityTrend([]ports.FindingSeen{
		{Priority: "P0", FirstSeen: fmtT(now.AddDate(0, 0, -3))},
		{Priority: "P1", FirstSeen: fmtT(now.AddDate(0, 0, -1))},
		{Priority: "P2", FirstSeen: ""},
	}, now)

	if len(trend) != 14 {
		t.Fatalf("趋势应为 14 天，实际 %d", len(trend))
	}
	if last := trend[len(trend)-1]; last.Total != 3 || last.P0 != 1 || last.P1 != 1 || last.P2 != 1 {
		t.Fatalf("今日累计异常：%+v", last)
	}
	// 3 天前：只有 P0 与无效时间的 P2 已计入
	threeDaysAgo := trend[len(trend)-1-3]
	if threeDaysAgo.Total != 2 || threeDaysAgo.P0 != 1 || threeDaysAgo.P1 != 0 || threeDaysAgo.P2 != 1 {
		t.Fatalf("3 天前累计异常：%+v", threeDaysAgo)
	}
	// 2 天前：仍不含 1 天前的 P1
	if twoDaysAgo := trend[len(trend)-1-2]; twoDaysAgo.P1 != 0 || twoDaysAgo.Total != 2 {
		t.Fatalf("2 天前累计异常：%+v", twoDaysAgo)
	}
}
