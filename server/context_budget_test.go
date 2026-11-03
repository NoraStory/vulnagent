package main

import (
	"strings"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	if got := estimateTokens(""); got != 0 {
		t.Fatalf("空文本应为 0，实际 %d", got)
	}
	if got := estimateTokens("abcdefgh"); got != 2 {
		t.Fatalf("ASCII 应按 4 字符 1 token，实际 %d", got)
	}
	if got := estimateTokens("中文上下文"); got != 5 {
		t.Fatalf("中文应按 1 字 1 token，实际 %d", got)
	}
}

func TestBuildSSHAgentPromptCompressesOlderSteps(t *testing.T) {
	host := sshHost{Name: "web-01", Host: "10.0.0.1", Port: 22, Username: "root"}
	history := make([]sshAgentStep, 0, 8)
	for index := 0; index < 8; index++ {
		history = append(history, sshAgentStep{
			Index:    index,
			Command:  "df -h /var",
			Output:   strings.Repeat("error: permission denied while reading volume\n", 180),
			ExitCode: 1,
		})
	}
	text, usage := buildSSHAgentPrompt(host, "排查磁盘与权限问题", "", "", history, 1)
	if !strings.Contains(text, "较早步骤摘要") {
		t.Fatalf("较早步骤应被压缩：%s", text[:200])
	}
	if !strings.Contains(text, "最近步骤") {
		t.Fatal("最近步骤应保留")
	}
	if usage.CompressedItems == 0 {
		t.Fatalf("压缩计数应大于 0：%+v", usage)
	}
	if usage.SavedTokens <= 0 {
		t.Fatalf("应统计节省 token：%+v", usage)
	}
	if usage.UsedTokens > usage.BudgetTokens {
		t.Fatalf("压缩后仍超出预算：used=%d budget=%d", usage.UsedTokens, usage.BudgetTokens)
	}
	if usage.Percent <= 0 || usage.Percent > 100 {
		t.Fatalf("占用百分比异常：%+v", usage)
	}
}

func TestBuildSSHAgentPromptKeepsRecentOutput(t *testing.T) {
	host := sshHost{Name: "web-01", Host: "10.0.0.1", Port: 22, Username: "root"}
	recent := strings.Repeat("ok\n", 100)
	history := []sshAgentStep{{Index: 0, Command: "uptime", Output: recent}}
	text, usage := buildSSHAgentPrompt(host, "查看负载", "", "", history, 7)
	if !strings.Contains(text, "uptime") || !strings.Contains(text, "ok") {
		t.Fatal("最近步骤的命令与输出应保留")
	}
	if usage.HistoryItems != 1 {
		t.Fatalf("历史条数异常：%+v", usage)
	}
}

func TestBudgetedSSHAIHistoryCompresses(t *testing.T) {
	items := make([]sshAIHistoryItem, 0, 20)
	for index := 0; index < 20; index++ {
		role := "user"
		if index%2 == 1 {
			role = "assistant"
		}
		items = append(items, sshAIHistoryItem{Role: role, Content: strings.Repeat("历史内容", 250)})
	}
	messages, compressed, saved, itemsTotal := budgetedSSHAIHistory(items, 8)
	if compressed == 0 || saved <= 0 {
		t.Fatalf("应压缩并统计节省：compressed=%d saved=%d", compressed, saved)
	}
	if itemsTotal != 20 {
		t.Fatalf("有效历史条数异常：%d", itemsTotal)
	}
	if len(messages) == 0 || messages[0].Role != "system" || !strings.Contains(messages[0].Content, "较早对话摘要") {
		t.Fatalf("首条应为压缩摘要：%+v", messages[:1])
	}
	if len(messages) > 1+8 {
		t.Fatalf("保留消息数超出上限：%d", len(messages))
	}
}

func TestAgentContextBudgetSupportsLongContext(t *testing.T) {
	t.Setenv("VA_AGENT_CONTEXT_BUDGET", "1000000")
	if got := agentContextBudget(); got != 1000000 {
		t.Fatalf("应允许 1M 预算，实际 %d", got)
	}
	t.Setenv("VA_AGENT_CONTEXT_BUDGET", "2000000")
	if got := agentContextBudget(); got != agentContextBudgetMax {
		t.Fatalf("超上限应钳制到 %d，实际 %d", agentContextBudgetMax, got)
	}
	t.Setenv("VA_AGENT_CONTEXT_BUDGET", "1000")
	if got := agentContextBudget(); got != agentContextBudgetDefault {
		t.Fatalf("低于下限应回落默认值，实际 %d", got)
	}
}

func TestBuildSSHAgentPromptUsesLargeBudget(t *testing.T) {
	host := sshHost{Name: "web-01", Host: "10.0.0.1", Port: 22, Username: "root"}
	history := make([]sshAgentStep, 0, 30)
	for index := 0; index < 30; index++ {
		history = append(history, sshAgentStep{
			Index:    index,
			Command:  "journalctl -u nginx --no-pager -n 500",
			Output:   strings.Repeat("2026-11-03 access log line with detail\n", 500),
			ExitCode: 0,
		})
	}
	t.Setenv("VA_AGENT_CONTEXT_BUDGET", "1000000")
	text, usage := buildSSHAgentPrompt(host, "分析访问日志", "", "", history, 0)
	if usage.BudgetTokens != 1000000 {
		t.Fatalf("预算应取环境值，实际 %+v", usage)
	}
	if usage.UsedTokens <= 30000 {
		t.Fatalf("大预算应保留更多上下文，实际仅 %d token", usage.UsedTokens)
	}
	if usage.UsedTokens > usage.BudgetTokens {
		t.Fatalf("超出预算：%+v", usage)
	}
	if !strings.Contains(text, "最近步骤") {
		t.Fatal("大预算应保留最近步骤完整输出")
	}
}
