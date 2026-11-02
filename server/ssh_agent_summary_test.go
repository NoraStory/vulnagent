package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeAgentSummary(t *testing.T) {
	raw := "```\n**结论**：主机整体运行正常\n**关键发现**：\n- 磁盘使用率 42%\n\n\n- 内存充足\n**建议**：\n- 保持现有监控\n```"
	got := normalizeAgentSummary(raw)
	if strings.Contains(got, "```") {
		t.Fatalf("代码围栏未清理：%q", got)
	}
	if !strings.Contains(got, "\n\n**关键发现**") || !strings.Contains(got, "\n\n**建议**") {
		t.Fatalf("小标题前应补空行：%q", got)
	}
	if strings.Contains(got, "\n\n\n") {
		t.Fatalf("连续空行未归一：%q", got)
	}
	if !strings.Contains(got, "- 磁盘使用率 42%") || !strings.Contains(got, "- 保持现有监控") {
		t.Fatalf("列表内容被破坏：%q", got)
	}

	if got := normalizeAgentSummary("   "); got != "" {
		t.Fatalf("空内容应返回空串，实际 %q", got)
	}

	long := strings.Repeat("测", agentSummaryRuneLimit+200)
	got = normalizeAgentSummary(long)
	if count := utf8.RuneCountInString(got); count > agentSummaryRuneLimit+1 {
		t.Fatalf("总结长度应被截断到 %d 以内，实际 %d", agentSummaryRuneLimit+1, count)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("截断后应带省略号：%q", got)
	}
}
