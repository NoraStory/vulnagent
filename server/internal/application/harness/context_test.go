package harnessapp

import (
	"context"
	"strings"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
)

func TestBuildContextCompactsHistory(t *testing.T) {
	svc := &Service{SystemPrompt: "system-prompt"}
	history := make([]harness.Message, 0, 30)
	for i := 0; i < 30; i++ {
		history = append(history, harness.Message{Role: "user", Content: strings.Repeat("x", 300)})
	}
	history = append(history, harness.Message{Role: "assistant", Content: "最新结论"})

	msgs := svc.buildContext(context.Background(), history)
	if len(msgs) < 2 || msgs[0].Role != "system" {
		t.Fatalf("上下文结构异常：%+v", msgs)
	}
	joined := ""
	for _, m := range msgs {
		joined += m.Content
	}
	if !strings.Contains(joined, "压缩摘要") || !strings.Contains(joined, "最新结论") {
		t.Fatalf("缺少摘要或最新消息：%s", joined)
	}
	if len(msgs) > 23 {
		t.Fatalf("压缩后消息数量应受控，实际 %d", len(msgs))
	}
}

func TestTrimContextKeepsSystemAndRecent(t *testing.T) {
	messages := []ports.LLMMessage{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: strings.Repeat("a", 100)},
		{Role: "assistant", Content: strings.Repeat("b", 100)},
	}
	out := trimContext(messages, 200)
	if len(out) == 0 || out[0].Role != "system" {
		t.Fatalf("系统消息应保留：%+v", out)
	}
}
