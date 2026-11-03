package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func TestChatParsesUsageAndReportsIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}`))
	}))
	defer server.Close()

	var reported Usage
	client := New(Config{
		BaseURL: server.URL, APIKey: "test", Model: "model-a",
		OnUsage: func(u Usage) { reported = u },
	})
	resp, err := client.Chat(context.Background(), ports.LLMRequest{
		Purpose:  "agent",
		Messages: []ports.LLMMessage{{Role: "user", Content: "查看磁盘"}},
	})
	if err != nil {
		t.Fatalf("调用失败：%v", err)
	}
	if resp.PromptTokens != 12 || resp.CompletionTokens != 5 || resp.TotalTokens != 17 || resp.UsageEstimated {
		t.Fatalf("响应 usage 解析异常：%+v", resp)
	}
	if reported.Model != "model-a" || reported.Purpose != "agent" || reported.TotalTokens != 17 || reported.Estimated {
		t.Fatalf("回调用量异常：%+v", reported)
	}
}

func TestChatEstimatesUsageWhenProviderOmitsIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"排查完成，磁盘使用率 82%"}}]}`))
	}))
	defer server.Close()

	var reported Usage
	client := New(Config{
		BaseURL: server.URL, APIKey: "test", Model: "model-b",
		OnUsage: func(u Usage) { reported = u },
	})
	resp, err := client.Chat(context.Background(), ports.LLMRequest{
		Purpose:  "",
		Messages: []ports.LLMMessage{{Role: "user", Content: "检查磁盘使用情况"}},
	})
	if err != nil {
		t.Fatalf("调用失败：%v", err)
	}
	if !resp.UsageEstimated || resp.TotalTokens <= 0 || resp.TotalTokens != resp.PromptTokens+resp.CompletionTokens {
		t.Fatalf("应回落到估算用量：%+v", resp)
	}
	if !reported.Estimated || reported.TotalTokens != resp.TotalTokens {
		t.Fatalf("估算用量回调异常：%+v", reported)
	}
	if reported.Purpose != "unknown" {
		t.Fatalf("未标注用途应回落 unknown：%+v", reported)
	}
}
