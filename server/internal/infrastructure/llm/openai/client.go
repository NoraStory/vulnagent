// Package openai 实现 OpenAI 兼容的 Chat Completions 客户端（含工具调用）。
// 兼容火山方舟、DeepSeek、OpenAI 等同协议服务，凭据只从环境变量注入。
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// Config 客户端配置
type Config struct {
	BaseURL string
	APIKey  string
	Model   string
	Timeout time.Duration
}

// Client OpenAI 兼容客户端
type Client struct {
	cfg  Config
	http *http.Client
}

// New 构造客户端，BaseURL 末尾的斜杠会被去掉
func New(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Client{
		cfg:  Config{BaseURL: strings.TrimRight(cfg.BaseURL, "/"), APIKey: cfg.APIKey, Model: cfg.Model, Timeout: cfg.Timeout},
		http: &http.Client{Timeout: cfg.Timeout},
	}
}

// Model 返回当前模型 ID
func (c *Client) Model() string { return c.cfg.Model }

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Tools       []chatTool    `json:"tools,omitempty"`
	ToolChoice  string        `json:"tool_choice,omitempty"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   string         `json:"content"`
			ToolCalls []chatToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Chat 发起一次对话，返回文本或工具调用
func (c *Client) Chat(ctx context.Context, req ports.LLMRequest) (ports.LLMResponse, error) {
	var out ports.LLMResponse
	if c.cfg.BaseURL == "" || c.cfg.APIKey == "" || c.cfg.Model == "" {
		return out, fmt.Errorf("模型未配置")
	}

	body := chatRequest{Model: c.cfg.Model, Temperature: 0.2}
	for _, m := range req.Messages {
		msg := chatMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID}
		for _, tc := range m.ToolCalls {
			call := chatToolCall{ID: tc.ID, Type: "function"}
			call.Function.Name = tc.Name
			call.Function.Arguments = tc.Arguments
			msg.ToolCalls = append(msg.ToolCalls, call)
		}
		body.Messages = append(body.Messages, msg)
	}
	for _, t := range req.Tools {
		tool := chatTool{Type: "function"}
		tool.Function.Name = t.Name
		tool.Function.Description = t.Description
		tool.Function.Parameters = t.Params
		body.Tools = append(body.Tools, tool)
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("模型返回 HTTP %d：%s", resp.StatusCode, clip(string(payload), 300))
	}
	var parsed chatResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return out, fmt.Errorf("解析模型响应失败：%w", err)
	}
	if parsed.Error != nil {
		return out, fmt.Errorf("模型错误：%s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return out, fmt.Errorf("模型未返回结果")
	}
	msg := parsed.Choices[0].Message
	out.Content = strings.TrimSpace(msg.Content)
	for _, tc := range msg.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ports.LLMToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
