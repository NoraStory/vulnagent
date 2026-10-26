package ports

import (
	"context"
	"encoding/json"

	"vulnagent/server/internal/domain/harness"
)

// LLMToolCall 模型返回的一次工具调用
type LLMToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// LLMMessage 模型消息
type LLMMessage struct {
	Role       string
	Content    string
	ToolCalls  []LLMToolCall
	ToolCallID string
}

// LLMToolDef 暴露给模型的工具定义
type LLMToolDef struct {
	Name        string
	Description string
	Params      json.RawMessage
}

// LLMRequest 一次对话请求
type LLMRequest struct {
	Messages []LLMMessage
	Tools    []LLMToolDef
}

// LLMResponse 一次对话响应
type LLMResponse struct {
	Content   string
	ToolCalls []LLMToolCall
}

// LLM 通用 OpenAI 兼容模型端口
type LLM interface {
	Chat(ctx context.Context, req LLMRequest) (LLMResponse, error)
	Model() string
}

// HarnessRepository Agent 会话与审批的持久化端口
type HarnessRepository interface {
	CreateSession(ctx context.Context, s harness.Session) error
	GetSession(ctx context.Context, id string) (harness.Session, error)
	ListSessions(ctx context.Context, owner string, limit int) ([]harness.Session, error)
	TouchSession(ctx context.Context, id, at string) error
	// UpdateSessionApprovalMode 更新会话审批模式
	UpdateSessionApprovalMode(ctx context.Context, id string, mode harness.ApprovalMode, at string) error

	AppendMessage(ctx context.Context, m harness.Message) (int64, error)
	Messages(ctx context.Context, sessionID string, limit int) ([]harness.Message, error)

	RecordToolCall(ctx context.Context, r harness.ToolCallRecord) (int64, error)
	FinishToolCall(ctx context.Context, id int64, status, result, errMsg, approver, at string) error

	CreateApproval(ctx context.Context, a harness.Approval) error
	GetApproval(ctx context.Context, id string) (harness.Approval, error)
	DecideApproval(ctx context.Context, id, status, by, at string) error
	// ConsumeApproval 一次性消费，成功返回 true；已消费或过期返回 false
	ConsumeApproval(ctx context.Context, id, at string) (bool, error)
	// PendingApproval 查找同一会话下匹配工具与参数指纹的待审批记录
	PendingApproval(ctx context.Context, sessionID, tool, argsHash string) (harness.Approval, bool, error)
	// PendingApprovals 返回会话下全部未过期待审批记录
	PendingApprovals(ctx context.Context, sessionID, at string) ([]harness.Approval, error)
	// HasPendingApproval 会话是否存在未过期且未处理的审批
	HasPendingApproval(ctx context.Context, sessionID, at string) (bool, error)
}
