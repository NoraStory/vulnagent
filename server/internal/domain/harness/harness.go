// Package harness 定义 Agent Harness 的领域模型：
// 工具规格、风险分级、会话、消息、工具调用与审批。
package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Risk 工具风险等级
type Risk string

const (
	// RiskLow 只读或幂等无损操作，可直接执行
	RiskLow Risk = "low"
	// RiskMedium 有副作用但可恢复，需要一次人工审批
	RiskMedium Risk = "medium"
	// RiskHigh 影响处置结论或凭据，需要审批 + 口令再认证
	RiskHigh Risk = "high"
)

// Valid 是否为已知风险等级
func (r Risk) Valid() bool {
	switch r {
	case RiskLow, RiskMedium, RiskHigh:
		return true
	}
	return false
}

// NeedsApproval 是否需要人工审批
func (r Risk) NeedsApproval() bool { return r == RiskMedium || r == RiskHigh }

// NeedsReauth 是否需要口令再认证
func (r Risk) NeedsReauth() bool { return r == RiskHigh }

// ToolSpec 工具规格。工具全部静态注册，模型无法新增。
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Risk        Risk            `json:"risk"`
	ReadOnly    bool            `json:"readOnly"`
	MinRole     string          `json:"minRole"`
	Params      json.RawMessage `json:"params"`
}

// Tool 工具规格 + 执行器
type Tool struct {
	Spec ToolSpec
	Run  func(args json.RawMessage) (any, error)
}

// Session Agent 会话
type Session struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	Role      string `json:"role"`
	Title     string `json:"title"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// Message 会话消息
type Message struct {
	ID         int64  `json:"id"`
	SessionID  string `json:"sessionId"`
	Role       string `json:"role"`
	Content    string `json:"content"`
	ToolCalls  string `json:"toolCalls"`
	ToolCallID string `json:"toolCallId"`
	CreatedAt  string `json:"createdAt"`
}

// ToolCallRecord 一次工具调用留痕
type ToolCallRecord struct {
	ID         int64  `json:"id"`
	SessionID  string `json:"sessionId"`
	Tool       string `json:"tool"`
	Args       string `json:"args"`
	ArgsHash   string `json:"argsHash"`
	Risk       string `json:"risk"`
	Status     string `json:"status"`
	Result     string `json:"result"`
	Error      string `json:"error"`
	Actor      string `json:"actor"`
	Approver   string `json:"approver"`
	CreatedAt  string `json:"createdAt"`
	FinishedAt string `json:"finishedAt"`
}

// Approval 一次性人工审批
type Approval struct {
	ID          string `json:"id"`
	SessionID   string `json:"sessionId"`
	Tool        string `json:"tool"`
	ArgsHash    string `json:"argsHash"`
	Args        string `json:"args"`
	CallID      string `json:"callId"`
	Risk        string `json:"risk"`
	RequestedBy string `json:"requestedBy"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	RequestedAt string `json:"requestedAt"`
	ExpiresAt   string `json:"expiresAt"`
	DecidedAt   string `json:"decidedAt"`
	DecidedBy   string `json:"decidedBy"`
	ConsumedAt  string `json:"consumedAt"`
}

// ArgsHash 计算参数指纹：键排序后序列化再取 SHA-256。
// 审批与调用都以指纹绑定，任何参数改动都会失效。
func ArgsHash(args json.RawMessage) string {
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		sum := sha256.Sum256(args)
		return hex.EncodeToString(sum[:])
	}
	canonical := canonicalJSON(v)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func canonicalJSON(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(":")
			b.WriteString(canonicalJSON(t[k]))
		}
		b.WriteString("}")
		return b.String()
	case []any:
		var b strings.Builder
		b.WriteString("[")
		for i, item := range t {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(canonicalJSON(item))
		}
		b.WriteString("]")
		return b.String()
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return "null"
		}
		return string(raw)
	}
}
