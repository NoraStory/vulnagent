package harnessapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
	"vulnagent/server/internal/domain/identity"
	"vulnagent/server/internal/platform/clock"
)

var (
	// ErrUnauthorized 会话或审批不属于当前账号
	ErrUnauthorized = errors.New("无权访问该会话")
	// ErrBusy 存在待审批操作，需先处理
	ErrBusy = errors.New("存在待审批操作，请先处理")
	// ErrReauth 高风险操作需要口令再认证
	ErrReauth = errors.New("高风险操作需要口令再认证")
	// ErrNotPending 审批已失效或已被处理
	ErrNotPending = errors.New("审批已失效或已被处理")
)

// Options 执行闸门参数
type Options struct {
	MaxSteps      int
	RatePerMinute int
	MaxArgsBytes  int
	ApprovalTTL   time.Duration
	ReauthWindow  time.Duration
}

// DefaultOptions 默认闸门参数
func DefaultOptions() Options {
	return Options{
		MaxSteps:      4,
		RatePerMinute: 20,
		MaxArgsBytes:  8 << 10,
		ApprovalTTL:   10 * time.Minute,
		ReauthWindow:  5 * time.Minute,
	}
}

// Event 流式事件
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// Principal 调用主体，只来自服务端会话
type Principal struct {
	Username string
	Role     string
}

// Service Harness 应用服务
type Service struct {
	Repo           ports.HarnessRepository
	LLM            ports.LLM
	Registry       *Registry
	VerifyPassword func(username, password string) bool
	SystemPrompt   string
	Opts           Options

	mu     sync.Mutex
	calls  map[string][]time.Time
	reauth map[string]time.Time
}

// New 构造服务
func New(repo ports.HarnessRepository, llm ports.LLM, registry *Registry, verify func(string, string) bool) *Service {
	return &Service{
		Repo:           repo,
		LLM:            llm,
		Registry:       registry,
		VerifyPassword: verify,
		Opts:           DefaultOptions(),
		calls:          make(map[string][]time.Time),
		reauth:         make(map[string]time.Time),
	}
}

// Available 模型与工具是否就绪
func (s *Service) Available() bool {
	return s != nil && s.LLM != nil && s.Registry != nil && s.Registry.Len() > 0
}

// Model 当前模型 ID
func (s *Service) Model() string {
	if s == nil || s.LLM == nil {
		return ""
	}
	return s.LLM.Model()
}

// Tools 返回当前角色可见的工具规格
func (s *Service) Tools(role string) []harness.ToolSpec {
	if s == nil || s.Registry == nil {
		return []harness.ToolSpec{}
	}
	minRank := identity.Role(role).Rank()
	out := make([]harness.ToolSpec, 0, s.Registry.Len())
	for _, spec := range s.Registry.Specs() {
		if identity.Role(spec.MinRole).Rank() <= minRank {
			out = append(out, spec)
		}
	}
	return out
}

// CreateSession 新建会话
func (s *Service) CreateSession(ctx context.Context, p Principal, title string) (harness.Session, error) {
	now := clock.FormatNow()
	title = strings.TrimSpace(title)
	if title == "" {
		title = "未命名会话"
	}
	sess := harness.Session{
		ID:        randomID(),
		Owner:     p.Username,
		Role:      p.Role,
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Repo.CreateSession(ctx, sess); err != nil {
		return harness.Session{}, err
	}
	return sess, nil
}

// ListSessions 列出当前账号的会话
func (s *Service) ListSessions(ctx context.Context, p Principal) ([]harness.Session, error) {
	return s.Repo.ListSessions(ctx, p.Username, 50)
}

// Session 读取并校验会话归属
func (s *Service) Session(ctx context.Context, p Principal, sessionID string) (harness.Session, error) {
	return s.session(ctx, p, sessionID)
}

// Messages 读取会话消息
func (s *Service) Messages(ctx context.Context, p Principal, sessionID string) ([]harness.Message, error) {
	if _, err := s.session(ctx, p, sessionID); err != nil {
		return nil, err
	}
	return s.Repo.Messages(ctx, sessionID, 200)
}

// Chat 处理一条用户消息，事件通过 emit 同步推送
func (s *Service) Chat(ctx context.Context, p Principal, sessionID, text string, emit func(Event)) error {
	if !s.Available() {
		return errors.New("模型未配置")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return errors.New("消息不能为空")
	}
	sess, err := s.session(ctx, p, sessionID)
	if err != nil {
		return err
	}
	now := clock.FormatNow()
	if _, err := s.Repo.AppendMessage(ctx, harness.Message{
		SessionID: sess.ID, Role: "user", Content: text, ToolCalls: "[]", CreatedAt: now,
	}); err != nil {
		return err
	}
	_ = s.Repo.TouchSession(ctx, sess.ID, now)
	emit(Event{Type: "message", Data: map[string]any{"role": "user", "content": text}})
	return s.runLoop(ctx, p, sess, emit)
}

// Resume 在审批处理完成后继续对话
func (s *Service) Resume(ctx context.Context, p Principal, sessionID string, emit func(Event)) error {
	if !s.Available() {
		return errors.New("模型未配置")
	}
	sess, err := s.session(ctx, p, sessionID)
	if err != nil {
		return err
	}
	if pending, err := s.Repo.HasPendingApproval(ctx, sess.ID, clock.FormatNow()); err != nil {
		return err
	} else if pending {
		return ErrBusy
	}
	return s.runLoop(ctx, p, sess, emit)
}

// Decide 处理审批：approve 会立即执行工具，reject 只记录结论
func (s *Service) Decide(ctx context.Context, p Principal, approvalID, decision, password string) (harness.Approval, json.RawMessage, error) {
	ap, err := s.Repo.GetApproval(ctx, approvalID)
	if err != nil {
		return ap, nil, err
	}
	sess, err := s.session(ctx, p, ap.SessionID)
	if err != nil {
		return ap, nil, err
	}
	if ap.RequestedBy != p.Username && sess.Owner != p.Username {
		return ap, nil, ErrUnauthorized
	}
	now := clock.FormatNow()
	if ap.Status != "pending" || ap.ExpiresAt <= now {
		return ap, nil, ErrNotPending
	}
	tool, ok := s.Registry.Get(ap.Tool)
	if !ok {
		return ap, nil, fmt.Errorf("工具已下线：%s", ap.Tool)
	}
	if decision == "reject" {
		if err := s.Repo.DecideApproval(ctx, ap.ID, "rejected", p.Username, now); err != nil {
			return ap, nil, err
		}
		text := "用户拒绝了该操作：" + ap.Tool
		s.appendMessage(ctx, ap.SessionID, "tool", text, nil, ap.CallID)
		emitToolResult(s, ap.SessionID, p.Username, ap.Tool, "rejected", text, "", p.Username, now)
		return ap, marshalJSON(map[string]any{"status": "rejected"}), nil
	}
	if tool.Spec.Risk.NeedsReauth() && !s.reauthOK(p.Username, password) {
		return ap, nil, ErrReauth
	}
	if err := s.Repo.DecideApproval(ctx, ap.ID, "approved", p.Username, now); err != nil {
		return ap, nil, err
	}
	consumed, err := s.Repo.ConsumeApproval(ctx, ap.ID, now)
	if err != nil {
		return ap, nil, err
	}
	if !consumed {
		return ap, nil, ErrNotPending
	}

	args := json.RawMessage(ap.Args)
	result, runErr := tool.Run(args)
	status, text := "ok", ""
	if runErr != nil {
		status = "error"
		text = "工具执行失败：" + runErr.Error()
	} else {
		text = Redact(jsonString(result))
	}
	s.appendMessage(ctx, ap.SessionID, "tool", text, nil, ap.CallID)
	emitToolResult(s, ap.SessionID, p.Username, ap.Tool, status, text, errorString(runErr), p.Username, now)
	slog.Info("Harness 审批执行", "tool", ap.Tool, "approval", ap.ID, "actor", p.Username, "status", status)
	return ap, json.RawMessage(text), runErr
}

// ---------- 内部实现 ----------

func (s *Service) session(ctx context.Context, p Principal, id string) (harness.Session, error) {
	sess, err := s.Repo.GetSession(ctx, id)
	if err != nil {
		return harness.Session{}, err
	}
	if sess.Owner != p.Username {
		return harness.Session{}, ErrUnauthorized
	}
	return sess, nil
}

func (s *Service) runLoop(ctx context.Context, p Principal, sess harness.Session, emit func(Event)) error {
	history, err := s.Repo.Messages(ctx, sess.ID, 24)
	if err != nil {
		return err
	}
	llmMessages := make([]ports.LLMMessage, 0, len(history)+1)
	if s.SystemPrompt != "" {
		llmMessages = append(llmMessages, ports.LLMMessage{Role: "system", Content: s.SystemPrompt})
	}
	for _, m := range history {
		llmMessages = append(llmMessages, toLLMMessage(m))
	}
	defs := s.Registry.DefsFor(p.Role)

	for step := 0; step < s.Opts.MaxSteps; step++ {
		resp, err := s.LLM.Chat(ctx, ports.LLMRequest{Messages: llmMessages, Tools: defs})
		if err != nil {
			emit(Event{Type: "error", Data: map[string]any{"message": err.Error()}})
			return err
		}
		if len(resp.ToolCalls) == 0 {
			content := strings.TrimSpace(resp.Content)
			if content == "" {
				content = "（模型未返回内容）"
			}
			s.appendMessage(ctx, sess.ID, "assistant", content, nil, "")
			emit(Event{Type: "message", Data: map[string]any{"role": "assistant", "content": content}})
			emit(Event{Type: "done", Data: map[string]any{"steps": step + 1}})
			return nil
		}

		s.appendMessage(ctx, sess.ID, "assistant", resp.Content, resp.ToolCalls, "")
		emit(Event{Type: "message", Data: map[string]any{
			"role": "assistant", "content": resp.Content, "toolCalls": resp.ToolCalls,
		}})
		llmMessages = append(llmMessages, ports.LLMMessage{
			Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls,
		})

		for _, call := range resp.ToolCalls {
			text, paused, err := s.invoke(ctx, p, sess, call, emit)
			if paused {
				emit(Event{Type: "done", Data: map[string]any{"waitingApproval": true}})
				return nil
			}
			if err != nil && text == "" {
				text = "工具执行失败：" + err.Error()
			}
			s.appendMessage(ctx, sess.ID, "tool", text, nil, call.ID)
			llmMessages = append(llmMessages, ports.LLMMessage{Role: "tool", Content: text, ToolCallID: call.ID})
		}
	}
	emit(Event{Type: "done", Data: map[string]any{"steps": s.Opts.MaxSteps, "truncated": true}})
	return nil
}

func (s *Service) invoke(ctx context.Context, p Principal, sess harness.Session, call ports.LLMToolCall, emit func(Event)) (string, bool, error) {
	rawArgs := json.RawMessage(call.Arguments)
	if len(rawArgs) == 0 {
		rawArgs = json.RawMessage("{}")
	}
	emit(Event{Type: "tool_call", Data: map[string]any{
		"id": call.ID, "tool": call.Name, "args": rawArgs,
	}})
	deny := func(msg string) (string, bool, error) {
		emit(Event{Type: "tool_result", Data: map[string]any{
			"tool": call.Name, "ok": false, "result": json.RawMessage(marshalJSON(msg)),
		}})
		return msg, false, nil
	}

	// 闸门 1：工具必须静态存在
	tool, ok := s.Registry.Get(call.Name)
	if !ok {
		return deny("未知工具：" + call.Name)
	}
	// 闸门 2：参数为合法 JSON 且不超限
	if len(rawArgs) > s.Opts.MaxArgsBytes {
		return deny("参数过大，最多 8KB")
	}
	if !json.Valid(rawArgs) {
		return deny("参数不是合法 JSON")
	}
	// 闸门 3：角色最小权限
	if !identity.Role(p.Role).AtLeast(identity.Role(tool.Spec.MinRole)) {
		return deny("当前角色无权调用该工具")
	}
	// 闸门 4：每会话调用频率
	if !s.allowRate(sess.ID) {
		return deny("调用过于频繁，请稍后再试")
	}

	now := clock.FormatNow()
	hash := harness.ArgsHash(rawArgs)

	// 闸门 5/6/7：写操作必须审批，审批按参数指纹绑定
	if tool.Spec.Risk.NeedsApproval() {
		if ap, found, _ := s.Repo.PendingApproval(ctx, sess.ID, call.Name, hash); found {
			emit(Event{Type: "approval_required", Data: ap})
			return "", true, nil
		}
		expires := clock.Format(time.Now().Add(s.Opts.ApprovalTTL))
		ap := harness.Approval{
			ID:          randomID(),
			SessionID:   sess.ID,
			Tool:        call.Name,
			ArgsHash:    hash,
			Args:        string(rawArgs),
			CallID:      call.ID,
			Risk:        string(tool.Spec.Risk),
			RequestedBy: p.Username,
			Status:      "pending",
			Reason:      approvalReason(tool),
			RequestedAt: now,
			ExpiresAt:   expires,
		}
		if err := s.Repo.CreateApproval(ctx, ap); err != nil {
			return "创建审批失败：" + err.Error(), false, err
		}
		_, _ = s.Repo.RecordToolCall(ctx, harness.ToolCallRecord{
			SessionID: sess.ID, Tool: call.Name, Args: string(rawArgs), ArgsHash: hash,
			Risk: string(tool.Spec.Risk), Status: "pending_approval", Actor: p.Username, CreatedAt: now,
		})
		emit(Event{Type: "approval_required", Data: ap})
		return "", true, nil
	}

	// 只读或低风险：直接执行
	callID, _ := s.Repo.RecordToolCall(ctx, harness.ToolCallRecord{
		SessionID: sess.ID, Tool: call.Name, Args: string(rawArgs), ArgsHash: hash,
		Risk: string(tool.Spec.Risk), Status: "running", Actor: p.Username, CreatedAt: now,
	})
	result, runErr := tool.Run(rawArgs)
	status, text, errText := "ok", "", ""
	if runErr != nil {
		status = "error"
		text = "工具执行失败：" + runErr.Error()
		errText = runErr.Error()
	} else {
		text = Redact(jsonString(result))
	}
	if callID > 0 {
		_ = s.Repo.FinishToolCall(ctx, callID, status, text, errText, "", clock.FormatNow())
	}
	emit(Event{Type: "tool_result", Data: map[string]any{
		"tool": call.Name, "ok": runErr == nil, "result": json.RawMessage(text),
	}})
	if runErr != nil {
		return text, false, runErr
	}
	return text, false, nil
}

func (s *Service) appendMessage(ctx context.Context, sessionID, role, content string, calls []ports.LLMToolCall, toolCallID string) {
	toolCalls := "[]"
	if len(calls) > 0 {
		toolCalls = string(marshalJSON(calls))
	}
	_, err := s.Repo.AppendMessage(ctx, harness.Message{
		SessionID: sessionID, Role: role, Content: content, ToolCalls: toolCalls,
		ToolCallID: toolCallID, CreatedAt: clock.FormatNow(),
	})
	if err != nil {
		slog.Warn("写入 Harness 消息失败", "session", sessionID, "err", err)
	}
	_ = s.Repo.TouchSession(ctx, sessionID, clock.FormatNow())
}

func (s *Service) allowRate(sessionID string) bool {
	if s.Opts.RatePerMinute <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.calls[sessionID][:0]
	for _, ts := range s.calls[sessionID] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= s.Opts.RatePerMinute {
		s.calls[sessionID] = kept
		return false
	}
	s.calls[sessionID] = append(kept, now)
	return true
}

func (s *Service) reauthOK(username, password string) bool {
	if password != "" && s.VerifyPassword != nil && s.VerifyPassword(username, password) {
		s.mu.Lock()
		s.reauth[username] = time.Now()
		s.mu.Unlock()
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.reauth[username]
	return ok && time.Since(ts) <= s.Opts.ReauthWindow
}

func toLLMMessage(m harness.Message) ports.LLMMessage {
	out := ports.LLMMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID}
	if m.ToolCalls != "" && m.ToolCalls != "[]" {
		var calls []ports.LLMToolCall
		if err := json.Unmarshal([]byte(m.ToolCalls), &calls); err == nil {
			out.ToolCalls = calls
		}
	}
	return out
}

func emitToolResult(s *Service, sessionID, actor, tool, status, result, errMsg, approver, at string) {
	id, err := s.Repo.RecordToolCall(context.Background(), harness.ToolCallRecord{
		SessionID: sessionID, Tool: tool, Args: "", ArgsHash: "", Risk: "high", Status: status,
		Actor: actor, Approver: approver, CreatedAt: at,
	})
	if err != nil || id == 0 {
		return
	}
	_ = s.Repo.FinishToolCall(context.Background(), id, status, result, errMsg, approver, at)
}

func approvalReason(tool harness.Tool) string {
	label := "写操作"
	if tool.Spec.Risk == harness.RiskHigh {
		label = "高风险写操作"
	}
	return label + "需要人工审批：" + tool.Spec.Name
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func marshalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return raw
}

func jsonString(v any) string {
	return string(marshalJSON(v))
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
