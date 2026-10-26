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
		MaxSteps:      6,
		RatePerMinute: 20,
		MaxArgsBytes:  64 << 10,
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
	Memory         ports.MemoryRepository
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

// CreateSession 新建会话（默认每次审批）
func (s *Service) CreateSession(ctx context.Context, p Principal, title string) (harness.Session, error) {
	return s.CreateSessionWithMode(ctx, p, title, string(harness.ApprovalEach))
}

// CreateSessionWithMode 按指定审批模式新建会话
func (s *Service) CreateSessionWithMode(ctx context.Context, p Principal, title, mode string) (harness.Session, error) {
	now := clock.FormatNow()
	title = strings.TrimSpace(title)
	if title == "" {
		title = "未命名会话"
	}
	sess := harness.Session{
		ID:           randomID(),
		Owner:        p.Username,
		Role:         p.Role,
		Title:        title,
		ApprovalMode: harness.NormalizeApprovalMode(mode),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.Repo.CreateSession(ctx, sess); err != nil {
		return harness.Session{}, err
	}
	return sess, nil
}

// SetApprovalMode 切换会话审批模式
func (s *Service) SetApprovalMode(ctx context.Context, p Principal, sessionID, mode string) (harness.Session, error) {
	sess, err := s.session(ctx, p, sessionID)
	if err != nil {
		return harness.Session{}, err
	}
	normalized := harness.NormalizeApprovalMode(mode)
	now := clock.FormatNow()
	if err := s.Repo.UpdateSessionApprovalMode(ctx, sessionID, normalized, now); err != nil {
		return harness.Session{}, err
	}
	sess.ApprovalMode = normalized
	sess.UpdatedAt = now
	slog.Info("Harness 审批模式切换", "session", sessionID, "mode", normalized, "actor", p.Username)
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

// PendingApprovals 返回会话下仍在有效期内的待审批记录，供刷新页面后恢复审批卡
func (s *Service) PendingApprovals(ctx context.Context, p Principal, sessionID string) ([]harness.Approval, error) {
	if _, err := s.session(ctx, p, sessionID); err != nil {
		return nil, err
	}
	return s.Repo.PendingApprovals(ctx, sessionID, clock.FormatNow())
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
	return s.ChatWithSkill(ctx, p, sessionID, text, "", "", emit)
}

// ChatWithSkill 在指定技能上下文下处理用户消息；skillContext 为空表示通用模式。
func (s *Service) ChatWithSkill(ctx context.Context, p Principal, sessionID, text, skillID, skillContext string, emit func(Event)) error {
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
	// 存在待审批时禁止继续发消息：否则历史里会留下没有工具结果的 tool_call
	if pending, err := s.Repo.HasPendingApproval(ctx, sess.ID, clock.FormatNow()); err != nil {
		return err
	} else if pending {
		return ErrBusy
	}
	s.ensureSkillMarker(ctx, sess.ID, strings.TrimSpace(skillID), skillContext)
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

// ensureSkillMarker 在技能切换时写入一条系统消息，避免重复注入。
func (s *Service) ensureSkillMarker(ctx context.Context, sessionID, skillID, skillContext string) {
	history, err := s.Repo.Messages(ctx, sessionID, 50)
	if err != nil {
		return
	}
	current := lastSkillMarker(history)
	switch {
	case skillContext != "" && current != skillID:
		s.appendMessage(ctx, sessionID, "system", skillContext, nil, "")
	case skillContext == "" && current != "":
		s.appendMessage(ctx, sessionID, "system", "[skill] 已退出技能模式，恢复通用助手。", nil, "")
	}
}

// lastSkillMarker 返回最近一条技能系统消息中的技能 ID，无则返回空。
func lastSkillMarker(history []harness.Message) string {
	for i := len(history) - 1; i >= 0; i-- {
		message := history[i]
		if message.Role != "system" || !strings.HasPrefix(message.Content, "[skill]") {
			continue
		}
		for _, line := range strings.Split(message.Content, "\n") {
			if strings.HasPrefix(line, "[skill] id=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "[skill] id="))
			}
		}
		return ""
	}
	return ""
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
		s.emitApprovalResult(ap, p.Username, "rejected", text, "", now)
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
	s.emitApprovalResult(ap, p.Username, status, text, errorString(runErr), now)
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
	history, err := s.Repo.Messages(ctx, sess.ID, 60)
	if err != nil {
		return err
	}
	llmMessages := s.buildContext(ctx, history)
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

// buildContext 组装上下文：系统提示 + 长期记忆 + 早期消息摘要 + 最近消息，并做字符预算裁剪。
func (s *Service) buildContext(ctx context.Context, history []harness.Message) []ports.LLMMessage {
	const keepRecent = 20
	const budgetChars = 48 << 10

	out := make([]ports.LLMMessage, 0, len(history)+3)
	if s.SystemPrompt != "" {
		out = append(out, ports.LLMMessage{Role: "system", Content: s.SystemPrompt})
	}
	if s.Memory != nil {
		if memories, err := s.Memory.Search(ctx, "global", "", "", 5); err == nil && len(memories) > 0 {
			var b strings.Builder
			b.WriteString("长期记忆（供参考，注意时效）：\n")
			for _, m := range memories {
				fmt.Fprintf(&b, "- [%s] %s\n", m.UpdatedAt, m.Content)
			}
			out = append(out, ports.LLMMessage{Role: "system", Content: b.String()})
		}
	}
	if len(history) > keepRecent {
		older := history[:len(history)-keepRecent]
		var b strings.Builder
		b.WriteString("较早对话的压缩摘要（按时间顺序，已截断）：\n")
		for _, m := range older {
			text := strings.TrimSpace(m.Content)
			if text == "" && len(m.ToolCalls) > 0 {
				text = "[工具调用]"
			}
			if len(text) > 240 {
				text = text[:240] + "…"
			}
			if text == "" {
				continue
			}
			fmt.Fprintf(&b, "%s: %s\n", m.Role, text)
		}
		out = append(out, ports.LLMMessage{Role: "system", Content: b.String()})
		history = history[len(history)-keepRecent:]
	}
	for _, m := range history {
		out = append(out, toLLMMessage(m))
	}
	return trimContext(out, budgetChars)
}

// trimContext 保留系统消息，并按总字符预算从最新消息向前保留。
func trimContext(messages []ports.LLMMessage, budget int) []ports.LLMMessage {
	total := 0
	for _, m := range messages {
		total += len(m.Content) + 64
	}
	if total <= budget {
		return messages
	}
	systems := make([]ports.LLMMessage, 0, 2)
	rest := make([]ports.LLMMessage, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			systems = append(systems, m)
		} else {
			rest = append(rest, m)
		}
	}
	used := 0
	for _, m := range systems {
		used += len(m.Content) + 64
	}
	cut := len(rest)
	for cut > 0 {
		next := rest[cut-1]
		cost := len(next.Content) + 64
		if used+cost > budget {
			break
		}
		used += cost
		cut--
	}
	out := append(append([]ports.LLMMessage{}, systems...), rest[cut:]...)
	if len(out) == len(systems) {
		out = append(out, ports.LLMMessage{Role: "system", Content: "（上下文过长，早期对话已省略，请结合长期记忆与工具结果回答）"})
	}
	return out
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
		return deny(fmt.Sprintf("参数过大，最多 %dKB", s.Opts.MaxArgsBytes/1024))
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

	// 闸门 5：按会话审批模式决定写操作是否放行
	auto := false
	autoNote := ""
	if tool.Spec.Risk.NeedsApproval() {
		auto, autoNote = s.autoDecision(ctx, sess, tool, rawArgs)
	}

	// 闸门 6/7：需要人工时创建审批，审批按参数指纹绑定
	if tool.Spec.Risk.NeedsApproval() && !auto {
		if ap, found, _ := s.Repo.PendingApproval(ctx, sess.ID, call.Name, hash); found {
			emit(Event{Type: "approval_required", Data: ap})
			return "", true, nil
		}
		expires := clock.Format(time.Now().Add(s.Opts.ApprovalTTL))
		reason := approvalReason(tool)
		if autoNote != "" {
			reason = autoNote + "；" + reason
		}
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
			Reason:      reason,
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

	// 执行：只读、或按会话模式自动放行；自动放行在工具调用记录中标注 approver
	approver := ""
	if auto {
		approver = "auto:" + string(sess.ApprovalMode)
	}
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
		_ = s.Repo.FinishToolCall(ctx, callID, status, text, errText, approver, clock.FormatNow())
	}
	emit(Event{Type: "tool_result", Data: map[string]any{
		"tool": call.Name, "ok": runErr == nil, "result": json.RawMessage(text),
	}})
	if runErr != nil {
		return text, false, runErr
	}
	return text, false, nil
}

// smartJudgePrompt 智能模式下的自动放行判定提示
const smartJudgePrompt = `你是 VulnAgent 的主机操作审批判定器。根据工具与参数，判断是否可以自动执行（无需人工点击确认）。
仅在以下条件同时满足时放行：
1) 操作范围明确限定在单个资产、单个文件或单条记录；
2) 只读、可回滚或影响可忽略；
3) 与用户当前诉求直接相关，参数完整无歧义；
4) 不会中断服务，不会覆盖或删除关键配置，不会批量变更。
必须拒绝并转人工：停止或禁用服务、删除或覆盖关键文件、回滚快照、批量或跨资产操作、生产核心组件升级、参数含糊或可能误伤。
只输出 JSON，不要输出其他内容，例如 {"approve":true,"reason":"单文件只读，可自动执行"}。`

// autoDecision 按会话审批模式判断是否跳过人工审批
func (s *Service) autoDecision(ctx context.Context, sess harness.Session, tool harness.Tool, args json.RawMessage) (bool, string) {
	switch sess.ApprovalMode {
	case harness.ApprovalFull:
		return true, ""
	case harness.ApprovalSmart:
		return s.aiJudge(ctx, tool, args)
	default:
		return false, ""
	}
}

// aiJudge 由模型判断该次写操作能否自动执行；失败一律转人工
func (s *Service) aiJudge(ctx context.Context, tool harness.Tool, args json.RawMessage) (bool, string) {
	if s.LLM == nil {
		return false, "AI 判断不可用，转人工审批"
	}
	resp, err := s.LLM.Chat(ctx, ports.LLMRequest{Messages: []ports.LLMMessage{
		{Role: "system", Content: smartJudgePrompt},
		{Role: "user", Content: fmt.Sprintf("工具：%s\n风险：%s\n说明：%s\n参数：%s",
			tool.Spec.Name, tool.Spec.Risk, tool.Spec.Description, string(args))},
	}})
	if err != nil {
		slog.Warn("AI 审批判断失败", "tool", tool.Spec.Name, "err", err)
		return false, "AI 判断失败，转人工审批"
	}
	approve, reason := parseJudge(resp.Content)
	if reason == "" {
		if approve {
			reason = "AI 判断可自动执行"
		} else {
			reason = "AI 判断需人工确认"
		}
	}
	slog.Info("AI 审批判断", "tool", tool.Spec.Name, "approve", approve, "reason", reason)
	return approve, reason
}

// parseJudge 解析判定结果，解析失败按拒绝处理
func parseJudge(content string) (bool, string) {
	text := strings.TrimSpace(content)
	text = strings.Trim(text, "`")
	if i := strings.Index(text, "{"); i >= 0 {
		if j := strings.LastIndex(text, "}"); j > i {
			text = text[i : j+1]
		}
	}
	var v struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return false, "AI 判断结果无法解析，转人工审批"
	}
	return v.Approve, strings.TrimSpace(v.Reason)
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

// emitApprovalResult 记录审批执行结果，保留原参数与指纹便于回放
func (s *Service) emitApprovalResult(ap harness.Approval, actor, status, result, errMsg, at string) {
	id, err := s.Repo.RecordToolCall(context.Background(), harness.ToolCallRecord{
		SessionID: ap.SessionID, Tool: ap.Tool, Args: ap.Args, ArgsHash: ap.ArgsHash,
		Risk: ap.Risk, Status: status, Actor: actor, Approver: actor, CreatedAt: at,
	})
	if err != nil || id == 0 {
		return
	}
	_ = s.Repo.FinishToolCall(context.Background(), id, status, result, errMsg, actor, at)
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
