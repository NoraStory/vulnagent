package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	harnessapp "vulnagent/server/internal/application/harness"
	"vulnagent/server/internal/domain/harness"
)

// harnessSystemPrompt 系统提示：约束模型只通过工具取数、不臆造结论。
func harnessSystemPrompt() string {
	return `你是 VulnAgent 的安全运营助手，服务于企业漏洞运维控制面。

工作规则：
1. 只能通过已注册工具获取数据，不要臆造 CVE、资产、漏洞或统计数字。
2. 回答必须引用真实 ID（如 CVE-2024-3094、finding 123、asset 7），并说明数据来源（工具名）。
3. 涉及写操作（复扫、改状态、建工单、改映射、自检）时，先解释影响，再调用工具；系统会要求人工审批，不要假设审批已通过。
4. 不要输出任何口令、令牌、密钥；不要尝试读取系统文件或执行命令。
5. 涉及主机性能、硬件、服务或端口时，先用 host_metrics / host_hardware 读取 Agent 上报的遥测；若未上报或 sampledAt 过旧，必须明确说明数据缺失或已过期，不要用存活心跳推断性能。
6. 用简体中文、结构化短段落回答，先给结论，再给依据与建议。`
}

func principalOf(u *User) harnessapp.Principal {
	return harnessapp.Principal{Username: u.Username, Role: u.Role}
}

// requireHarness 未配置模型时返回可读提示
func (a *App) requireHarness(w http.ResponseWriter) bool {
	if a.harness == nil || !a.harness.Available() {
		writeErr(w, http.StatusServiceUnavailable, "harness_disabled",
			"Agent 助手未启用：请配置 VA_LLM_BASE_URL、VA_LLM_API_KEY、VA_LLM_MODEL 后重启服务")
		return false
	}
	return true
}

// handleHarnessTools 返回当前角色可见的工具与模型信息
func (a *App) handleHarnessTools(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	enabled := a.harness != nil && a.harness.Available()
	resp := map[string]any{
		"enabled": enabled,
		"model":   "",
		"tools":   []harness.ToolSpec{},
	}
	if enabled {
		resp["model"] = a.harness.Model()
		resp["tools"] = a.harness.Tools(u.Role)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHarnessSessions 列出当前账号的会话
func (a *App) handleHarnessSessions(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	sessions, err := a.harness.ListSessions(r.Context(), principalOf(u))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取会话失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// handleHarnessCreateSession 新建会话
func (a *App) handleHarnessCreateSession(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	var req struct {
		Title string `json:"title"`
	}
	_ = readJSON(r, &req)
	sess, err := a.harness.CreateSession(r.Context(), principalOf(u), req.Title)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建会话失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"session": sess})
}

// handleHarnessMessages 读取会话消息
func (a *App) handleHarnessMessages(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	id := r.PathValue("id")
	sess, err := a.harness.Session(r.Context(), principalOf(u), id)
	if err != nil {
		writeHarnessErr(w, err)
		return
	}
	msgs, err := a.harness.Messages(r.Context(), principalOf(u), id)
	if err != nil {
		writeHarnessErr(w, err)
		return
	}
	approvals, err := a.harness.PendingApprovals(r.Context(), principalOf(u), id)
	if err != nil {
		approvals = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session": sess, "messages": msgs, "pendingApprovals": approvals,
	})
}

// handleHarnessChat 发送消息并流式返回事件
func (a *App) handleHarnessChat(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "消息不能为空")
		return
	}
	id := r.PathValue("id")
	if _, err := a.harness.Session(r.Context(), principalOf(u), id); err != nil {
		writeHarnessErr(w, err)
		return
	}

	stream := newSSEStream(w)
	err := a.harness.Chat(r.Context(), principalOf(u), id, req.Content, stream.emit)
	if err != nil {
		stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": err.Error()}})
	}
	stream.close()
}

// handleHarnessResume 在审批处理后继续对话
func (a *App) handleHarnessResume(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	id := r.PathValue("id")
	if _, err := a.harness.Session(r.Context(), principalOf(u), id); err != nil {
		writeHarnessErr(w, err)
		return
	}
	stream := newSSEStream(w)
	err := a.harness.Resume(r.Context(), principalOf(u), id, stream.emit)
	if err != nil {
		stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": err.Error()}})
	}
	stream.close()
}

// handleHarnessDecision 处理审批：approve 立即执行工具，reject 仅记录
func (a *App) handleHarnessDecision(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	if !a.requireHarness(w) {
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if req.Decision != "approve" && req.Decision != "reject" {
		writeErr(w, http.StatusBadRequest, "bad_request", "decision 必须为 approve 或 reject")
		return
	}
	ap, result, err := a.harness.Decide(r.Context(), principalOf(u), r.PathValue("id"), req.Decision, req.Password)
	if err != nil {
		writeHarnessErr(w, err)
		return
	}
	a.audit(r, "agent.approval."+req.Decision, ap.Tool, "审批 "+ap.ID+"，参数指纹 "+ap.ArgsHash[:12])
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approval": ap, "result": result})
}

func writeHarnessErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, harnessapp.ErrUnauthorized):
		writeErr(w, http.StatusForbidden, "forbidden", "无权访问该会话")
	case errors.Is(err, harnessapp.ErrReauth):
		writeErr(w, http.StatusUnauthorized, "reauth_required", "高风险操作需要输入当前账号口令再认证")
	case errors.Is(err, harnessapp.ErrNotPending):
		writeErr(w, http.StatusConflict, "approval_expired", "审批已失效、已处理或已过期")
	case errors.Is(err, harnessapp.ErrBusy):
		writeErr(w, http.StatusConflict, "approval_pending", "存在待审批操作，请先处理")
	default:
		writeErr(w, http.StatusNotFound, "not_found", "记录不存在或已失效")
	}
}

// sseStream 极简 SSE 输出：每条事件一行 data:
type sseStream struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSEStream(w http.ResponseWriter) *sseStream {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	return &sseStream{w: w, f: f}
}

func (s *sseStream) emit(ev harnessapp.Event) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Fprintf(s.w, "data: %s\n\n", raw)
	if s.f != nil {
		s.f.Flush()
	}
}

func (s *sseStream) close() {
	fmt.Fprint(s.w, "event: close\ndata: {}\n\n")
	if s.f != nil {
		s.f.Flush()
	}
}

// verifyPassword 用于高风险操作的再认证
func (a *App) verifyPassword(username, password string) bool {
	acc, err := a.identityRepo().FindAccount(context.Background(), username)
	if err != nil || acc.Disabled {
		return false
	}
	return bcryptCompare(acc.PwdHash, password)
}
