package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	harnessapp "vulnagent/server/internal/application/harness"
	"vulnagent/server/internal/application/ports"
)

// ---------- 数据结构 ----------

type sshAgentRequest struct {
	HostID int64  `json:"hostId"`
	Goal   string `json:"goal"`
	Mode   string `json:"mode"` // confirm | safe | auto
}

type sshAgentDecision struct {
	Thought string `json:"thought"`
	Command string `json:"command"`
	Done    bool   `json:"done"`
	Summary string `json:"summary"`
}

type sshAgentStep struct {
	Index    int
	Thought  string
	Command  string
	Output   string
	Risk     string
	Approved string
	ExitCode int
}

const (
	sshAgentMaxSteps    = 8
	sshAgentTimeout     = 90 * time.Second
	sshAgentOutputCap   = 16 << 10
	sshAgentApprovalTTL = 5 * time.Minute
)

const sshAgentSystemPrompt = `你是 VulnAgent 的 SSH 智能体，直接操作目标 Linux 主机完成用户目标。
每次只输出一个 JSON 对象，不要输出 Markdown、解释或多余文字：
{"thought":"一句话判断","command":"要执行的单条 shell 命令","done":false,"summary":""}

规则：
1. 先只读侦察（如 hostname、df -h、free -m、ps、systemctl status），确认后再做变更。
2. 命令必须单行、非交互、可自动结束；禁止 vim、top、less、交互式登录等命令。
3. 命令必须包含必要的非交互参数，例如 apt-get -y、systemctl --no-pager。
4. 删除、覆盖、重启、停止服务、批量变更等危险操作会被人工确认，不要试图绕过。
5. 输出不足以判断时继续执行下一条命令；目标完成时返回 {"thought":"...","command":"","done":true,"summary":"结论"}。
6. 不要输出密码、密钥、令牌；不要执行与目标无关的操作。
7. 最多执行有限步数，优先用最少命令完成任务。
8. 不熟悉的命令或参数必须先在目标机验证（command -v、--help），禁止臆造参数；若提供了命令参考资料，优先采用其中的写法。`

var (
	sshCriticalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/(\s|$)`),
		regexp.MustCompile(`(?i)\bmkfs(\.[a-z0-9]+)?\b`),
		regexp.MustCompile(`(?i)\bdd\b[^\n]*\bof=/dev/`),
		regexp.MustCompile(`(?i)\b(shutdown|reboot|poweroff|halt)\b`),
		regexp.MustCompile(`(?i)\bwipefs\b|\bfdisk\b|\bparted\b`),
	}
	sshHighPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\brm\s+-[a-z]*r`),
		regexp.MustCompile(`(?i)\bsystemctl\s+(stop|disable|mask|restart)\b`),
		regexp.MustCompile(`(?i)\biptables\s+-F\b|\bnft\s+flush\b`),
		regexp.MustCompile(`(?i)\b(userdel|groupdel|passwd)\b`),
		regexp.MustCompile(`(?i)\bkill\s+-9\b`),
		regexp.MustCompile(`(?i)\bdocker\s+(rm|rmi|stop|kill)\b|\bkubectl\s+delete\b`),
		regexp.MustCompile(`(?i)\btruncate\s+-s\s+0\b|\bshred\b|\bcrontab\s+-r\b`),
		regexp.MustCompile(`(?i)>\s*/etc/|\bmv\s+/etc/|\bchmod\s+-R\s+777\b|\bchown\s+-R\b`),
	}
)

// classifySSHCommand 判断命令风险，critical 始终需要人工确认
func classifySSHCommand(command string) string {
	for _, pattern := range sshCriticalPatterns {
		if pattern.MatchString(command) {
			return "critical"
		}
	}
	for _, pattern := range sshHighPatterns {
		if pattern.MatchString(command) {
			return "high"
		}
	}
	return "normal"
}

// ---------- HTTP：Agent 运行 ----------

func (a *App) handleSSHAgentRun(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	if a.harness == nil || a.harness.LLM == nil {
		writeErr(w, http.StatusServiceUnavailable, "llm_unavailable", "未配置模型凭据，Agent 模式不可用")
		return
	}
	var req sshAgentRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	goal := strings.TrimSpace(req.Goal)
	if goal == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "目标不能为空")
		return
	}
	goal = truncateRunes(goal, 1000)
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "confirm" && mode != "safe" && mode != "auto" {
		mode = "safe"
	}
	host, err := a.getSSHHost(r.Context(), req.HostID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}

	refCtx, cancelRef := context.WithTimeout(r.Context(), 10*time.Second)
	references, refErr := a.commandReferences(refCtx, goal)
	cancelRef()
	referenceBlock := commandReferencePrompt(references)

	stream := newSSEStream(w)
	defer stream.close()

	runID := newSSHRunID()
	startedAt := fmtT(nowT())
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO ssh_agent_runs
		(id, host_id, host_name, actor, role, goal, mode, status, steps, summary, error, started_at, finished_at)
		VALUES(?,?,?,?,?,?,?,?,0,'','',?,'')`,
		runID, host.ID, host.Name, u.Username, u.Role, goal, mode, "running", startedAt); err != nil {
		stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": "创建 Agent 运行失败"}})
		return
	}

	status, summary, errText := "failed", "", ""
	stepsDone := 0
	defer func() {
		if status == "running" {
			status = "failed"
			if errText == "" {
				errText = "运行中断"
			}
		}
		if _, err := a.db.Exec(`UPDATE ssh_agent_runs SET status=?, steps=?, summary=?, error=?, finished_at=? WHERE id=?`,
			status, stepsDone, summary, errText, fmtT(nowT()), runID); err != nil {
			slog.Warn("更新 Agent 运行失败", "run", runID, "err", err)
		}
		a.audit(r, "ssh.agent.done", host.Name,
			fmt.Sprintf("运行 %s，状态 %s，步骤 %d：%s", runID, status, stepsDone, truncateRunes(goal, 80)))
	}()

	a.audit(r, "ssh.agent.run", host.Name,
		fmt.Sprintf("%s（参考 %d 条）", truncateRunes(goal, 100), len(references)))
	slog.Info("SSH Agent 启动", "run", runID, "host", host.Name, "mode", mode, "goal", truncateRunes(goal, 80))
	stream.emit(harnessapp.Event{Type: "status", Data: map[string]any{
		"runId": runID, "mode": mode, "maxSteps": sshAgentMaxSteps, "host": host.Name,
		"references": referenceMeta(references), "referenceError": refErr,
	}})

	ctx := r.Context()
	client, fingerprint, err := a.dialSSHHost(ctx, host)
	if err != nil {
		errText = err.Error()
		stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": err.Error()}})
		return
	}
	defer client.Close()
	if host.HostKey == "" {
		if _, err := a.db.ExecContext(ctx, `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			fingerprint, fmtT(nowT()), host.ID); err != nil {
			slog.Warn("保存 SSH 主机指纹失败", "host", host.Name, "err", err)
		}
	}

	history := make([]sshAgentStep, 0, sshAgentMaxSteps)
	for index := 0; index < sshAgentMaxSteps; index++ {
		if ctx.Err() != nil {
			errText = "请求已取消"
			return
		}
		remaining := sshAgentMaxSteps - index
		decision, err := a.askSSHAgent(ctx, host, goal, referenceBlock, history, remaining)
		if err != nil {
			errText = "模型调用失败：" + err.Error()
			stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": errText}})
			return
		}
		if decision.Done {
			status = "completed"
			summary = strings.TrimSpace(decision.Summary)
			if summary == "" {
				summary = "目标已完成"
			}
			stream.emit(harnessapp.Event{Type: "done", Data: map[string]any{
				"runId": runID, "steps": stepsDone, "summary": summary, "truncated": false,
			}})
			return
		}
		command := sanitizeAgentCommand(decision.Command)
		if command == "" {
			errText = "模型未给出可执行命令"
			stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": errText}})
			return
		}
		risk := classifySSHCommand(command)
		needApproval := mode == "confirm" || (mode == "safe" && risk != "normal") || risk == "critical"
		approved := "auto"
		slog.Info("SSH Agent 步骤", "run", runID, "index", index, "command", truncateRunes(command, 120), "risk", risk, "approval", needApproval)
		stream.emit(harnessapp.Event{Type: "step", Data: map[string]any{
			"index": index, "thought": truncateRunes(decision.Thought, 200), "command": command,
			"risk": risk, "approval": map[bool]string{true: "pending", false: "not_required"}[needApproval],
		}})
		if needApproval {
			approvalID := newSSHRunID()
			a.registerSSHApproval(approvalID)
			stream.emit(harnessapp.Event{Type: "await_approval", Data: map[string]any{
				"approvalId": approvalID, "index": index, "command": command, "risk": risk,
				"reason": sshRiskReason(risk),
			}})
			decisionOK, resolved := a.waitSSHApproval(ctx, approvalID, sshAgentApprovalTTL)
			a.unregisterSSHApproval(approvalID)
			if !resolved {
				if ctx.Err() != nil {
					errText = "连接已断开，运行终止"
				} else {
					errText = "审批等待超时"
				}
				stream.emit(harnessapp.Event{Type: "error", Data: map[string]any{"message": errText}})
				return
			}
			if !decisionOK {
				approved = "rejected"
				stream.emit(harnessapp.Event{Type: "approval_result", Data: map[string]any{"index": index, "approved": false}})
				a.recordSSHAgentStep(runID, index, decision.Thought, command, "用户拒绝执行", risk, "rejected", -1)
				history = append(history, sshAgentStep{
					Index: index, Thought: decision.Thought, Command: command,
					Output: "用户拒绝执行该命令", Risk: risk, Approved: "rejected",
				})
				stepsDone++
				continue
			}
			approved = "user"
			stream.emit(harnessapp.Event{Type: "approval_result", Data: map[string]any{"index": index, "approved": true}})
		}

		output, exitCode, runErr := runSSHCommand(ctx, client, command, sshAgentTimeout)
		if runErr != nil && output == "" {
			output = "执行失败：" + runErr.Error()
		}
		stream.emit(harnessapp.Event{Type: "output", Data: map[string]any{
			"index": index, "output": output, "exitCode": exitCode,
		}})
		a.recordSSHAgentStep(runID, index, decision.Thought, command, truncateRunes(output, 4000), risk, approved, exitCode)
		if _, err := a.db.Exec(`INSERT INTO ssh_events(session_id, kind, data, created_at) VALUES(?,?,?,?)`,
			"agent:"+runID, "agent", truncateRunes(command+" → exit="+strconv.Itoa(exitCode), 500), fmtT(nowT())); err != nil {
			slog.Warn("记录 Agent 命令失败", "run", runID, "err", err)
		}
		history = append(history, sshAgentStep{
			Index: index, Thought: decision.Thought, Command: command,
			Output: output, Risk: risk, Approved: approved, ExitCode: exitCode,
		})
		stepsDone++
	}

	status = "completed"
	summary = a.summarizeSSHAgent(ctx, host, goal, history)
	if summary == "" {
		summary = "已达到最大步数，请补充目标后继续"
	}
	stream.emit(harnessapp.Event{Type: "done", Data: map[string]any{
		"runId": runID, "steps": stepsDone, "summary": summary, "truncated": true,
	}})
}

// summarizeSSHAgent 在达到步数上限时，基于已有观察生成收尾结论
func (a *App) summarizeSSHAgent(ctx context.Context, host sshHost, goal string, history []sshAgentStep) string {
	if len(history) == 0 {
		return ""
	}
	var user strings.Builder
	user.WriteString("目标主机：")
	user.WriteString(host.Name)
	user.WriteString("（")
	user.WriteString(host.addr())
	user.WriteString("）\n目标：")
	user.WriteString(goal)
	user.WriteString("\n已执行的命令与输出：\n")
	start := 0
	if len(history) > 8 {
		start = len(history) - 8
	}
	for _, step := range history[start:] {
		user.WriteString(fmt.Sprintf("- 命令：%s\n  输出：%s\n", step.Command, truncateRunes(step.Output, 1200)))
	}
	user.WriteString("\n请基于以上观察给出最终结论与建议（中文，300 字以内），不要再要求执行命令。")

	resp, err := a.harness.LLM.Chat(ctx, ports.LLMRequest{Messages: []ports.LLMMessage{
		{Role: "system", Content: "你是资深 SRE，请根据已收集的主机信息给出简洁、可执行的结论。"},
		{Role: "user", Content: user.String()},
	}})
	if err != nil {
		slog.Warn("SSH Agent 收尾总结失败", "host", host.Name, "err", err)
		return ""
	}
	return strings.TrimSpace(resp.Content)
}
func sshRiskReason(risk string) string {
	switch risk {
	case "critical":
		return "该命令可能破坏系统或中断服务，需要你确认"
	case "high":
		return "该命令涉及删除、停止服务或系统变更，需要你确认"
	default:
		return "按当前模式需要确认"
	}
}

func (a *App) askSSHAgent(ctx context.Context, host sshHost, goal, reference string, history []sshAgentStep, remaining int) (sshAgentDecision, error) {
	var user strings.Builder
	user.WriteString("目标主机：")
	user.WriteString(host.Name)
	user.WriteString("（")
	user.WriteString(host.Username)
	user.WriteString("@")
	user.WriteString(host.addr())
	user.WriteString("）\n目标：")
	user.WriteString(goal)
	if reference != "" {
		user.WriteString("\n")
		user.WriteString(reference)
	}
	user.WriteString("\n剩余可执行步数：")
	user.WriteString(strconv.Itoa(remaining))
	user.WriteString("\n")

	start := 0
	if len(history) > 6 {
		start = len(history) - 6
	}
	if len(history) == 0 {
		user.WriteString("尚未执行任何命令。\n")
	} else {
		user.WriteString("已执行步骤：\n")
		for _, step := range history[start:] {
			user.WriteString(fmt.Sprintf("步骤 %d\n命令：%s\n结果：%s\n",
				step.Index+1, step.Command, truncateRunes(step.Output, 1500)))
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	resp, err := a.harness.LLM.Chat(callCtx, ports.LLMRequest{Messages: []ports.LLMMessage{
		{Role: "system", Content: sshAgentSystemPrompt},
		{Role: "user", Content: user.String()},
	}})
	if err != nil {
		return sshAgentDecision{}, err
	}
	decision, err := parseSSHAgentDecision(resp.Content)
	if err != nil {
		return sshAgentDecision{}, err
	}
	return decision, nil
}

// parseSSHAgentDecision 从模型输出中提取 JSON 决策
func parseSSHAgentDecision(content string) (sshAgentDecision, error) {
	text := strings.TrimSpace(content)
	text = strings.Trim(text, "`")
	if start := strings.Index(text, "{"); start >= 0 {
		if end := strings.LastIndex(text, "}"); end > start {
			text = text[start : end+1]
		}
	}
	var decision sshAgentDecision
	if err := json.Unmarshal([]byte(text), &decision); err != nil {
		return sshAgentDecision{}, errors.New("模型返回不是合法 JSON 决策")
	}
	return decision, nil
}

// sanitizeAgentCommand 清理模型给出的命令：去围栏、去提示符、压缩为单行
func sanitizeAgentCommand(command string) string {
	command = strings.TrimSpace(command)
	command = strings.Trim(command, "`")
	command = strings.TrimPrefix(command, "$ ")
	lines := strings.Split(command, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	command = strings.Join(cleaned, " && ")
	if len(command) > 500 {
		command = command[:500]
	}
	return command
}

// runSSHCommand 在独立 SSH 会话中执行命令，带超时与输出截断
func runSSHCommand(ctx context.Context, client *ssh.Client, command string, timeout time.Duration) (string, int, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer session.Close()

	type execResult struct {
		out []byte
		err error
	}
	done := make(chan execResult, 1)
	go func() {
		out, err := session.CombinedOutput(command)
		done <- execResult{out: out, err: err}
	}()

	select {
	case result := <-done:
		code := 0
		if result.err != nil {
			if exitErr, ok := result.err.(*ssh.ExitError); ok {
				code = exitErr.ExitStatus()
			} else {
				code = -1
			}
		}
		return truncateOutput(string(result.out), sshAgentOutputCap), code, result.err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return "命令执行超时", -1, fmt.Errorf("命令执行超时（%s）", timeout)
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return "请求已取消", -1, ctx.Err()
	}
}

func truncateOutput(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n…（输出已截断）"
}

func (a *App) recordSSHAgentStep(runID string, index int, thought, command, output, risk, approved string, exitCode int) {
	if _, err := a.db.Exec(`INSERT INTO ssh_agent_steps
		(run_id, idx, thought, command, output, risk, approved, exit_code, created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		runID, index, truncateRunes(thought, 300), command, output, risk, approved, exitCode, fmtT(nowT())); err != nil {
		slog.Warn("写入 Agent 步骤失败", "run", runID, "err", err)
	}
}

func newSSHRunID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// ---------- 审批 ----------

func (a *App) registerSSHApproval(id string) {
	a.sshApprovalMu.Lock()
	defer a.sshApprovalMu.Unlock()
	if a.sshApprovals == nil {
		a.sshApprovals = make(map[string]chan bool)
	}
	a.sshApprovals[id] = make(chan bool, 1)
}

func (a *App) unregisterSSHApproval(id string) {
	a.sshApprovalMu.Lock()
	delete(a.sshApprovals, id)
	a.sshApprovalMu.Unlock()
}

func (a *App) waitSSHApproval(ctx context.Context, id string, timeout time.Duration) (bool, bool) {
	a.sshApprovalMu.Lock()
	ch := a.sshApprovals[id]
	a.sshApprovalMu.Unlock()
	if ch == nil {
		return false, false
	}
	select {
	case approved := <-ch:
		return approved, true
	case <-time.After(timeout):
		return false, false
	case <-ctx.Done():
		return false, false
	}
}

func (a *App) resolveSSHApproval(id string, approved bool) bool {
	a.sshApprovalMu.Lock()
	defer a.sshApprovalMu.Unlock()
	ch, ok := a.sshApprovals[id]
	if !ok {
		return false
	}
	select {
	case ch <- approved:
	default:
	}
	return true
}

func (a *App) handleSSHAgentApproval(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	var req struct {
		Decision string `json:"decision"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if req.Decision != "approve" && req.Decision != "reject" {
		writeErr(w, http.StatusBadRequest, "bad_request", "decision 必须为 approve 或 reject")
		return
	}
	id := r.PathValue("id")
	if !a.resolveSSHApproval(id, req.Decision == "approve") {
		writeErr(w, http.StatusNotFound, "not_found", "审批不存在或已失效")
		return
	}
	a.audit(r, "ssh.agent."+req.Decision, id, "SSH Agent 命令审批")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 运行记录 ----------

func (a *App) handleSSHAgentRuns(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	limit := clampInt(queryInt(r, "limit", 20), 1, 100)
	hostID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("hostId")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			hostID = parsed
		}
	}
	query := `SELECT id, host_id, host_name, actor, role, goal, mode, status, steps, summary, error, started_at, finished_at
		FROM ssh_agent_runs`
	args := []any{}
	if hostID > 0 {
		query += ` WHERE host_id = ?`
		args = append(args, hostID)
	}
	query += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := a.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Agent 运行失败")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var (
			id, hostName, actor, role, goal, mode, status, summary, errText, startedAt, endedAt string
			hostIDValue                                                                         int64
			steps                                                                               int
		)
		if err := rows.Scan(&id, &hostIDValue, &hostName, &actor, &role, &goal, &mode, &status, &steps,
			&summary, &errText, &startedAt, &endedAt); err != nil {
			continue
		}
		items = append(items, map[string]any{
			"id": id, "hostId": hostIDValue, "hostName": hostName, "actor": actor, "role": role,
			"goal": goal, "mode": mode, "status": status, "steps": steps,
			"summary": summary, "error": errText, "startedAt": startedAt, "endedAt": endedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleSSHAgentRunDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	runID := r.PathValue("id")
	var (
		id, hostName, actor, role, goal, mode, status, summary, errText, startedAt, endedAt string
		hostID                                                                              int64
		steps                                                                               int
	)
	err := a.db.QueryRowContext(r.Context(), `SELECT id, host_id, host_name, actor, role, goal, mode, status, steps,
		summary, error, started_at, finished_at FROM ssh_agent_runs WHERE id = ?`, runID).
		Scan(&id, &hostID, &hostName, &actor, &role, &goal, &mode, &status, &steps, &summary, &errText, &startedAt, &endedAt)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "运行记录不存在")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT idx, thought, command, output, risk, approved, exit_code, created_at
		FROM ssh_agent_steps WHERE run_id = ? ORDER BY idx ASC`, runID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取运行步骤失败")
		return
	}
	defer rows.Close()
	stepItems := make([]map[string]any, 0, steps)
	for rows.Next() {
		var (
			index                                               int
			thought, command, output, risk, approved, createdAt string
			exitCode                                            int
		)
		if err := rows.Scan(&index, &thought, &command, &output, &risk, &approved, &exitCode, &createdAt); err != nil {
			continue
		}
		stepItems = append(stepItems, map[string]any{
			"index": index, "thought": thought, "command": command, "output": output,
			"risk": risk, "approved": approved, "exitCode": exitCode, "createdAt": createdAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run": map[string]any{
			"id": id, "hostId": hostID, "hostName": hostName, "actor": actor, "role": role,
			"goal": goal, "mode": mode, "status": status, "steps": steps, "summary": summary,
			"error": errText, "startedAt": startedAt, "endedAt": endedAt,
		},
		"steps": stepItems,
	})
}
