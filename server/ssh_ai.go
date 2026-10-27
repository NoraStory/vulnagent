package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"vulnagent/server/internal/application/ports"
)

type sshAIRequest struct {
	HostID    int64  `json:"hostId"`
	Question  string `json:"question"`
	Context   string `json:"context"`
	SessionID string `json:"sessionId"`
}

type sshAIResponse struct {
	Answer   string   `json:"answer"`
	Commands []string `json:"commands"`
	Model    string   `json:"model"`
}

const sshAISystemPrompt = `你是 VulnAgent 的 SSH 终端智能助手，面向运维与安全工程师。
你会收到目标主机信息与最近一段终端输出，请结合现场回答，不要编造未出现的事实。

回答要求：
1. 使用简体中文，先给结论，再给必要步骤；控制在 400 字以内。
2. 需要执行的命令必须放在 ` + "```sh" + ` 代码块中，每行一条、可直接粘贴执行。
3. 涉及删除、覆盖、重启、停止服务、批量变更等高风险操作时，明确标注「危险」并给出更安全的替代方案。
4. 如果终端输出不足以判断，先说明缺少什么信息，再给出下一步取证命令。
5. 不要输出与当前终端任务无关的内容，不要输出密码、密钥或令牌。`

// handleSSHAssistant 基于主机信息与终端上下文生成诊断建议与可执行命令
func (a *App) handleSSHAssistant(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	if a.harness == nil || a.harness.LLM == nil {
		writeErr(w, http.StatusServiceUnavailable, "llm_unavailable", "未配置模型凭据，SSH 智能助手不可用")
		return
	}
	var req sshAIRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "问题不能为空")
		return
	}
	question = truncateRunes(question, 2000)

	hostName := "未指定主机"
	hostLine := ""
	if req.HostID > 0 {
		if host, err := a.getSSHHost(r.Context(), req.HostID); err == nil {
			hostName = host.Name
			hostLine = "目标主机：" + host.Name + "（" + host.Username + "@" + host.addr() + "）"
		}
	}
	context := strings.TrimSpace(req.Context)
	context = truncateRunes(context, 8000)

	var user strings.Builder
	if hostLine != "" {
		user.WriteString(hostLine)
		user.WriteString("\n")
	}
	if context != "" {
		user.WriteString("最近终端输出（可能包含敏感信息，请勿外泄）：\n```\n")
		user.WriteString(context)
		user.WriteString("\n```\n")
	} else {
		user.WriteString("当前没有可用的终端输出。\n")
	}
	user.WriteString("问题：")
	user.WriteString(question)

	resp, err := a.harness.LLM.Chat(r.Context(), ports.LLMRequest{Messages: []ports.LLMMessage{
		{Role: "system", Content: sshAISystemPrompt},
		{Role: "user", Content: user.String()},
	}})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "llm_failed", "模型调用失败："+err.Error())
		return
	}
	answer := strings.TrimSpace(resp.Content)
	commands := extractShellCommands(answer)
	a.audit(r, "ssh.ai.ask", hostName,
		fmt.Sprintf("%s（会话 %s，命令 %d 条）", truncateRunes(question, 120), req.SessionID, len(commands)))
	writeJSON(w, http.StatusOK, sshAIResponse{
		Answer:   answer,
		Commands: commands,
		Model:    a.harness.LLM.Model(),
	})
}

var shellFencePattern = regexp.MustCompile("(?s)```(?:sh|bash|shell|zsh|console)?\\s*\\n(.*?)```")

// extractShellCommands 从模型回答中提取可执行命令，去重并限制数量
func extractShellCommands(answer string) []string {
	matches := shellFencePattern.FindAllStringSubmatch(answer, -1)
	out := make([]string, 0, 8)
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		for _, raw := range strings.Split(match[1], "\n") {
			line := strings.TrimSpace(raw)
			line = strings.TrimPrefix(line, "$ ")
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			if len(line) > 300 {
				line = line[:300]
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
			if len(out) >= 8 {
				return out
			}
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
