package main

import (
	"os"
	"strconv"
	"strings"

	"vulnagent/server/internal/application/ports"
)

// agentContextBudgetDefault 单次模型调用的上下文预算（估算 token）
const agentContextBudgetDefault = 16000

// contextUsage 一次模型调用的上下文占用，用于 SSE 事件与界面展示
type contextUsage struct {
	UsedTokens      int     `json:"usedTokens"`
	BudgetTokens    int     `json:"budgetTokens"`
	Percent         float64 `json:"percent"`
	CompressedItems int     `json:"compressedItems"`
	SavedTokens     int     `json:"savedTokens"`
	HistoryItems    int     `json:"historyItems"`
}

// agentContextBudget 读取 VA_AGENT_CONTEXT_BUDGET，缺省 16000，限制在 4000–128000
func agentContextBudget() int {
	raw := strings.TrimSpace(os.Getenv("VA_AGENT_CONTEXT_BUDGET"))
	if raw == "" {
		return agentContextBudgetDefault
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 4000 {
		return agentContextBudgetDefault
	}
	if value > 128000 {
		return 128000
	}
	return value
}

// estimateTokens 粗略估算 token：中文按 1 字 1 token，其余按 4 字符 1 token
func estimateTokens(text string) int {
	cjk, other := 0, 0
	for _, r := range text {
		switch {
		case r >= 0x2E80:
			cjk++
		case r > ' ':
			other++
		}
	}
	return cjk + (other+3)/4
}

func buildContextUsage(used, budget, compressed, saved, items int) contextUsage {
	if budget <= 0 {
		budget = agentContextBudgetDefault
	}
	percent := float64(used) / float64(budget) * 100
	if percent > 999 {
		percent = 999
	}
	if saved < 0 {
		saved = 0
	}
	return contextUsage{
		UsedTokens:      used,
		BudgetTokens:    budget,
		Percent:         round1(percent),
		CompressedItems: compressed,
		SavedTokens:     saved,
		HistoryItems:    items,
	}
}

// summarizeStepOutput 从命令输出中提取适合压缩保留的关键行
func summarizeStepOutput(output string, limit int) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return "无输出"
	}
	keywords := []string{"error", "fail", "denied", "not found", "no such", "permission", "fatal", "warning", "错误", "失败", "拒绝", "不存在"}
	var picked []string
	var first string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if first == "" {
			first = line
		}
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				picked = append(picked, line)
				break
			}
		}
		if len(picked) >= 3 {
			break
		}
	}
	if len(picked) == 0 {
		picked = []string{first}
	}
	return truncateRunes(strings.Join(picked, "；"), limit)
}

// budgetedSSHAIHistory 按条数与字符预算筛选问答历史，并把被丢弃的较早对话压缩成一段摘要。
// 返回消息、压缩条数、节省的 token 与原始有效条数。
func budgetedSSHAIHistory(items []sshAIHistoryItem, max int) ([]ports.LLMMessage, int, int, int) {
	if max <= 0 {
		max = 8
	}
	out := make([]ports.LLMMessage, 0, max)
	var dropped []sshAIHistoryItem
	total := 0
	valid := 0
	for index := len(items) - 1; index >= 0; index-- {
		role := strings.ToLower(strings.TrimSpace(items[index].Role))
		if role != "user" && role != "assistant" {
			continue
		}
		content := strings.TrimSpace(items[index].Content)
		if content == "" {
			continue
		}
		valid++
		content = truncateRunes(content, 1500)
		length := len([]rune(content))
		if len(out) >= max || total+length > 6000 {
			dropped = append(dropped, sshAIHistoryItem{Role: role, Content: content})
			continue
		}
		total += length
		out = append(out, ports.LLMMessage{Role: role, Content: content})
	}
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	if len(dropped) == 0 {
		return out, 0, 0, valid
	}

	var builder strings.Builder
	builder.WriteString("较早对话摘要（已压缩，仅保留要点）：\n")
	droppedRunes := 0
	count := 0
	for _, item := range dropped {
		if count >= 6 {
			break
		}
		builder.WriteString(map[bool]string{true: "用户：", false: "助手："}[item.Role == "user"])
		builder.WriteString(truncateRunes(item.Content, 200))
		builder.WriteString("\n")
		droppedRunes += len([]rune(item.Content))
		count++
	}
	summary := truncateRunes(builder.String(), 900)
	out = append([]ports.LLMMessage{{Role: "system", Content: summary}}, out...)
	saved := droppedRunes - len([]rune(summary))
	if saved < 0 {
		saved = 0
	}
	// 用字符差换算成 token 近似值
	savedTokens := saved / 3
	return out, len(dropped), savedTokens, valid
}

// agentPromptTier 某一档上下文压缩参数
type agentPromptTier struct {
	referenceCap    int
	previousCap     int
	recentOutputCap int
	keepRecent      int
}

// buildSSHAgentPrompt 组装 Agent 提示词，并在预算内做分级压缩。
// 最近若干步保留完整输出，更早步骤压缩为「命令 + 退出码 + 关键行」。
func buildSSHAgentPrompt(host sshHost, goal, reference, previous string, history []sshAgentStep, remaining int) (string, contextUsage) {
	budget := agentContextBudget()
	goal = truncateRunes(goal, 4000)
	reference = truncateRunes(reference, 8000)
	previous = truncateRunes(previous, 2000)
	tiers := []agentPromptTier{
		{referenceCap: 8000, previousCap: 2000, recentOutputCap: 1500, keepRecent: 4},
		{referenceCap: 4000, previousCap: 1000, recentOutputCap: 1200, keepRecent: 4},
		{referenceCap: 2000, previousCap: 600, recentOutputCap: 800, keepRecent: 3},
		{referenceCap: 0, previousCap: 0, recentOutputCap: 400, keepRecent: 2},
	}

	text, compressed := composeAgentPrompt(host, goal, truncateRunes(reference, tiers[0].referenceCap),
		truncateRunes(previous, tiers[0].previousCap), history, remaining, tiers[0])
	for _, tier := range tiers[1:] {
		if estimateTokens(text) <= budget {
			break
		}
		text, compressed = composeAgentPrompt(host, goal, truncateRunes(reference, tier.referenceCap),
			truncateRunes(previous, tier.previousCap), history, remaining, tier)
	}

	used := estimateTokens(text)
	baselineText, _ := composeAgentPrompt(host, goal, reference, previous, history, remaining,
		agentPromptTier{referenceCap: 8000, previousCap: 2000, recentOutputCap: 4000, keepRecent: len(history)})
	baselineTokens := estimateTokens(baselineText)
	return text, buildContextUsage(used, budget, compressed, baselineTokens-used, len(history))
}

func composeAgentPrompt(host sshHost, goal, reference, previous string, history []sshAgentStep, remaining int, tier agentPromptTier) (string, int) {
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
	if previous != "" {
		user.WriteString("\n")
		user.WriteString(previous)
	}
	if remaining > 0 {
		user.WriteString("\n剩余可执行步数：")
		user.WriteString(strconv.Itoa(remaining))
		user.WriteString("\n")
	} else {
		user.WriteString("\n可执行步数：不限（连续 5 条命令失败会自动停止）\n")
	}

	if len(history) == 0 {
		user.WriteString("尚未执行任何命令。\n")
		return user.String(), 0
	}

	keep := tier.keepRecent
	if keep <= 0 {
		keep = 4
	}
	split := len(history) - keep
	if split < 0 {
		split = 0
	}
	older := history[:split]
	recent := history[split:]
	compressed := 0

	if len(older) > 0 {
		user.WriteString("较早步骤摘要（已压缩，保留命令、退出码与关键输出）：\n")
		total := 0
		start := 0
		if len(older) > 6 {
			start = len(older) - 6
			compressed += start
		}
		for _, step := range older[start:] {
			line := "- 步骤" + strconv.Itoa(step.Index+1) + "：`" + step.Command + "`"
			if step.ExitCode != 0 {
				line += "（exit " + strconv.Itoa(step.ExitCode) + "）"
			}
			line += " → " + summarizeStepOutput(step.Output, 240) + "\n"
			if total+len([]rune(line)) > 1500 {
				compressed++
				continue
			}
			total += len([]rune(line))
			user.WriteString(line)
			compressed++
		}
	}

	if len(recent) > 0 {
		user.WriteString("最近步骤：\n")
		for _, step := range recent {
			user.WriteString("步骤 " + strconv.Itoa(step.Index+1) + "\n")
			user.WriteString("命令：" + step.Command + "\n")
			user.WriteString("结果：" + truncateRunes(step.Output, tier.recentOutputCap) + "\n")
			if step.ExitCode != 0 {
				user.WriteString("退出码：" + strconv.Itoa(step.ExitCode) + "\n")
			}
		}
	}
	return user.String(), compressed
}
