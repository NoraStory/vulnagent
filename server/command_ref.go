package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"vulnagent/server/internal/application/ports"
)

// sshCommandReference 一条来自公共命令参考库（cheat.sh）的检索结果。
// Content 只用于拼装模型提示，不直接返回给前端。
type sshCommandReference struct {
	Topic   string `json:"topic"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
	Content string `json:"-"`
}

const (
	commandRefBase      = "https://cheat.sh"
	commandRefTimeout   = 8 * time.Second
	commandRefCacheTTL  = 10 * time.Minute
	commandRefPerTopic  = 4000
	commandRefPromptCap = 8000
	commandRefMaxTopics = 3
)

var commandRefClient = &http.Client{Timeout: commandRefTimeout}

type cachedCommandRef struct {
	ref sshCommandReference
	at  time.Time
}

var commandRefCache = struct {
	sync.Mutex
	items map[string]cachedCommandRef
}{items: make(map[string]cachedCommandRef)}

var commandTokenPattern = regexp.MustCompile(`[a-z][a-z0-9_-]{1,20}`)
var commandTopicPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,24}$`)

var (
	htmlPrePattern = regexp.MustCompile(`(?is)<pre[^>]*>(.*?)</pre>`)
	htmlTagPattern = regexp.MustCompile(`(?s)<[^>]+>`)
)

// extractCheatSheetPre 兼容 cheat.sh 对非 curl UA 返回 HTML 的情况，提取正文。
func extractCheatSheetPre(document string) string {
	match := htmlPrePattern.FindStringSubmatch(document)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(htmlTagPattern.ReplaceAllString(match[1], "")))
}

// commandTopicSet 只对常见系统命令做检索，避免把自然语言里的英文单词当命令。
var commandTopicSet = map[string]bool{
	"df": true, "du": true, "free": true, "ps": true, "top": true, "htop": true,
	"ss": true, "netstat": true, "ip": true, "ping": true, "traceroute": true, "dig": true, "nslookup": true,
	"curl": true, "wget": true, "nc": true, "telnet": true, "tcpdump": true,
	"systemctl": true, "journalctl": true, "dmesg": true, "service": true, "timedatectl": true,
	"grep": true, "sed": true, "awk": true, "find": true, "xargs": true, "sort": true, "uniq": true,
	"tar": true, "gzip": true, "zip": true, "unzip": true, "rsync": true, "scp": true, "ssh": true,
	"chmod": true, "chown": true, "useradd": true, "usermod": true, "passwd": true, "crontab": true,
	"iptables": true, "nft": true, "firewall-cmd": true, "ufw": true, "semanage": true, "getenforce": true,
	"docker": true, "podman": true, "kubectl": true, "lsof": true, "strace": true,
	"mount": true, "umount": true, "lsblk": true, "blkid": true, "fdisk": true, "parted": true, "mkfs": true,
	"openssl": true, "vmstat": true, "iostat": true, "mpstat": true, "sar": true, "lscpu": true, "lsmod": true,
	"sysctl": true, "apt": true, "apt-get": true, "yum": true, "dnf": true, "rpm": true, "dpkg": true,
	"hostnamectl": true, "getent": true, "id": true, "last": true, "lastb": true, "who": true, "w": true,
	"uptime": true, "hostname": true, "uname": true, "kill": true, "pkill": true, "killall": true,
	"ulimit": true, "auditctl": true, "ausearch": true, "tmux": true, "screen": true, "nohup": true,
}

var keywordTopics = []struct {
	keyword string
	topic   string
}{
	{"磁盘空间", "df"}, {"磁盘使用", "df"}, {"挂载", "df"}, {"目录大小", "du"}, {"占用最大", "du"},
	{"大文件", "find"}, {"内存", "free"}, {"负载", "uptime"}, {"进程", "ps"}, {"端口", "ss"}, {"监听", "ss"},
	{"网络连接", "ss"}, {"路由", "ip"}, {"网卡", "ip"}, {"防火墙", "iptables"},
	{"服务", "systemctl"}, {"开机自启", "systemctl"}, {"日志", "journalctl"}, {"异常登录", "lastb"},
	{"登录失败", "lastb"}, {"最近登录", "last"}, {"定时任务", "crontab"}, {"计划任务", "crontab"},
	{"权限", "chmod"}, {"属主", "chown"}, {"用户", "useradd"}, {"压缩", "tar"}, {"解压", "tar"},
	{"打包", "tar"}, {"查找文件", "find"}, {"搜索文件", "find"}, {"文本替换", "sed"}, {"文本处理", "awk"},
	{"过滤", "grep"}, {"容器", "docker"}, {"kubernetes", "kubectl"}, {"k8s", "kubectl"},
	{"证书", "openssl"}, {"抓包", "tcpdump"}, {"磁盘分区", "fdisk"}, {"分区", "fdisk"},
	{"软件包", "apt"}, {"安装包", "apt"}, {"安全基线", "auditctl"}, {"审计", "ausearch"},
	{"文件句柄", "lsof"}, {"端口占用", "lsof"}, {"内核", "uname"}, {"系统版本", "uname"},
}

// guessCommandTopics 从自然语言问题中提取最多 3 个可检索的命令主题。
func guessCommandTopics(question string) []string {
	lower := strings.ToLower(question)
	seen := make(map[string]bool, commandRefMaxTopics)
	out := make([]string, 0, commandRefMaxTopics)
	add := func(topic string) {
		if topic == "" || seen[topic] || len(out) >= commandRefMaxTopics {
			return
		}
		seen[topic] = true
		out = append(out, topic)
	}
	for _, token := range commandTokenPattern.FindAllString(lower, -1) {
		if commandTopicSet[token] {
			add(token)
		}
	}
	for _, item := range keywordTopics {
		if strings.Contains(question, item.keyword) {
			add(item.topic)
		}
	}
	return out
}

func fetchCommandReference(ctx context.Context, topic string) (sshCommandReference, error) {
	ref := sshCommandReference{Topic: topic, URL: commandRefBase + "/" + url.PathEscape(topic)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.URL+"?T", nil)
	if err != nil {
		return ref, err
	}
	req.Header.Set("User-Agent", "curl/8.5.0 VulnAgent/0.1")
	resp, err := commandRefClient.Do(req)
	if err != nil {
		return ref, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ref, err
	}
	if resp.StatusCode != http.StatusOK {
		return ref, fmt.Errorf("命令参考服务返回 HTTP %d", resp.StatusCode)
	}
	text := strings.TrimSpace(ansiPattern.ReplaceAllString(string(body), ""))
	if strings.Contains(strings.ToLower(text), "<html") {
		text = extractCheatSheetPre(text)
	}
	if text == "" || strings.HasPrefix(text, "Unknown topic") {
		return ref, errors.New("未找到命令参考")
	}
	ref.Title, ref.Snippet, ref.Content = summarizeCommandReference(text)
	if ref.Content == "" {
		return ref, errors.New("命令参考为空")
	}
	return ref, nil
}

func summarizeCommandReference(text string) (title, snippet, content string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	comments := make([]string, 0, 2)
	samples := make([]string, 0, 2)
	kept := make([]string, 0, len(lines))
	for _, raw := range lines {
		trimmed := strings.TrimSpace(strings.TrimRight(raw, " \t"))
		if strings.HasPrefix(trimmed, "#[") {
			continue
		}
		kept = append(kept, strings.TrimRight(raw, " \t"))
		if trimmed == "" || trimmed == "#" {
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
			if value == "" {
				continue
			}
			if title == "" {
				title = value
				continue
			}
			if len(comments) < 2 {
				comments = append(comments, value)
			}
			continue
		}
		if len(samples) < 2 {
			samples = append(samples, trimmed)
		}
	}
	snippet = strings.Join(append(comments, samples...), " · ")
	if len([]rune(snippet)) > 240 {
		snippet = string([]rune(snippet)[:240]) + "…"
	}
	content = strings.TrimSpace(strings.Join(kept, "\n"))
	if len([]rune(content)) > commandRefPerTopic {
		content = string([]rune(content)[:commandRefPerTopic])
	}
	return title, snippet, content
}

// parseCommandTopicList 解析模型输出的命令名数组，限制字符集与数量。
func parseCommandTopicList(raw string) []string {
	text := strings.TrimSpace(raw)
	if start := strings.Index(text, "["); start >= 0 {
		if end := strings.LastIndex(text, "]"); end > start {
			text = text[start : end+1]
		}
	}
	var items []string
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		cleaned := strings.NewReplacer("[", "", "]", "", "\"", "", "`", "").Replace(text)
		items = strings.FieldsFunc(cleaned, func(r rune) bool { return r == ',' || r == '\n' || r == '，' })
	}
	out := make([]string, 0, commandRefMaxTopics)
	seen := make(map[string]bool, commandRefMaxTopics)
	for _, item := range items {
		topic := strings.ToLower(strings.TrimSpace(item))
		topic = strings.Trim(topic, "`'\" .")
		if topic == "" || seen[topic] || !commandTopicPattern.MatchString(topic) {
			continue
		}
		seen[topic] = true
		out = append(out, topic)
		if len(out) >= commandRefMaxTopics {
			break
		}
	}
	return out
}

// modelCommandTopics 在本地关键词无法判断时，让模型给出 1-3 个候选命令名。
func (a *App) modelCommandTopics(ctx context.Context, question string) []string {
	if a.harness == nil || a.harness.LLM == nil {
		return nil
	}
	callCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	resp, err := a.harness.LLM.Chat(callCtx, ports.LLMRequest{Messages: []ports.LLMMessage{
		{
			Role: "system",
			Content: "你是 Linux 命令检索助手。根据用户任务列出最相关的 1-3 个命令名，" +
				"只输出 JSON 字符串数组，例如 [\"df\",\"du\"]；不要输出解释、参数或 Markdown。",
		},
		{Role: "user", Content: truncateRunes(question, 500)},
	}})
	if err != nil {
		return nil
	}
	return parseCommandTopicList(resp.Content)
}

// commandReferences 检索命令参考：本地关键词优先，无法判断时用模型提取命令名。
func (a *App) commandReferences(ctx context.Context, question string) ([]sshCommandReference, string) {
	topics := guessCommandTopics(question)
	if len(topics) == 0 {
		topics = a.modelCommandTopics(ctx, question)
	}
	return a.fetchCommandReferences(ctx, topics)
}

func (a *App) fetchCommandReferences(ctx context.Context, topics []string) ([]sshCommandReference, string) {
	if len(topics) == 0 {
		return nil, ""
	}
	type fetchResult struct {
		ref sshCommandReference
		err error
	}
	results := make(chan fetchResult, len(topics))
	for _, topic := range topics {
		go func(topic string) {
			commandRefCache.Lock()
			cached, ok := commandRefCache.items[topic]
			commandRefCache.Unlock()
			if ok && time.Since(cached.at) < commandRefCacheTTL {
				results <- fetchResult{ref: cached.ref}
				return
			}
			fetchCtx, cancel := context.WithTimeout(ctx, commandRefTimeout)
			defer cancel()
			ref, err := fetchCommandReference(fetchCtx, topic)
			if err == nil {
				commandRefCache.Lock()
				commandRefCache.items[topic] = cachedCommandRef{ref: ref, at: time.Now()}
				commandRefCache.Unlock()
			}
			results <- fetchResult{ref: ref, err: err}
		}(topic)
	}
	refs := make([]sshCommandReference, 0, len(topics))
	for range topics {
		result := <-results
		if result.err == nil && result.ref.Content != "" {
			refs = append(refs, result.ref)
		}
	}
	if len(refs) == 0 {
		return nil, "命令参考检索暂不可用，已回退到模型自身知识"
	}
	return refs, ""
}

func commandReferencePrompt(refs []sshCommandReference) string {
	if len(refs) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("命令参考资料（来自 cheat.sh，按命令主题检索；可能与本机版本不一致，执行前必须先用 command -v / --help 验证）：\n")
	total := 0
	for _, ref := range refs {
		if total >= commandRefPromptCap {
			break
		}
		block := "\n### " + ref.Topic + "\n" + ref.Content + "\n"
		remaining := commandRefPromptCap - total
		if len([]rune(block)) > remaining {
			block = string([]rune(block)[:remaining])
		}
		builder.WriteString(block)
		total += len([]rune(block))
	}
	return builder.String()
}

func referenceMeta(refs []sshCommandReference) []map[string]string {
	out := make([]map[string]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, map[string]string{
			"topic": ref.Topic, "title": ref.Title, "url": ref.URL, "snippet": ref.Snippet,
		})
	}
	return out
}
