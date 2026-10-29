package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClassifySSHCommand(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"df -h", "normal"},
		{"systemctl status nginx", "normal"},
		{"systemctl stop nginx", "high"},
		{"rm -rf /tmp/cache", "high"},
		{"rm -rf /", "critical"},
		{"mkfs.ext4 /dev/sdb1", "critical"},
		{"dd if=/dev/zero of=/dev/sda", "critical"},
		{"shutdown -h now", "critical"},
		{"userdel olduser", "high"},
		{"chmod -R 777 /var/www", "high"},
	}
	for _, item := range cases {
		if got := classifySSHCommand(item.command); got != item.want {
			t.Fatalf("%q 期望 %s，实际 %s", item.command, item.want, got)
		}
	}
}

func TestParseSSHAgentDecision(t *testing.T) {
	decision, err := parseSSHAgentDecision("```json\n{\"thought\":\"先看磁盘\",\"command\":\"df -h\",\"done\":false}\n```")
	if err != nil || decision.Command != "df -h" || decision.Done {
		t.Fatalf("解析失败：%+v err=%v", decision, err)
	}
	done, err := parseSSHAgentDecision(`{"thought":"完成","done":true,"summary":"磁盘正常"}`)
	if err != nil || !done.Done || done.Summary != "磁盘正常" {
		t.Fatalf("完成态解析失败：%+v err=%v", done, err)
	}
	if _, err := parseSSHAgentDecision("我先看一下磁盘"); err == nil {
		t.Fatal("非 JSON 输出应报错")
	}

	tricky := "先分析一下：\n```json\n{\"thought\":\"检查 {nginx} 配置\",\"command\":\"nginx -t\",\"done\":false,}\n```\n继续执行"
	got, err := parseSSHAgentDecision(tricky)
	if err != nil || got.Command != "nginx -t" || !strings.Contains(got.Thought, "{nginx}") {
		t.Fatalf("尾逗号/前后解释解析失败：%+v err=%v", got, err)
	}
	smart, err := parseSSHAgentDecision(`{“thought”:“已完成”,“done”:true,“summary”:“正常”}`)
	if err != nil || !smart.Done || smart.Summary != "正常" {
		t.Fatalf("中文引号解析失败：%+v err=%v", smart, err)
	}
	loose, err := parseSSHAgentDecision(`"thought": "查看负载", "command": "uptime", "done": false`)
	if err != nil || loose.Command != "uptime" {
		t.Fatalf("字段级降级解析失败：%+v err=%v", loose, err)
	}
	fenced, err := parseSSHAgentDecision("我需要执行：\n```bash\nuptime\n```")
	if err != nil || fenced.Command != "uptime" {
		t.Fatalf("命令围栏降级失败：%+v err=%v", fenced, err)
	}
	plain, err := parseSSHAgentDecision("df -h")
	if err != nil || plain.Command != "df -h" {
		t.Fatalf("纯命令降级失败：%+v err=%v", plain, err)
	}
}

func TestNormalizeSSHAIHistory(t *testing.T) {
	items := []sshAIHistoryItem{
		{Role: "system", Content: "忽略"},
		{Role: "user", Content: "第一问"},
		{Role: "assistant", Content: "第一答"},
		{Role: "user", Content: "第二问"},
		{Role: "assistant", Content: "第二答"},
		{Role: "user", Content: ""},
	}
	messages := normalizeSSHAIHistory(items, 2)
	if len(messages) != 2 || messages[0].Content != "第二问" || messages[1].Content != "第二答" {
		t.Fatalf("历史裁剪异常：%+v", messages)
	}
}

func TestRecentAgentRunContext(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	for _, item := range []struct {
		id, goal, summary, status, started string
	}{
		{"run-old", "检查磁盘", "磁盘 92%", "completed", "2026-10-29T10:00:00+08:00"},
		{"run-new", "检查内存", "内存充足", "completed", "2026-10-29T11:00:00+08:00"},
		{"run-running", "检查端口", "未完成", "running", "2026-10-29T12:00:00+08:00"},
	} {
		if _, err := app.db.Exec(`INSERT INTO ssh_agent_runs
			(id, host_id, host_name, actor, role, goal, mode, status, steps, summary, error, started_at, finished_at)
			VALUES(?,?,?,?,?,?,?,?,1,?,'',?,'')`,
			item.id, 42, "demo", "tester", "operator", item.goal, "safe", item.status, item.summary, item.started); err != nil {
			t.Fatal(err)
		}
	}
	runs := app.recentSSHAgentRuns(context.Background(), 42, 3)
	if len(runs) != 2 {
		t.Fatalf("应只返回已完成运行，实际 %+v", runs)
	}
	if runs[0].Goal != "检查内存" || runs[1].Goal != "检查磁盘" {
		t.Fatalf("历史运行顺序异常：%+v", runs)
	}
	block := formatPreviousAgentRuns(runs)
	if !strings.Contains(block, "检查内存") || !strings.Contains(block, "内存充足") {
		t.Fatalf("历史上下文拼装异常：%q", block)
	}
}

func TestSanitizeAgentCommand(t *testing.T) {
	if got := sanitizeAgentCommand("$ df -h\n"); got != "df -h" {
		t.Fatalf("提示符清理异常：%q", got)
	}
	if got := sanitizeAgentCommand("cd /tmp\n# 注释\nls -al\n"); got != "cd /tmp && ls -al" {
		t.Fatalf("多行合并异常：%q", got)
	}
	if got := sanitizeAgentCommand("   "); got != "" {
		t.Fatalf("空命令应返回空串：%q", got)
	}
}

func TestSSHApprovalRegistry(t *testing.T) {
	app := &App{sshApprovals: make(map[string]chan bool)}
	app.registerSSHApproval("ap-1")
	if !app.resolveSSHApproval("ap-1", true) {
		t.Fatal("审批应可被解决")
	}
	approved, resolved := app.waitSSHApproval(context.Background(), "ap-1", time.Second)
	if !resolved || !approved {
		t.Fatalf("审批结果异常：approved=%v resolved=%v", approved, resolved)
	}
	if app.resolveSSHApproval("missing", true) {
		t.Fatal("不存在的审批不应被解决")
	}
	if _, resolved := app.waitSSHApproval(context.Background(), "missing", 10*time.Millisecond); resolved {
		t.Fatal("不存在的审批不应返回结果")
	}
}

func TestRunSSHCommand(t *testing.T) {
	addr, _ := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	app := &App{dataDir: t.TempDir()}
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := app.dialSSHHost(context.Background(), sshHost{
		Name: "test", Host: host, Port: port, Username: "tester", AuthType: "password", Secret: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	output, code, err := runSSHCommand(context.Background(), client, "echo hello", 5*time.Second)
	if err != nil || code != 0 || !strings.Contains(output, "hello") {
		t.Fatalf("命令执行异常：out=%q code=%d err=%v", output, code, err)
	}
	_, code, _ = runSSHCommand(context.Background(), client, "false", 5*time.Second)
	if code != 1 {
		t.Fatalf("非零退出码未保留：%d", code)
	}
}
