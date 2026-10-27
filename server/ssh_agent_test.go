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
