package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnagent/server/internal/collect"
)

// agentAuth Agent 侧接入凭据：旧版全局令牌或单机身份（Agent ID + Secret）
type agentAuth struct {
	Token   string
	AgentID string
	Secret  string
}

func (a agentAuth) enrolled() bool { return a.AgentID != "" && a.Secret != "" }

func (a agentAuth) apply(req *http.Request) {
	if a.enrolled() {
		req.Header.Set("X-Agent-Id", a.AgentID)
		req.Header.Set("X-Agent-Secret", a.Secret)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
}

func (a agentAuth) signingKey() []byte {
	if a.enrolled() {
		return agentSigningKey(a.Secret)
	}
	return []byte(a.Token)
}

// agentIdentityFile 存放在 Agent 本机，权限 0600
type agentIdentityFile struct {
	AgentID string `json:"agentId"`
	Secret  string `json:"secret"`
	Server  string `json:"server"`
	Name    string `json:"name"`
}

func defaultAgentIdentityPath() string {
	if path := strings.TrimSpace(os.Getenv("VA_AGENT_IDENTITY")); path != "" {
		return path
	}
	return filepath.Join(dataDirFromEnv(), "agent.identity.json")
}

func loadAgentIdentity(path string) (agentIdentityFile, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return agentIdentityFile{}, false
	}
	var identity agentIdentityFile
	if err := json.Unmarshal(data, &identity); err != nil || identity.AgentID == "" || identity.Secret == "" {
		return agentIdentityFile{}, false
	}
	return identity, true
}

func saveAgentIdentity(path string, identity agentIdentityFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// resolveAgentAuth 依次尝试全局令牌、本机 Agent 身份、一次性注册令牌
func resolveAgentAuth(server, token, tokenFile, enrollToken, identityPath, name string,
	report collect.Report, timeout time.Duration) (agentAuth, error) {
	if strings.TrimSpace(token) == "" && strings.TrimSpace(tokenFile) == "" {
		if resolved, err := resolveAgentToken("", ""); err == nil && resolved != "" {
			return agentAuth{Token: resolved}, nil
		}
	} else if resolved, err := resolveAgentToken(token, tokenFile); err == nil && resolved != "" {
		return agentAuth{Token: resolved}, nil
	}

	if identityPath == "" {
		identityPath = defaultAgentIdentityPath()
	}
	if identity, ok := loadAgentIdentity(identityPath); ok {
		if identity.Server != "" && trimServer(identity.Server) != trimServer(server) {
			fmt.Fprintf(os.Stderr, "警告：本机身份注册于 %s，当前连接 %s\n", identity.Server, server)
		}
		return agentAuth{AgentID: identity.AgentID, Secret: identity.Secret}, nil
	}

	if strings.TrimSpace(enrollToken) == "" {
		return agentAuth{}, fmt.Errorf("未找到 Agent 令牌或身份，请使用 --enroll-token 注册，或用 --token 指定全局令牌")
	}
	if strings.TrimSpace(name) == "" {
		name = report.Hostname
	}
	identity, err := enrollAgent(server, strings.TrimSpace(enrollToken), name, report, timeout)
	if err != nil {
		return agentAuth{}, err
	}
	identity.Server = trimServer(server)
	if err := saveAgentIdentity(identityPath, identity); err != nil {
		return agentAuth{}, fmt.Errorf("保存 Agent 身份失败：%w", err)
	}
	fmt.Fprintf(os.Stderr, "注册成功：agent=%s，身份已保存到 %s\n", identity.AgentID, identityPath)
	return agentAuth{AgentID: identity.AgentID, Secret: identity.Secret}, nil
}

func enrollAgent(server, token, name string, report collect.Report, timeout time.Duration) (agentIdentityFile, error) {
	payload := map[string]any{
		"token": token, "name": name,
		"hostname": report.Hostname, "os": report.OS, "osVersion": report.OSVersion,
		"version": appVersion,
	}
	body, _ := json.Marshal(payload)
	endpoint := trimServer(server) + "/api/v1/agents/enroll"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return agentIdentityFile{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return agentIdentityFile{}, fmt.Errorf("注册请求失败：%w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return agentIdentityFile{}, fmt.Errorf("注册失败（HTTP %d）：%s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AgentID string `json:"agentId"`
		Secret  string `json:"secret"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return agentIdentityFile{}, fmt.Errorf("解析注册响应失败：%w", err)
	}
	if out.AgentID == "" || out.Secret == "" {
		return agentIdentityFile{}, fmt.Errorf("注册响应缺少 Agent 身份")
	}
	return agentIdentityFile{AgentID: out.AgentID, Secret: out.Secret, Name: out.Name}, nil
}

func sendHeartbeat(ctx context.Context, server string, auth agentAuth, report collect.Report) {
	if !auth.enrolled() {
		return
	}
	payload := map[string]any{
		"hostname": report.Hostname, "os": report.OS, "osVersion": report.OSVersion,
		"version": appVersion,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimServer(server)+"/api/v1/agents/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	auth.apply(req)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
}

type agentCommandEnvelope struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Params string `json:"params"`
}

func pollAgentCommands(ctx context.Context, server string, auth agentAuth) ([]agentCommandEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimServer(server)+"/api/v1/agents/commands", nil)
	if err != nil {
		return nil, err
	}
	auth.apply(req)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Items []agentCommandEnvelope `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Items, nil
}

func postAgentCommandResult(ctx context.Context, server string, auth agentAuth, id, status, output, errText string) error {
	payload := map[string]string{"status": status, "output": output, "error": errText}
	body, _ := json.Marshal(payload)
	endpoint := trimServer(server) + "/api/v1/agents/commands/" + url.PathEscape(id) + "/result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	auth.apply(req)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d：%s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

// runAgentCommands 执行控制台下发的 ping / collect 命令并回传结果
func runAgentCommands(ctx context.Context, server string, auth agentAuth, timeout time.Duration) {
	if !auth.enrolled() {
		return
	}
	commands, err := pollAgentCommands(ctx, server, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "拉取 Agent 命令失败：%v\n", err)
		return
	}
	for _, command := range commands {
		status, output, errText := "succeeded", "", ""
		switch command.Action {
		case "ping":
			output = "pong"
		case "collect":
			fresh, err := collect.Collect(collect.Options{IncludeSelf: true})
			if err != nil {
				status, errText = "failed", "采集失败："+err.Error()
			} else if err := postAgentReport(server, auth, fresh, timeout); err != nil {
				status, errText = "failed", "上报失败："+err.Error()
			} else {
				output = fmt.Sprintf("已上报 %s：%d 个组件", fresh.Hostname, len(fresh.Components))
			}
		default:
			status, errText = "failed", "不支持的命令："+command.Action
		}
		if err := postAgentCommandResult(ctx, server, auth, command.ID, status, output, errText); err != nil {
			fmt.Fprintf(os.Stderr, "回传命令 %s 结果失败：%v\n", command.ID, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "命令 %s（%s）完成：%s\n", command.ID, command.Action, status)
	}
}
