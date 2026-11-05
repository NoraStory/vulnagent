package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func agentJSONRequest(method, path string, body any, headers map[string]string) *http.Request {
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

func TestAgentPrincipalHostnameBinding(t *testing.T) {
	legacy := agentPrincipal{Legacy: true}
	if !legacy.allowsHostname("any-host") {
		t.Fatal("全局令牌不应限制主机名")
	}
	enrolled := agentPrincipal{Agent: agentRecord{Hostname: "web-01"}}
	if !enrolled.allowsHostname("WEB-01") {
		t.Fatal("主机名比较应忽略大小写")
	}
	if enrolled.allowsHostname("db-02") {
		t.Fatal("已注册 Agent 不应操作其他主机名")
	}
	unbound := agentPrincipal{Agent: agentRecord{}}
	if !unbound.allowsHostname("any-host") {
		t.Fatal("未记录主机名的历史 Agent 应保持兼容")
	}
}

func TestAgentEnrollmentHeartbeatAndCommands(t *testing.T) {
	app := newRuntimeTestApp(t)

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "POST", "/api/v1/agents/enroll-tokens",
		map[string]any{"nameHint": "测试机", "ttlMinutes": 30}, "operator")
	app.handleAgentEnrollTokenCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("创建注册令牌失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Token == "" {
		t.Fatalf("注册令牌为空")
	}

	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/enroll", map[string]any{
		"token": created.Token, "name": "agent-1", "hostname": "host-1",
		"os": "linux", "osVersion": "Ubuntu 24.04", "version": "test",
	}, nil)
	app.handleAgentEnroll(rec, req)
	if rec.Code != 201 {
		t.Fatalf("注册失败：%d %s", rec.Code, rec.Body.String())
	}
	var enrolled struct {
		AgentID string `json:"agentId"`
		Secret  string `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &enrolled)
	if enrolled.AgentID == "" || enrolled.Secret == "" {
		t.Fatalf("注册响应缺少身份：%+v", enrolled)
	}

	// 令牌一次性
	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/enroll", map[string]any{
		"token": created.Token, "hostname": "host-2",
	}, nil)
	app.handleAgentEnroll(rec, req)
	if rec.Code != 409 {
		t.Fatalf("重复注册应返回 409，实际 %d", rec.Code)
	}

	headers := map[string]string{"X-Agent-Id": enrolled.AgentID, "X-Agent-Secret": enrolled.Secret}
	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/heartbeat", map[string]any{
		"hostname": "host-1", "os": "linux", "osVersion": "Ubuntu 24.04", "version": "test",
	}, headers)
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != 200 {
		t.Fatalf("心跳失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/agents", nil, "viewer")
	app.handleAgents(rec, req)
	if rec.Code != 200 {
		t.Fatalf("读取 Agent 列表失败：%d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []agentRecord `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Items) != 1 || !list.Items[0].Online || list.Items[0].Hostname != "host-1" {
		t.Fatalf("Agent 列表异常：%+v", list.Items)
	}

	// 心跳不能改绑主机，否则后续作业校验会读取被篡改的绑定。
	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/heartbeat", map[string]any{"hostname": "host-2"}, headers)
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("改绑主机名应返回 403，实际 %d %s", rec.Code, rec.Body.String())
	}
	stored, err := app.agentByID(t.Context(), enrolled.AgentID)
	if err != nil || stored.Hostname != "host-1" {
		t.Fatalf("改绑被拒绝后主机名不应变化：%+v err=%v", stored, err)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/agents/x/commands", map[string]any{"action": "ping"}, "operator")
	req.SetPathValue("id", enrolled.AgentID)
	app.handleAgentCommandCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("下发命令失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = agentJSONRequest("GET", "/api/v1/agents/commands", nil, headers)
	app.handleAgentCommandPoll(rec, req)
	if rec.Code != 200 {
		t.Fatalf("拉取命令失败：%d %s", rec.Code, rec.Body.String())
	}
	var polled struct {
		Items []agentCommandRecord `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &polled)
	if len(polled.Items) != 1 || polled.Items[0].Action != "ping" {
		t.Fatalf("命令拉取异常：%+v", polled.Items)
	}

	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/commands/"+polled.Items[0].ID+"/result",
		map[string]any{"status": "succeeded", "output": "pong"}, headers)
	req.SetPathValue("id", polled.Items[0].ID)
	app.handleAgentCommandResult(rec, req)
	if rec.Code != 200 {
		t.Fatalf("回传命令结果失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/agents/x/commands", nil, "viewer")
	req.SetPathValue("id", enrolled.AgentID)
	app.handleAgentCommands(rec, req)
	var history struct {
		Items []agentCommandRecord `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &history)
	if len(history.Items) != 1 || history.Items[0].Status != "succeeded" || history.Items[0].Output != "pong" {
		t.Fatalf("命令历史异常：%+v", history.Items)
	}

	// 错误密钥必须拒绝
	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/heartbeat", map[string]any{"hostname": "host-1"},
		map[string]string{"X-Agent-Id": enrolled.AgentID, "X-Agent-Secret": "wrong"})
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != 401 {
		t.Fatalf("错误密钥应返回 401，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/agents/x/revoke", nil, "operator")
	req.SetPathValue("id", enrolled.AgentID)
	app.handleAgentRevoke(rec, req)
	if rec.Code != 200 {
		t.Fatalf("吊销失败：%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = agentJSONRequest("POST", "/api/v1/agents/heartbeat", map[string]any{"hostname": "host-1"}, headers)
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != 401 {
		t.Fatalf("吊销后心跳应返回 401，实际 %d", rec.Code)
	}
}
