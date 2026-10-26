package harnessapp

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
	"vulnagent/server/internal/infrastructure/sqlite"
)

// fakeLLM 按脚本依次返回响应，便于端到端验证工具循环
type fakeLLM struct {
	responses []ports.LLMResponse
	idx       int
	requests  []ports.LLMRequest
}

func (f *fakeLLM) Chat(_ context.Context, req ports.LLMRequest) (ports.LLMResponse, error) {
	f.requests = append(f.requests, req)
	if f.idx >= len(f.responses) {
		return ports.LLMResponse{Content: "（无更多脚本）"}, nil
	}
	resp := f.responses[f.idx]
	f.idx++
	return resp, nil
}

func (f *fakeLLM) Model() string { return "fake-model" }

func newTestService(t *testing.T, llm ports.LLM, tools []harness.Tool) (*Service, *sqlite.HarnessRepo) {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatalf("打开测试库失败：%v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := sqlite.NewHarnessRepo(db)
	svc := New(repo, llm, NewRegistry(tools), func(username, password string) bool {
		return username == "alice" && password == "correct-password"
	})
	svc.SystemPrompt = "test"
	return svc, repo
}

func readTool(name string) harness.Tool {
	return harness.Tool{
		Spec: harness.ToolSpec{
			Name: name, Description: "read", Risk: harness.RiskLow, ReadOnly: true, MinRole: "viewer",
			Params: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		Run: func(json.RawMessage) (any, error) {
			return map[string]any{"rows": []string{"a", "b"}}, nil
		},
	}
}

func TestReadToolLoop(t *testing.T) {
	llm := &fakeLLM{responses: []ports.LLMResponse{
		{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "echo", Arguments: `{"q":"x"}`}}},
		{Content: "结论：共 2 条"},
	}}
	svc, repo := newTestService(t, llm, []harness.Tool{readTool("echo")})
	p := Principal{Username: "alice", Role: "viewer"}

	sess, err := svc.CreateSession(context.Background(), p, "测试会话")
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	err = svc.Chat(context.Background(), p, sess.ID, "查一下", func(ev Event) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("对话失败：%v", err)
	}
	types := map[string]int{}
	for _, ev := range events {
		types[ev.Type]++
	}
	if types["tool_result"] != 1 || types["message"] != 3 || types["done"] != 1 {
		t.Fatalf("事件序列不符：%+v", types)
	}
	msgs, err := repo.Messages(context.Background(), sess.ID, 20)
	if err != nil || len(msgs) != 4 {
		t.Fatalf("消息应落库 4 条，实际 %d err=%v", len(msgs), err)
	}
	if msgs[2].Role != "tool" || msgs[2].ToolCallID != "c1" {
		t.Fatalf("工具结果消息不正确：%+v", msgs[2])
	}
}

func TestWriteToolNeedsOneTimeApproval(t *testing.T) {
	var executed atomic.Int32
	writeTool := harness.Tool{
		Spec: harness.ToolSpec{
			Name: "danger", Description: "write", Risk: harness.RiskMedium, MinRole: "operator",
			Params: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		Run: func(json.RawMessage) (any, error) {
			executed.Add(1)
			return map[string]any{"ok": true}, nil
		},
	}
	llm := &fakeLLM{responses: []ports.LLMResponse{
		{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "danger", Arguments: `{"x":1}`}}},
		{Content: "操作已完成"},
	}}
	svc, _ := newTestService(t, llm, []harness.Tool{writeTool})
	p := Principal{Username: "alice", Role: "operator"}
	sess, _ := svc.CreateSession(context.Background(), p, "写操作")

	var approval harness.Approval
	err := svc.Chat(context.Background(), p, sess.ID, "帮我改一下", func(ev Event) {
		if ev.Type == "approval_required" {
			approval = ev.Data.(harness.Approval)
		}
	})
	if err != nil {
		t.Fatalf("对话失败：%v", err)
	}
	if approval.ID == "" {
		t.Fatal("写工具应触发审批")
	}
	if executed.Load() != 0 {
		t.Fatal("审批前不应执行工具")
	}
	if pending, err := svc.PendingApprovals(context.Background(), p, sess.ID); err != nil || len(pending) != 1 {
		t.Fatalf("刷新后应能恢复 1 条待审批，实际 %d err=%v", len(pending), err)
	}
	if err := svc.Chat(context.Background(), p, sess.ID, "再问一句", func(Event) {}); !errors.Is(err, ErrBusy) {
		t.Fatalf("待审批期间不应允许继续对话，实际 %v", err)
	}
	if err := svc.Resume(context.Background(), p, sess.ID, func(Event) {}); !errors.Is(err, ErrBusy) {
		t.Fatalf("待审批时 Resume 应返回 ErrBusy，实际 %v", err)
	}

	if _, _, err := svc.Decide(context.Background(), p, approval.ID, "approve", ""); err != nil {
		t.Fatalf("审批失败：%v", err)
	}
	if pending, _ := svc.PendingApprovals(context.Background(), p, sess.ID); len(pending) != 0 {
		t.Fatalf("审批后不应再有待处理记录：%+v", pending)
	}
	if executed.Load() != 1 {
		t.Fatalf("审批后应执行一次，实际 %d", executed.Load())
	}
	if _, _, err := svc.Decide(context.Background(), p, approval.ID, "approve", ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("审批必须一次性，第二次应报错，实际 %v", err)
	}

	var done bool
	if err := svc.Resume(context.Background(), p, sess.ID, func(ev Event) {
		if ev.Type == "done" {
			done = true
		}
	}); err != nil {
		t.Fatalf("恢复失败：%v", err)
	}
	if !done {
		t.Fatal("恢复后应正常结束")
	}
}

func TestHighRiskRequiresReauthAndRoleGuard(t *testing.T) {
	var executed atomic.Int32
	tool := harness.Tool{
		Spec: harness.ToolSpec{
			Name: "highwrite", Description: "high", Risk: harness.RiskHigh, MinRole: "admin",
			Params: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		Run: func(json.RawMessage) (any, error) {
			executed.Add(1)
			return map[string]any{"ok": true}, nil
		},
	}
	llm := &fakeLLM{responses: []ports.LLMResponse{
		{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "highwrite", Arguments: `{"y":2}`}}},
		{Content: "越权提示已返回"},
		{ToolCalls: []ports.LLMToolCall{{ID: "c2", Name: "highwrite", Arguments: `{"y":2}`}}},
		{Content: "好的"},
	}}
	svc, _ := newTestService(t, llm, []harness.Tool{tool})

	admin := Principal{Username: "alice", Role: "admin"}
	sess, _ := svc.CreateSession(context.Background(), admin, "高风险")

	// operator 调用 admin 工具：直接拒绝，不产生审批
	operator := Principal{Username: "alice", Role: "operator"}
	var denied string
	if err := svc.Chat(context.Background(), operator, sess.ID, "试试", func(ev Event) {
		if ev.Type == "tool_result" {
			denied = string(ev.Data.(map[string]any)["result"].(json.RawMessage))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if denied == "" || executed.Load() != 0 {
		t.Fatalf("越权调用不应执行：%q", denied)
	}

	var approval harness.Approval
	if err := svc.Chat(context.Background(), admin, sess.ID, "执行", func(ev Event) {
		if ev.Type == "approval_required" {
			approval = ev.Data.(harness.Approval)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if approval.ID == "" {
		t.Fatal("高风险工具应触发审批")
	}
	if _, _, err := svc.Decide(context.Background(), admin, approval.ID, "approve", ""); !errors.Is(err, ErrReauth) {
		t.Fatalf("缺少口令应要求再认证，实际 %v", err)
	}
	if executed.Load() != 0 {
		t.Fatal("再认证失败不应执行")
	}
	if _, _, err := svc.Decide(context.Background(), admin, approval.ID, "approve", "correct-password"); err != nil {
		t.Fatalf("带口令审批应成功：%v", err)
	}
	if executed.Load() != 1 {
		t.Fatalf("应执行一次，实际 %d", executed.Load())
	}
}

func TestSessionOwnership(t *testing.T) {
	llm := &fakeLLM{}
	svc, _ := newTestService(t, llm, []harness.Tool{readTool("echo")})
	alice := Principal{Username: "alice", Role: "viewer"}
	bob := Principal{Username: "bob", Role: "viewer"}
	sess, _ := svc.CreateSession(context.Background(), alice, "私有会话")
	if _, err := svc.Session(context.Background(), bob, sess.ID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("他人会话应拒绝访问，实际 %v", err)
	}
	if err := svc.Chat(context.Background(), bob, sess.ID, "hi", func(Event) {}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("他人会话不应可对话，实际 %v", err)
	}
}

// writeToolFor 构造一个可计数的写工具
func writeToolFor(name string, risk harness.Risk, executed *atomic.Int32) harness.Tool {
	return harness.Tool{
		Spec: harness.ToolSpec{
			Name: name, Description: "写操作", Risk: risk, MinRole: "operator",
			Params: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		Run: func(json.RawMessage) (any, error) {
			executed.Add(1)
			return map[string]any{"ok": true}, nil
		},
	}
}

func TestFullModeSkipsApproval(t *testing.T) {
	var executed atomic.Int32
	llm := &fakeLLM{responses: []ports.LLMResponse{
		{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "danger", Arguments: `{"x":1}`}}},
		{Content: "已执行"},
	}}
	svc, _ := newTestService(t, llm, []harness.Tool{writeToolFor("danger", harness.RiskHigh, &executed)})
	p := Principal{Username: "alice", Role: "operator"}

	sess, err := svc.CreateSessionWithMode(context.Background(), p, "完全操作", "full")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ApprovalMode != harness.ApprovalFull {
		t.Fatalf("会话模式应为 full，实际 %s", sess.ApprovalMode)
	}
	got, err := svc.Session(context.Background(), p, sess.ID)
	if err != nil || got.ApprovalMode != harness.ApprovalFull {
		t.Fatalf("模式未持久化：%+v err=%v", got, err)
	}

	var approvalSeen bool
	if err := svc.Chat(context.Background(), p, sess.ID, "直接执行", func(ev Event) {
		if ev.Type == "approval_required" {
			approvalSeen = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if approvalSeen {
		t.Fatal("完全操作模式不应产生审批")
	}
	if executed.Load() != 1 {
		t.Fatalf("完全操作模式应直接执行一次，实际 %d", executed.Load())
	}

	// 切回每次审批后应重新产生审批
	if _, err := svc.SetApprovalMode(context.Background(), p, sess.ID, "each"); err != nil {
		t.Fatal(err)
	}
	llm.idx = 0
	llm.responses = []ports.LLMResponse{
		{ToolCalls: []ports.LLMToolCall{{ID: "c2", Name: "danger", Arguments: `{"x":2}`}}},
		{Content: "待审批"},
	}
	approvalSeen = false
	if err := svc.Chat(context.Background(), p, sess.ID, "再执行一次", func(ev Event) {
		if ev.Type == "approval_required" {
			approvalSeen = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !approvalSeen || executed.Load() != 1 {
		t.Fatalf("切回每次审批后应暂停并等待审批：approval=%v executed=%d", approvalSeen, executed.Load())
	}
}

func TestSkillContextInjectedOnceAndCleared(t *testing.T) {
	llm := &fakeLLM{responses: []ports.LLMResponse{
		{Content: "ok1"}, {Content: "ok2"}, {Content: "ok3"},
	}}
	svc, repo := newTestService(t, llm, []harness.Tool{readTool("echo")})
	p := Principal{Username: "alice", Role: "viewer"}
	sess, err := svc.CreateSession(context.Background(), p, "技能会话")
	if err != nil {
		t.Fatal(err)
	}
	ctxText := "[skill] id=demo\n技能说明"
	for i := 0; i < 2; i++ {
		if err := svc.ChatWithSkill(context.Background(), p, sess.ID, "问题", "demo", ctxText, func(Event) {}); err != nil {
			t.Fatalf("技能对话失败：%v", err)
		}
	}
	messages, err := repo.Messages(context.Background(), sess.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	injected := 0
	for _, message := range messages {
		if message.Role == "system" && strings.Contains(message.Content, "[skill] id=demo") {
			injected++
		}
	}
	if injected != 1 {
		t.Fatalf("同一技能不应重复注入上下文，实际 %d 次", injected)
	}

	if err := svc.Chat(context.Background(), p, sess.ID, "退出技能", func(Event) {}); err != nil {
		t.Fatal(err)
	}
	messages, _ = repo.Messages(context.Background(), sess.ID, 100)
	last := ""
	for _, message := range messages {
		if message.Role == "system" && strings.HasPrefix(message.Content, "[skill]") {
			last = message.Content
		}
	}
	if !strings.Contains(last, "已退出技能模式") {
		t.Fatalf("退出技能后应写入退出标记，实际 %q", last)
	}
}

func TestSmartModeAIJudge(t *testing.T) {
	t.Run("放行", func(t *testing.T) {
		var executed atomic.Int32
		llm := &fakeLLM{responses: []ports.LLMResponse{
			{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "snap", Arguments: `{"assetId":1}`}}},
			{Content: "{\"approve\":true,\"reason\":\"单资产可回滚操作\"}"},
			{Content: "已自动执行"},
		}}
		svc, _ := newTestService(t, llm, []harness.Tool{writeToolFor("snap", harness.RiskMedium, &executed)})
		p := Principal{Username: "alice", Role: "operator"}
		sess, err := svc.CreateSessionWithMode(context.Background(), p, "智能", "smart")
		if err != nil {
			t.Fatal(err)
		}
		var approvalSeen bool
		if err := svc.Chat(context.Background(), p, sess.ID, "创建快照", func(ev Event) {
			if ev.Type == "approval_required" {
				approvalSeen = true
			}
		}); err != nil {
			t.Fatal(err)
		}
		if approvalSeen || executed.Load() != 1 {
			t.Fatalf("AI 放行后应自动执行：approval=%v executed=%d", approvalSeen, executed.Load())
		}
		if len(llm.requests) < 2 || llm.requests[1].Messages[0].Content != smartJudgePrompt {
			t.Fatal("应先调用 AI 审批判断，再执行工具")
		}
	})

	t.Run("转人工", func(t *testing.T) {
		var executed atomic.Int32
		llm := &fakeLLM{responses: []ports.LLMResponse{
			{ToolCalls: []ports.LLMToolCall{{ID: "c1", Name: "svc", Arguments: `{"action":"stop"}`}}},
			{Content: "{\"approve\":false,\"reason\":\"停止服务会影响业务\"}"},
		}}
		svc, _ := newTestService(t, llm, []harness.Tool{writeToolFor("svc", harness.RiskHigh, &executed)})
		p := Principal{Username: "alice", Role: "operator"}
		sess, err := svc.CreateSessionWithMode(context.Background(), p, "智能", "smart")
		if err != nil {
			t.Fatal(err)
		}
		var approval harness.Approval
		if err := svc.Chat(context.Background(), p, sess.ID, "停服务", func(ev Event) {
			if ev.Type == "approval_required" {
				approval = ev.Data.(harness.Approval)
			}
		}); err != nil {
			t.Fatal(err)
		}
		if approval.ID == "" {
			t.Fatal("AI 拒绝放行时应转人工审批")
		}
		if !strings.Contains(approval.Reason, "停止服务会影响业务") {
			t.Fatalf("审批理由应包含 AI 判断：%s", approval.Reason)
		}
		if executed.Load() != 0 {
			t.Fatal("转人工时不应执行")
		}
	})

	t.Run("解析兜底", func(t *testing.T) {
		approve, reason := parseJudge("```json\n{\"approve\":true,\"reason\":\"ok\"}\n```")
		if !approve || reason != "ok" {
			t.Fatalf("代码块包裹应能解析：%v %q", approve, reason)
		}
		if approve, _ := parseJudge("无法判断"); approve {
			t.Fatal("无法解析时应按拒绝处理")
		}
	})
}
