package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/domain/harness"
	"vulnagent/server/internal/domain/vuln"
	"vulnagent/server/internal/infrastructure/sqlite"
)

// harnessTools 返回静态注册的工具集。这里明确不暴露：
// SSH 扫描、Agent 令牌轮换、账号增删改、风险策略修改、任意 shell/SQL/URL。
func (a *App) harnessTools() []harness.Tool {
	return []harness.Tool{
		a.toolOverviewSummary(),
		a.toolListAssets(),
		a.toolGetAsset(),
		a.toolListFindings(),
		a.toolGetFinding(),
		a.toolSearchCVEs(),
		a.toolGetCVE(),
		a.toolListProductMap(),
		a.toolListAuditLogs(),
		a.toolSyncStatus(),
		a.toolSelfcheckLatest(),
		a.toolRescanAsset(),
		a.toolUpdateFindingStatus(),
		a.toolCreateTicket(),
		a.toolUpsertProductMap(),
		a.toolRunSelfcheck(),
		a.toolListHostJobs(),
		a.toolGetHostJob(),
		a.toolReadHostFile(),
		a.toolRunHostCommand(),
		a.toolWriteHostFile(),
		a.toolServiceAction(),
	}
}

func toolSpec(name, desc string, risk harness.Risk, minRole string, params string) harness.ToolSpec {
	return harness.ToolSpec{
		Name:        name,
		Description: desc,
		Risk:        risk,
		ReadOnly:    risk == harness.RiskLow,
		MinRole:     minRole,
		Params:      json.RawMessage(params),
	}
}

func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("参数格式错误：%w", err)
	}
	return nil
}

func limitOf(v int, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// ---------- 只读工具 ----------

func (a *App) toolOverviewSummary() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("overview_summary", "获取控制面总览：漏洞优先级/状态分布、资产与 Agent 概况、同步状态、最近自检。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{},"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			ctx := context.Background()
			prio, err := a.statsRepo().FindingsByPriority(ctx)
			if err != nil {
				return nil, err
			}
			status, err := a.statsRepo().FindingsByStatus(ctx)
			if err != nil {
				return nil, err
			}
			agents, _ := a.statsRepo().AgentSummary(ctx)
			checks, found, _ := a.statsRepo().LatestSelfcheck(ctx)
			return map[string]any{
				"byPriority": prio,
				"byStatus":   status,
				"agents":     agents,
				"sync":       a.loadSync(),
				"selfcheck":  map[string]any{"found": found, "summary": checks},
			}, nil
		},
	}
}

func (a *App) toolListAssets() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_assets", "分页列出资产，可按主机名/IP/负责人关键词过滤。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{
				"q":{"type":"string","description":"关键词，匹配主机名、IP 或负责人"},
				"limit":{"type":"integer","minimum":1,"maximum":50,"description":"返回条数，默认 20"}
			},
			"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			items, total, err := a.readAssets().List(context.Background(), strings.TrimSpace(in.Q),
				limitOf(in.Limit, 20, 50), 0)
			if err != nil {
				return nil, err
			}
			return map[string]any{"total": total, "items": items}, nil
		},
	}
}

func (a *App) toolGetAsset() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_asset", "读取单台资产的详情、组件清单与关联漏洞（最多 30 条）。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{"id":{"type":"integer","description":"资产 ID"}},
			"required":["id"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				ID int64 `json:"id"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			ctx := context.Background()
			item, err := a.readAssets().Detail(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			comps, err := a.readAssets().ComponentRows(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			findings, err := a.readFindings().ListByAsset(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			if len(findings) > 30 {
				findings = findings[:30]
			}
			if len(comps) > 100 {
				comps = comps[:100]
			}
			return map[string]any{"asset": item, "components": comps, "findings": findings}, nil
		},
	}
}

func (a *App) toolListFindings() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_findings", "按优先级、状态或关键词查询漏洞结论。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{
				"priority":{"type":"string","enum":["P0","P1","P2","P3"]},
				"status":{"type":"string","enum":["open","triaged","fixing","fixed","verified","closed","risk_accepted","false_positive"]},
				"q":{"type":"string","description":"关键词，匹配主机名、CVE 或组件名"},
				"limit":{"type":"integer","minimum":1,"maximum":50}
			},
			"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Priority string `json:"priority"`
				Status   string `json:"status"`
				Q        string `json:"q"`
				Limit    int    `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			items, total, err := a.readFindings().List(context.Background(), ports.FindingFilter{
				Priority: in.Priority, Status: in.Status, Query: strings.TrimSpace(in.Q),
				Limit: limitOf(in.Limit, 20, 50),
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"total": total, "items": items}, nil
		},
	}
}

func (a *App) toolGetFinding() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_finding", "读取单条漏洞的完整信息：描述、CWE、打分明细、POC 与处置事件。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{"id":{"type":"integer","description":"漏洞 ID"}},
			"required":["id"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				ID int64 `json:"id"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			ctx := context.Background()
			item, err := a.readFindings().Get(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			extra, err := a.readFindings().Extra(ctx, in.ID)
			if err != nil {
				return nil, err
			}
			pocs, _ := a.readFindings().POCs(ctx, item.CVEID)
			events, _ := a.readFindings().Events(ctx, in.ID)
			if len(events) > 20 {
				events = events[len(events)-20:]
			}
			return map[string]any{"finding": item, "extra": extra, "pocs": pocs, "events": events}, nil
		},
	}
}

func (a *App) toolSearchCVEs() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("search_cves", "在本地情报库中按关键词搜索 CVE（CVE ID、标题或描述）。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{
				"q":{"type":"string","description":"关键词"},
				"limit":{"type":"integer","minimum":1,"maximum":20}
			},
			"required":["q"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.Q) == "" {
				return nil, fmt.Errorf("关键词不能为空")
			}
			items, err := a.readIntel().SearchCVEs(context.Background(), strings.TrimSpace(in.Q), limitOf(in.Limit, 10, 20))
			if err != nil {
				return nil, err
			}
			return map[string]any{"count": len(items), "items": items}, nil
		},
	}
}

func (a *App) toolGetCVE() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_cve", "读取单条 CVE 的情报详情与受影响版本区间。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{"id":{"type":"string","description":"CVE 编号，例如 CVE-2024-3094"}},
			"required":["id"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			cve, affected, err := a.readIntel().GetCVE(context.Background(), strings.TrimSpace(in.ID))
			if err != nil {
				return nil, err
			}
			return map[string]any{"cve": cve, "affected": affected}, nil
		},
	}
}

func (a *App) toolListProductMap() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_product_map", "列出组件名到漏洞库产品名的映射。", harness.RiskLow, "viewer", `{
			"type":"object",
			"properties":{
				"q":{"type":"string"},
				"limit":{"type":"integer","minimum":1,"maximum":100}
			},
			"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			items, err := a.readIntel().ProductMapList(context.Background(), strings.TrimSpace(in.Q), limitOf(in.Limit, 50, 100))
			if err != nil {
				return nil, err
			}
			return map[string]any{"count": len(items), "items": items}, nil
		},
	}
}

func (a *App) toolListAuditLogs() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_audit_logs", "查询审计日志，可按动作与操作人过滤（仅管理员）。", harness.RiskLow, "admin", `{
			"type":"object",
			"properties":{
				"action":{"type":"string"},
				"actor":{"type":"string"},
				"limit":{"type":"integer","minimum":1,"maximum":50}
			},
			"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Action string `json:"action"`
				Actor  string `json:"actor"`
				Limit  int    `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			items, err := a.readAudit().List(context.Background(), ports.AuditFilter{
				Action: strings.TrimSpace(in.Action), Actor: strings.TrimSpace(in.Actor),
				Limit: limitOf(in.Limit, 20, 50),
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"count": len(items), "items": items}, nil
		},
	}
}

func (a *App) toolSyncStatus() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_sync_status", "读取情报同步状态（CVE、POC、EPSS）与滞后小时数。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{},"additionalProperties":false}`),
		Run: func(json.RawMessage) (any, error) {
			return map[string]any{"sources": a.loadSync()}, nil
		},
	}
}

func (a *App) toolSelfcheckLatest() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_selfcheck_latest", "读取最近一次自检结果摘要。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{},"additionalProperties":false}`),
		Run: func(json.RawMessage) (any, error) {
			summary, found, err := a.statsRepo().LatestSelfcheck(context.Background())
			if err != nil {
				return nil, err
			}
			return map[string]any{"found": found, "summary": summary}, nil
		},
	}
}

// ---------- 写工具（需审批） ----------

func (a *App) toolRescanAsset() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("rescan_asset", "对指定资产重新执行匹配与状态收敛（写操作，需审批）。", harness.RiskMedium, "operator", `{
			"type":"object",
			"properties":{"assetId":{"type":"integer","description":"资产 ID"}},
			"required":["assetId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID int64 `json:"assetId"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			out, err := a.rescanAsset(in.AssetID, "Agent 助手")
			if err != nil {
				return nil, err
			}
			a.auditAs("Agent 助手", "agent", "127.0.0.1", "harness", "findings.rescan",
				fmt.Sprintf("asset:%d", in.AssetID), "经审批由 Agent 助手触发复扫")
			return out, nil
		},
	}
}

func (a *App) toolUpdateFindingStatus() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("update_finding_status", "修改漏洞处置状态（高风险写操作，需审批 + 口令再认证）。", harness.RiskHigh, "operator", `{
			"type":"object",
			"properties":{
				"findingId":{"type":"integer"},
				"status":{"type":"string","enum":["open","triaged","fixing","fixed","verified","closed","risk_accepted","false_positive"]}
			},
			"required":["findingId","status"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				FindingID int64  `json:"findingId"`
				Status    string `json:"status"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			if !vuln.Status(in.Status).Valid() {
				return nil, fmt.Errorf("非法状态：%s", in.Status)
			}
			ctx := context.Background()
			cur, err := a.findingRepo().Get(ctx, in.FindingID)
			if err != nil {
				return nil, err
			}
			if err := a.findingRepo().UpdateStatusAssignee(ctx, in.FindingID, in.Status, cur.Assignee); err != nil {
				return nil, err
			}
			now := fmtT(nowT())
			if ticket, found, err := a.ticketRepo().ByFinding(ctx, in.FindingID); err == nil && found {
				_ = a.ticketRepo().UpdateStatus(ctx, ticket.ID, in.Status, cur.Assignee, now)
			}
			event := fmt.Sprintf("status: %s → %s", cur.Status, in.Status)
			_ = a.findingRepo().AddEvent(ctx, in.FindingID, event, "Agent 助手", "经审批由 Agent 助手执行", now)
			a.auditAs("Agent 助手", "agent", "127.0.0.1", "harness", "finding.status",
				cur.CVEID+" @ "+cur.AssetHostname, event)
			return map[string]any{"ok": true, "findingId": in.FindingID, "status": in.Status}, nil
		},
	}
}

func (a *App) toolCreateTicket() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("create_ticket", "为漏洞创建变更工单并流转为修复中（高风险写操作，需审批 + 口令再认证）。", harness.RiskHigh, "operator", `{
			"type":"object",
			"properties":{"findingId":{"type":"integer"}},
			"required":["findingId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				FindingID int64 `json:"findingId"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			ctx := context.Background()
			cur, err := a.findingRepo().Get(ctx, in.FindingID)
			if err != nil {
				return nil, err
			}
			item, err := a.getFinding(in.FindingID)
			if err != nil {
				return nil, err
			}
			ticket, created, err := a.ensureTicket(item, "Agent 助手")
			if err != nil {
				return nil, err
			}
			now := fmtT(nowT())
			if created {
				_ = a.findingRepo().AddEvent(ctx, in.FindingID, "ticket: "+ticket.ID+" 已创建", "Agent 助手",
					"经审批由 Agent 助手创建本地工单", now)
				a.auditAs("Agent 助手", "agent", "127.0.0.1", "harness", "finding.ticket",
					cur.CVEID+" @ "+cur.AssetHostname, "创建工单 "+ticket.ID)
				a.dispatch("ticket.created", map[string]any{
					"ticketId": ticket.ID, "cveId": cur.CVEID, "hostname": cur.AssetHostname,
					"priority": cur.Priority, "risk": cur.Risk, "status": ticket.Status, "assignee": ticket.Assignee,
				})
			}
			return map[string]any{"ok": true, "ticketId": ticket.ID, "status": ticket.Status, "ticket": ticket, "created": created}, nil
		},
	}
}

func (a *App) toolUpsertProductMap() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("upsert_product_map", "新增或更新组件名到产品名的映射，并重新匹配全部资产（高风险写操作，需审批 + 口令再认证）。", harness.RiskHigh, "admin", `{
			"type":"object",
			"properties":{
				"eco":{"type":"string"},
				"name":{"type":"string"},
				"product":{"type":"string"},
				"confidence":{"type":"number","minimum":0,"maximum":1}
			},
			"required":["eco","name","product"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				Eco        string  `json:"eco"`
				Name       string  `json:"name"`
				Product    string  `json:"product"`
				Confidence float64 `json:"confidence"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			in.Eco = strings.ToLower(strings.TrimSpace(in.Eco))
			in.Name = strings.ToLower(strings.TrimSpace(in.Name))
			in.Product = strings.ToLower(strings.TrimSpace(in.Product))
			if in.Eco == "" || in.Name == "" || in.Product == "" {
				return nil, fmt.Errorf("生态、组件名与产品不能为空")
			}
			if in.Confidence == 0 {
				in.Confidence = 1.0
			}
			if in.Confidence < 0 || in.Confidence > 1 {
				return nil, fmt.Errorf("置信度需在 0 与 1 之间")
			}
			now := fmtT(nowT())
			if err := a.intelRepo().UpsertProductMapping(context.Background(), ports.ProductMapping{
				Eco: in.Eco, Name: in.Name, Product: in.Product, Confidence: in.Confidence,
				Source: "manual", UpdatedAt: now,
			}, now); err != nil {
				return nil, err
			}
			rematched, err := a.rematchAllAssets()
			if err != nil {
				return nil, err
			}
			a.auditAs("Agent 助手", "agent", "127.0.0.1", "harness", "productmap.upsert",
				in.Eco+"/"+in.Name, fmt.Sprintf("映射到 %s，重匹配 %d 台资产", in.Product, rematched))
			return map[string]any{"ok": true, "rematched": rematched}, nil
		},
	}
}

// ---------- 主机执行工具（Phase 2） ----------

func (a *App) toolListHostJobs() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_host_jobs", "查看指定资产最近的主机作业（只读）。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{
				"assetId":{"type":"integer"},
				"limit":{"type":"integer","minimum":1,"maximum":100}
			},"required":["assetId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID int64 `json:"assetId"`
				Limit   int   `json:"limit"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			jobs, err := a.jobRepo().ListByAsset(context.Background(), in.AssetID, limitOf(in.Limit, 20, 100))
			if err != nil {
				return nil, err
			}
			return map[string]any{"count": len(jobs), "items": jobs}, nil
		},
	}
}

func (a *App) toolGetHostJob() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("get_host_job", "按作业 ID 查询执行状态与输出（只读）。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{"jobId":{"type":"string"}},"required":["jobId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				JobID string `json:"jobId"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			job, found, err := a.jobRepo().ByID(context.Background(), in.JobID)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, fmt.Errorf("作业不存在：%s", in.JobID)
			}
			return map[string]any{"job": job}, nil
		},
	}
}

func (a *App) toolReadHostFile() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("read_host_file", "读取目标主机上的文本文件（只读，需审批）。", harness.RiskMedium, "operator", `{
			"type":"object","properties":{
				"assetId":{"type":"integer"},
				"path":{"type":"string"},
				"maxBytes":{"type":"integer","minimum":1,"maximum":524288}
			},"required":["assetId","path"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID  int64  `json:"assetId"`
				Path     string `json:"path"`
				MaxBytes int    `json:"maxBytes"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			return a.runHostAction(in.AssetID, "read_file", in, "Agent 助手")
		},
	}
}

func (a *App) toolRunHostCommand() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("run_host_command", "在目标主机执行白名单只读命令（高风险，需审批 + 口令再认证）。禁止 shell 拼接。", harness.RiskHigh, "operator", `{
			"type":"object","properties":{
				"assetId":{"type":"integer"},
				"argv":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":20},
				"cwd":{"type":"string"},
				"timeoutSec":{"type":"integer","minimum":1,"maximum":120}
			},"required":["assetId","argv"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID    int64    `json:"assetId"`
				Argv       []string `json:"argv"`
				Cwd        string   `json:"cwd"`
				TimeoutSec int      `json:"timeoutSec"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			return a.runHostAction(in.AssetID, "run_command", in, "Agent 助手")
		},
	}
}

func (a *App) toolWriteHostFile() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("write_host_file", "写入目标主机文件（高风险，需审批 + 口令再认证；自动备份原文件）。", harness.RiskHigh, "operator", `{
			"type":"object","properties":{
				"assetId":{"type":"integer"},
				"path":{"type":"string"},
				"content":{"type":"string"},
				"dryRun":{"type":"boolean","description":"true 时仅预检，不落盘"}
			},"required":["assetId","path","content"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID int64  `json:"assetId"`
				Path    string `json:"path"`
				Content string `json:"content"`
				DryRun  bool   `json:"dryRun"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			return a.runHostAction(in.AssetID, "write_file", in, "Agent 助手")
		},
	}
}

func (a *App) toolServiceAction() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("service_action", "启停/重启/查看系统服务（高风险，需审批 + 口令再认证）。", harness.RiskHigh, "operator", `{
			"type":"object","properties":{
				"assetId":{"type":"integer"},
				"service":{"type":"string"},
				"action":{"type":"string","enum":["start","stop","restart","status","enable","disable"]}
			},"required":["assetId","service","action"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var in struct {
				AssetID int64  `json:"assetId"`
				Service string `json:"service"`
				Action  string `json:"action"`
			}
			if err := decodeArgs(raw, &in); err != nil {
				return nil, err
			}
			return a.runHostAction(in.AssetID, "service_action", in, "Agent 助手")
		},
	}
}

// runHostAction 排队并等待主机作业，返回作业结果
func (a *App) runHostAction(assetID int64, action string, params any, actor string) (any, error) {
	if _, err := a.assetHostname(assetID); err != nil {
		return nil, fmt.Errorf("资产不存在：%w", err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	job, err := a.queueHostJob(assetID, action, raw, actor, "")
	if err != nil {
		return nil, err
	}
	a.auditAs(actor, "operator", "127.0.0.1", "harness", "host.job.queue", job.ID,
		fmt.Sprintf("%s @ asset:%d", action, assetID))
	done, err := a.waitHostJob(job.ID, 20*time.Second)
	if err != nil {
		return nil, err
	}
	pending := done.Status == "pending" || done.Status == "running"
	return map[string]any{
		"ok":       done.Status == "succeeded",
		"jobId":    done.ID,
		"status":   done.Status,
		"pending":  pending,
		"output":   done.Output,
		"error":    done.Error,
		"exitCode": done.ExitCode,
		"attempts": done.Attempts,
	}, nil
}

func (a *App) toolRunSelfcheck() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("run_selfcheck", "执行一次完整自检（写操作，需审批，仅管理员）。", harness.RiskMedium, "admin", `{
			"type":"object","properties":{},"additionalProperties":false}`),
		Run: func(json.RawMessage) (any, error) {
			run, err := a.runSelfcheck("Agent 助手")
			if err != nil {
				return nil, err
			}
			return run, nil
		},
	}
}

// 只读仓储：使用 mode=ro 连接，从连接层杜绝读工具写入
func (a *App) readAssets() *sqlite.AssetRepo { return sqlite.NewAssetRepo(a.readDB()) }

func (a *App) readFindings() *sqlite.FindingRepo { return sqlite.NewFindingRepo(a.readDB()) }

func (a *App) readIntel() *sqlite.IntelRepo { return sqlite.NewIntelRepo(a.readDB()) }

func (a *App) readAudit() *sqlite.AuditRepo { return sqlite.NewAuditRepo(a.readDB()) }
