package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenUsageAggregatesByModel(t *testing.T) {
	app := newRuntimeTestApp(t)
	now := nowT()
	rows := []struct {
		model, purpose string
		prompt, out    int
		estimated      int
		at             time.Time
	}{
		{"model-a", "agent", 1000, 500, 0, now},
		{"model-a", "agent", 2000, 800, 1, now.AddDate(0, 0, -1)},
		{"model-b", "qa", 400, 100, 0, now},
		{"model-b", "assistant", 100, 50, 0, now.AddDate(0, 0, -3)},
	}
	for _, row := range rows {
		if _, err := app.db.Exec(`INSERT INTO llm_usage
			(model, purpose, prompt_tokens, completion_tokens, total_tokens, estimated, created_at)
			VALUES(?,?,?,?,?,?,?)`,
			row.model, row.purpose, row.prompt, row.out, row.prompt+row.out, row.estimated, fmtT(row.at)); err != nil {
			t.Fatalf("写入测试数据失败：%v", err)
		}
	}

	rec := httptest.NewRecorder()
	app.handleTokenUsage(rec, newCatalogRequest(t, "GET", "/api/v1/audit/token-usage?days=7", nil, "admin"))
	if rec.Code != 200 {
		t.Fatalf("读取 Token 统计失败：%d %s", rec.Code, rec.Body.String())
	}
	var got tokenUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析响应失败：%v", err)
	}
	if got.Totals.Requests != 4 || got.Totals.TotalTokens != 4950 || got.Totals.EstimatedRequests != 1 {
		t.Fatalf("汇总异常：%+v", got.Totals)
	}
	if len(got.Models) != 2 || got.Models[0].Model != "model-a" || got.Models[0].TotalTokens != 4300 {
		t.Fatalf("按模型统计异常：%+v", got.Models)
	}
	if got.Models[0].Share != 86.9 {
		t.Fatalf("模型占比异常：%+v", got.Models[0])
	}
	if len(got.Purposes) != 3 {
		t.Fatalf("按用途统计异常：%+v", got.Purposes)
	}
	if len(got.Trend) != 7 {
		t.Fatalf("趋势应补齐 7 天，实际 %d", len(got.Trend))
	}
	today := now.Format("2006-01-02")
	if got.Trend[len(got.Trend)-1].Date != today {
		t.Fatalf("趋势末位应为今天，实际 %+v", got.Trend[len(got.Trend)-1])
	}

	// 只读与运维角色不可查看审计统计
	for _, role := range []string{"operator", "viewer"} {
		rec = httptest.NewRecorder()
		app.handleTokenUsage(rec, newCatalogRequest(t, "GET", "/api/v1/audit/token-usage", nil, role))
		if rec.Code != 403 {
			t.Fatalf("%s 不应有权限，实际 %d", role, rec.Code)
		}
	}
}
