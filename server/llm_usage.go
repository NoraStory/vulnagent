package main

import (
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/infrastructure/llm/openai"
)

// recordLLMUsage 记录一次模型调用的 token 用量，供审计页面聚合展示。
func (a *App) recordLLMUsage(u openai.Usage) {
	if a.db == nil || u.TotalTokens <= 0 {
		return
	}
	estimated := 0
	if u.Estimated {
		estimated = 1
	}
	if _, err := a.db.Exec(`INSERT INTO llm_usage
		(model, purpose, prompt_tokens, completion_tokens, total_tokens, estimated, created_at)
		VALUES(?,?,?,?,?,?,?)`,
		u.Model, u.Purpose, u.PromptTokens, u.CompletionTokens, u.TotalTokens, estimated, fmtT(nowT())); err != nil {
		slog.Warn("记录模型 token 用量失败", "model", u.Model, "err", err)
	}
}

type tokenUsageModel struct {
	Model             string  `json:"model"`
	Requests          int     `json:"requests"`
	PromptTokens      int     `json:"promptTokens"`
	CompletionTokens  int     `json:"completionTokens"`
	TotalTokens       int     `json:"totalTokens"`
	Share             float64 `json:"share"`
	EstimatedRequests int     `json:"estimatedRequests"`
}

type tokenUsagePurpose struct {
	Purpose          string  `json:"purpose"`
	Requests         int     `json:"requests"`
	PromptTokens     int     `json:"promptTokens"`
	CompletionTokens int     `json:"completionTokens"`
	TotalTokens      int     `json:"totalTokens"`
	Share            float64 `json:"share"`
}

type tokenUsagePoint struct {
	Date        string `json:"date"`
	Requests    int    `json:"requests"`
	TotalTokens int    `json:"totalTokens"`
}

type tokenUsageTotals struct {
	Requests          int     `json:"requests"`
	PromptTokens      int     `json:"promptTokens"`
	CompletionTokens  int     `json:"completionTokens"`
	TotalTokens       int     `json:"totalTokens"`
	EstimatedRequests int     `json:"estimatedRequests"`
	AvgTokensPerCall  float64 `json:"avgTokensPerCall"`
}

type tokenUsageResponse struct {
	Demo     bool                `json:"demo"`
	Days     int                 `json:"days"`
	From     string              `json:"from"`
	To       string              `json:"to"`
	Totals   tokenUsageTotals    `json:"totals"`
	Models   []tokenUsageModel   `json:"models"`
	Purposes []tokenUsagePurpose `json:"purposes"`
	Trend    []tokenUsagePoint   `json:"trend"`
}

func sortTokenUsageModels(items []tokenUsageModel) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TotalTokens == items[j].TotalTokens {
			return items[i].Model < items[j].Model
		}
		return items[i].TotalTokens > items[j].TotalTokens
	})
}

func sortTokenUsagePurposes(items []tokenUsagePurpose) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TotalTokens == items[j].TotalTokens {
			return items[i].Purpose < items[j].Purpose
		}
		return items[i].TotalTokens > items[j].TotalTokens
	})
}

// handleTokenUsage 汇总模型调用 token 消耗：按模型、按用途、按天趋势（admin）。
func (a *App) handleTokenUsage(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	days := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			days = parsed
		}
	}
	if days > 365 {
		days = 365
	}
	now := nowT()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -(days - 1))
	fromText := fmtT(start)

	rows, err := a.db.Query(`SELECT substr(created_at, 1, 10) AS day, model, purpose,
		COUNT(*), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0),
		COALESCE(SUM(total_tokens),0), COALESCE(SUM(estimated),0)
		FROM llm_usage WHERE created_at >= ? GROUP BY day, model, purpose`, fromText)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Token 统计失败")
		return
	}
	defer rows.Close()

	modelIndex := map[string]*tokenUsageModel{}
	purposeIndex := map[string]*tokenUsagePurpose{}
	dayIndex := map[string]*tokenUsagePoint{}
	totals := tokenUsageTotals{}
	for rows.Next() {
		var day, model, purpose string
		var requests, prompt, completion, total, estimated int
		if err := rows.Scan(&day, &model, &purpose, &requests, &prompt, &completion, &total, &estimated); err != nil {
			continue
		}
		if model == "" {
			model = "未知模型"
		}
		if purpose == "" {
			purpose = "unknown"
		}
		totals.Requests += requests
		totals.PromptTokens += prompt
		totals.CompletionTokens += completion
		totals.TotalTokens += total
		totals.EstimatedRequests += estimated

		entry := modelIndex[model]
		if entry == nil {
			entry = &tokenUsageModel{Model: model}
			modelIndex[model] = entry
		}
		entry.Requests += requests
		entry.PromptTokens += prompt
		entry.CompletionTokens += completion
		entry.TotalTokens += total
		entry.EstimatedRequests += estimated

		purposeEntry := purposeIndex[purpose]
		if purposeEntry == nil {
			purposeEntry = &tokenUsagePurpose{Purpose: purpose}
			purposeIndex[purpose] = purposeEntry
		}
		purposeEntry.Requests += requests
		purposeEntry.PromptTokens += prompt
		purposeEntry.CompletionTokens += completion
		purposeEntry.TotalTokens += total

		point := dayIndex[day]
		if point == nil {
			point = &tokenUsagePoint{Date: day}
			dayIndex[day] = point
		}
		point.Requests += requests
		point.TotalTokens += total
	}
	if err := rows.Err(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Token 统计失败")
		return
	}

	models := make([]tokenUsageModel, 0, len(modelIndex))
	for _, entry := range modelIndex {
		if totals.TotalTokens > 0 {
			entry.Share = round1(float64(entry.TotalTokens) / float64(totals.TotalTokens) * 100)
		}
		models = append(models, *entry)
	}
	sortTokenUsageModels(models)

	purposes := make([]tokenUsagePurpose, 0, len(purposeIndex))
	for _, entry := range purposeIndex {
		if totals.TotalTokens > 0 {
			entry.Share = round1(float64(entry.TotalTokens) / float64(totals.TotalTokens) * 100)
		}
		purposes = append(purposes, *entry)
	}
	sortTokenUsagePurposes(purposes)

	if totals.Requests > 0 {
		totals.AvgTokensPerCall = round1(float64(totals.TotalTokens) / float64(totals.Requests))
	}

	// 补齐空白日期，保证趋势图连续
	trend := make([]tokenUsagePoint, 0, days)
	for cursor := start; !cursor.After(now); cursor = cursor.AddDate(0, 0, 1) {
		key := cursor.Format("2006-01-02")
		if point, ok := dayIndex[key]; ok {
			trend = append(trend, *point)
		} else {
			trend = append(trend, tokenUsagePoint{Date: key})
		}
	}

	writeJSON(w, http.StatusOK, tokenUsageResponse{
		Demo: a.demoMode(), Days: days, From: fromText, To: fmtT(now),
		Totals: totals, Models: models, Purposes: purposes, Trend: trend,
	})
}
