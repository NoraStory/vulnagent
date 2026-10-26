package main

import (
	"net/http"
	"sort"
	"strconv"
)

type trajectoryItem struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Time   string `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// handleTrajectory 聚合审计、主机作业与工具调用，形成统一操作轨迹
func (a *App) handleTrajectory(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	kind := r.URL.Query().Get("kind")
	items := make([]trajectoryItem, 0, limit)

	if kind == "" || kind == "audit" {
		rows, err := a.db.Query(`SELECT id, actor, action, target, detail, created_at FROM audit_logs
			ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				var actor, action, target, detail, at string
				if rows.Scan(&id, &actor, &action, &target, &detail, &at) == nil {
					items = append(items, trajectoryItem{
						ID: "audit-" + strconv.FormatInt(id, 10), Kind: "audit", Time: at,
						Actor: actor, Action: action, Target: target, Status: "recorded", Detail: detail,
					})
				}
			}
		}
	}
	if kind == "" || kind == "job" {
		rows, err := a.db.Query(`SELECT id, asset_id, requested_by, action, status, output, error, created_at
			FROM host_jobs ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, actor, action, status, output, errText, at string
				var assetID int64
				if rows.Scan(&id, &assetID, &actor, &action, &status, &output, &errText, &at) == nil {
					detail := output
					if detail == "" {
						detail = errText
					}
					items = append(items, trajectoryItem{
						ID: id, Kind: "job", Time: at, Actor: actor, Action: action,
						Target: "asset:" + strconv.FormatInt(assetID, 10),
						Status: status, Detail: clipTrajectory(detail),
					})
				}
			}
		}
	}
	if kind == "" || kind == "tool" {
		rows, err := a.db.Query(`SELECT c.id, s.owner, c.tool, c.status, c.error, c.created_at
			FROM agent_tool_calls c JOIN agent_sessions s ON s.id = c.session_id
			ORDER BY c.created_at DESC, c.id DESC LIMIT ?`, limit)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				var actor, tool, status, errText, at string
				if rows.Scan(&id, &actor, &tool, &status, &errText, &at) == nil {
					items = append(items, trajectoryItem{
						ID: "tool-" + strconv.FormatInt(id, 10), Kind: "tool", Time: at,
						Actor: actor, Action: tool, Target: "agent", Status: status,
						Detail: clipTrajectory(errText),
					})
				}
			}
		}
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Time > items[j].Time })
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func clipTrajectory(text string) string {
	if len(text) > 400 {
		return text[:400] + "…"
	}
	return text
}
