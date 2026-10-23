package main

import (
	"fmt"
	"net/http"
	"strings"
)

// handleMetrics 输出 Prometheus 文本指标；允许会话或 Agent Bearer 令牌访问
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	var b strings.Builder
	b.WriteString("# HELP vulnagent_findings_total 漏洞总数（按优先级）\n")
	b.WriteString("# TYPE vulnagent_findings_total gauge\n")
	if rows, err := a.db.Query(`SELECT priority, COUNT(*) FROM findings GROUP BY priority`); err == nil {
		for rows.Next() {
			var priority string
			var count int
			if err := rows.Scan(&priority, &count); err == nil {
				fmt.Fprintf(&b, "vulnagent_findings_total{priority=%q} %d\n", priority, count)
			}
		}
		rows.Close()
	}

	b.WriteString("# HELP vulnagent_findings_status 漏洞总数（按状态）\n")
	b.WriteString("# TYPE vulnagent_findings_status gauge\n")
	if rows, err := a.db.Query(`SELECT status, COUNT(*) FROM findings GROUP BY status`); err == nil {
		for rows.Next() {
			var status string
			var count int
			if err := rows.Scan(&status, &count); err == nil {
				fmt.Fprintf(&b, "vulnagent_findings_status{status=%q} %d\n", status, count)
			}
		}
		rows.Close()
	}

	writeGauge := func(name, help string, query string) {
		var value int
		if err := a.db.QueryRow(query).Scan(&value); err != nil {
			value = 0
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	writeGauge("vulnagent_assets", "资产总数", `SELECT COUNT(*) FROM assets`)
	writeGauge("vulnagent_components", "组件总数", `SELECT COUNT(*) FROM components`)
	writeGauge("vulnagent_cves", "情报库 CVE 总数", `SELECT COUNT(*) FROM cves`)
	writeGauge("vulnagent_agents_online", "在线 Agent 数", `SELECT COUNT(*) FROM assets WHERE source='agent' AND agent_status='online'`)
	writeGauge("vulnagent_selfcheck_failed", "最近一次自检失败项数",
		`SELECT COALESCE((SELECT failed FROM selfcheck_runs ORDER BY finished_at DESC LIMIT 1), 0)`)

	fmt.Fprint(w, b.String())
}
