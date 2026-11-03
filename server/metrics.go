package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"vulnagent/server/internal/platform/config"
)

// metricsAuthorized 校验指标抓取凭据：优先使用 VA_METRICS_TOKEN；
// 未配置时兼容旧的 Agent Bearer 令牌，避免已有 Prometheus 抓取任务中断。
func (a *App) metricsAuthorized(r *http.Request) bool {
	expected := strings.TrimSpace(config.Load().MetricsToken)
	header := r.Header.Get("Authorization")
	provided := ""
	if strings.HasPrefix(header, "Bearer ") {
		provided = strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	if expected == "" {
		return a.agentAuthorized(r)
	}
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

// handleMetrics 输出 Prometheus 文本指标；允许会话或专用指标令牌访问
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	ctx := r.Context()
	var b strings.Builder
	b.WriteString("# HELP vulnagent_findings_total 漏洞总数（按优先级）\n")
	b.WriteString("# TYPE vulnagent_findings_total gauge\n")
	if rows, err := a.statsRepo().FindingsByPriority(ctx); err == nil {
		for _, item := range rows {
			fmt.Fprintf(&b, "vulnagent_findings_total{priority=%q} %d\n", item.Priority, item.Count)
		}
	}

	b.WriteString("# HELP vulnagent_findings_status 漏洞总数（按状态）\n")
	b.WriteString("# TYPE vulnagent_findings_status gauge\n")
	if rows, err := a.statsRepo().FindingsByStatus(ctx); err == nil {
		for _, item := range rows {
			fmt.Fprintf(&b, "vulnagent_findings_status{status=%q} %d\n", item.Status, item.Count)
		}
	}

	writeGauge := func(name, help string, value int) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	gauges, _ := a.statsRepo().Gauges(ctx)
	writeGauge("vulnagent_assets", "资产总数", gauges.Assets)
	writeGauge("vulnagent_components", "组件总数", gauges.Components)
	writeGauge("vulnagent_cves", "情报库 CVE 总数", gauges.CVEs)
	writeGauge("vulnagent_agents_online", "在线 Agent 数", gauges.AgentsOnline)
	writeGauge("vulnagent_selfcheck_failed", "最近一次自检失败项数", gauges.SelfcheckFailed)

	fmt.Fprint(w, b.String())
}
