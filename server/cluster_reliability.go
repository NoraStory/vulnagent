package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// clusterNodeRelation 节点依赖关系：from 依赖 to（from -> to）。
type clusterNodeRelation struct {
	ID           int64  `json:"id"`
	ClusterID    int64  `json:"clusterId"`
	FromNodeID   int64  `json:"fromNodeId"`
	ToNodeID     int64  `json:"toNodeId"`
	Kind         string `json:"kind"`
	FromNodeName string `json:"fromNodeName,omitempty"`
	ToNodeName   string `json:"toNodeName,omitempty"`
	CreatedAt    string `json:"createdAt"`
}

type clusterReliabilityNode struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Status        string   `json:"status"`
	LatencyMs     int64    `json:"latencyMs"`
	CheckedAt     string   `json:"checkedAt"`
	HasData       bool     `json:"hasData"`
	Availability  float64  `json:"availability"`
	Checks        int      `json:"checks"`
	Failures      int      `json:"failures"`
	FailureStreak int      `json:"failureStreak"`
	BaselineMs    int64    `json:"baselineMs"`
	LatencyZ      float64  `json:"latencyZ"`
	Anomaly       bool     `json:"anomaly"`
	AnomalyReason string   `json:"anomalyReason,omitempty"`
	HealthScore   int      `json:"healthScore"`
	Spark         []int    `json:"spark"`
	DependsOn     []int64  `json:"dependsOn"`
	ImpactCount   int      `json:"impactCount"`
	ImpactNodes   []string `json:"impactNodes"`
}

type clusterBurnRate struct {
	Window       string  `json:"window"`
	Hours        int     `json:"hours"`
	Availability float64 `json:"availability"`
	BurnRate     float64 `json:"burnRate"`
	Severity     string  `json:"severity"`
	HasData      bool    `json:"hasData"`
}

type clusterRootCause struct {
	NodeID      int64    `json:"nodeId"`
	NodeName    string   `json:"nodeName"`
	Role        string   `json:"role"`
	Reason      string   `json:"reason"`
	Score       float64  `json:"score"`
	ImpactCount int      `json:"impactCount"`
	ImpactNodes []string `json:"impactNodes"`
}

type clusterReliability struct {
	ClusterID              int64                    `json:"clusterId"`
	ClusterName            string                   `json:"clusterName"`
	SLOTarget              float64                  `json:"sloTarget"`
	SLOWindowHours         int                      `json:"sloWindowHours"`
	WindowHours            int                      `json:"windowHours"`
	Availability           float64                  `json:"availability"`
	HasData                bool                     `json:"hasData"`
	Checks                 int                      `json:"checks"`
	ErrorBudgetRemaining   float64                  `json:"errorBudgetRemaining"`
	BurnRate               float64                  `json:"burnRate"`
	ProjectedExhaustionHrs float64                  `json:"projectedExhaustionHours"`
	HealthyNodes           int                      `json:"healthyNodes"`
	FailedNodes            int                      `json:"failedNodes"`
	AnomalyNodes           int                      `json:"anomalyNodes"`
	Nodes                  []clusterReliabilityNode `json:"nodes"`
	BurnRates              []clusterBurnRate        `json:"burnRates"`
	RootCauses             []clusterRootCause       `json:"rootCauses"`
	Relations              []clusterNodeRelation    `json:"relations"`
	GeneratedAt            string                   `json:"generatedAt"`
}

type clusterCheckSample struct {
	ID        int64  `json:"id"`
	NodeID    int64  `json:"nodeId"`
	Status    string `json:"status"`
	LatencyMs int64  `json:"latencyMs"`
	Detail    string `json:"detail"`
	CheckedAt string `json:"checkedAt"`
}

func (a *App) clusterNodeRelations(ctx context.Context, clusterID int64) []clusterNodeRelation {
	rows, err := a.db.QueryContext(ctx, `SELECT r.id, r.cluster_id, r.from_node_id, r.to_node_id, r.kind, r.created_at,
		COALESCE(f.name, ''), COALESCE(t.name, '')
		FROM cluster_node_relations r
		LEFT JOIN cluster_nodes f ON f.id = r.from_node_id
		LEFT JOIN cluster_nodes t ON t.id = r.to_node_id
		WHERE r.cluster_id = ? ORDER BY r.id`, clusterID)
	if err != nil {
		return []clusterNodeRelation{}
	}
	defer rows.Close()
	out := make([]clusterNodeRelation, 0, 8)
	for rows.Next() {
		var item clusterNodeRelation
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.FromNodeID, &item.ToNodeID, &item.Kind,
			&item.CreatedAt, &item.FromNodeName, &item.ToNodeName); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out
}

// replaceNodeDependencies 用给定列表替换节点的 depends_on 依赖，目标节点必须属于同一集群。
func (a *App) replaceNodeDependencies(ctx context.Context, clusterID, nodeID int64, dependsOn []int64) error {
	seen := make(map[int64]bool, len(dependsOn))
	ids := make([]int64, 0, len(dependsOn))
	for _, id := range dependsOn {
		if id <= 0 || id == nodeID || seen[id] {
			continue
		}
		var exists int
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_nodes WHERE id = ? AND cluster_id = ?`,
			id, clusterID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return errors.New("依赖节点不存在或不属于当前集群")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cluster_node_relations WHERE from_node_id = ? AND kind = 'depends_on'`, nodeID); err != nil {
		return err
	}
	now := fmtT(nowT())
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cluster_node_relations
			(cluster_id, from_node_id, to_node_id, kind, created_at) VALUES(?,?,?,'depends_on',?)`,
			clusterID, nodeID, id, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// recordClusterNodeCheck 写入检查历史，并清理 30 天前的旧记录。
func (a *App) recordClusterNodeCheck(ctx context.Context, node clusterNodeRecord) {
	if _, err := a.db.ExecContext(ctx, `INSERT INTO cluster_node_checks
		(cluster_id, node_id, status, latency_ms, detail, checked_at) VALUES(?,?,?,?,?,?)`,
		node.ClusterID, node.ID, node.Status, node.LatencyMs, truncateRunes(node.Detail, 300), node.CheckedAt); err != nil {
		return
	}
	cutoff := fmtT(nowT().Add(-30 * 24 * time.Hour))
	_, _ = a.db.ExecContext(ctx, `DELETE FROM cluster_node_checks WHERE cluster_id = ? AND checked_at < ?`, node.ClusterID, cutoff)
}

// clusterReliability 依据检查历史计算可用率、错误预算、多窗口燃烧率、节点基线与根因候选。
func (a *App) clusterReliability(ctx context.Context, clusterID int64, windowHours int) (clusterReliability, error) {
	var result clusterReliability
	var sloTarget float64
	var sloWindow int
	err := a.db.QueryRowContext(ctx, `SELECT id, name, slo_target, slo_window_hours FROM clusters WHERE id = ?`, clusterID).
		Scan(&result.ClusterID, &result.ClusterName, &sloTarget, &sloWindow)
	if errors.Is(err, sql.ErrNoRows) {
		return result, sql.ErrNoRows
	}
	if err != nil {
		return result, err
	}
	if windowHours <= 0 {
		windowHours = sloWindow
	}
	if windowHours < 1 {
		windowHours = 720
	}
	result.SLOTarget = sloTarget
	result.SLOWindowHours = sloWindow
	result.WindowHours = windowHours
	result.GeneratedAt = fmtT(nowT())
	result.Nodes = []clusterReliabilityNode{}
	result.BurnRates = []clusterBurnRate{}
	result.RootCauses = []clusterRootCause{}
	result.Relations = a.clusterNodeRelations(ctx, clusterID)

	rows, err := a.db.QueryContext(ctx, `SELECT `+clusterNodeColumns+` FROM cluster_nodes
		WHERE cluster_id = ? ORDER BY role, name COLLATE NOCASE`, clusterID)
	if err != nil {
		return result, err
	}
	nodes := make([]clusterNodeRecord, 0, 8)
	for rows.Next() {
		node, err := scanClusterNode(rows)
		if err != nil {
			continue
		}
		nodes = append(nodes, node)
	}
	rows.Close()

	cutoff := fmtT(nowT().Add(-time.Duration(windowHours) * time.Hour))
	checkRows, err := a.db.QueryContext(ctx, `SELECT id, node_id, status, latency_ms, checked_at
		FROM cluster_node_checks WHERE cluster_id = ? AND checked_at >= ? ORDER BY checked_at ASC`, clusterID, cutoff)
	if err != nil {
		return result, err
	}
	samples := make(map[int64][]clusterCheckSample, len(nodes))
	for checkRows.Next() {
		var item clusterCheckSample
		if err := checkRows.Scan(&item.ID, &item.NodeID, &item.Status, &item.LatencyMs, &item.CheckedAt); err != nil {
			continue
		}
		samples[item.NodeID] = append(samples[item.NodeID], item)
	}
	checkRows.Close()

	dependsOn := make(map[int64][]int64)
	impact := make(map[int64][]int64)
	for _, rel := range result.Relations {
		dependsOn[rel.FromNodeID] = append(dependsOn[rel.FromNodeID], rel.ToNodeID)
		impact[rel.ToNodeID] = append(impact[rel.ToNodeID], rel.FromNodeID)
	}
	nodeNames := make(map[int64]string, len(nodes))
	for _, node := range nodes {
		nodeNames[node.ID] = node.Name
	}

	totalChecks, totalSuccess := 0, 0
	for _, node := range nodes {
		nodeDeps := dependsOn[node.ID]
		if nodeDeps == nil {
			nodeDeps = []int64{}
		}
		item := clusterReliabilityNode{
			ID: node.ID, Name: node.Name, Role: node.Role, Status: node.Status,
			LatencyMs: node.LatencyMs, CheckedAt: node.CheckedAt,
			Spark: []int{}, DependsOn: nodeDeps, ImpactNodes: []string{},
		}
		list := samples[node.ID]
		item.Checks = len(list)
		item.HasData = len(list) > 0
		if len(list) > 0 {
			for _, sample := range list {
				if sample.Status == "ok" {
					item.Spark = append(item.Spark, 1)
				} else {
					item.Spark = append(item.Spark, 0)
				}
			}
			if len(item.Spark) > 40 {
				item.Spark = item.Spark[len(item.Spark)-40:]
			}
			for _, sample := range list {
				if sample.Status == "ok" {
					totalSuccess++
				}
			}
			totalChecks += len(list)
			item.Failures = len(list) - countOK(list)
			item.Availability = float64(len(list)-item.Failures) / float64(len(list)) * 100
			item.HealthScore = int(math.Round(item.Availability))
			item.FailureStreak = failureStreak(list)
			baseline, mad, z := latencyBaseline(list)
			item.BaselineMs, item.LatencyZ = baseline, z
			if len(list) >= 3 && baseline > 0 {
				threshold := math.Max(200, float64(baseline)*2)
				if z >= 3.5 || float64(node.LatencyMs) > float64(baseline)+threshold {
					item.Anomaly = true
					item.AnomalyReason = fmt.Sprintf("延迟 %d ms 显著高于基线 %d ms（z=%.1f）", node.LatencyMs, baseline, z)
				}
			}
			_ = mad
		}
		item.ImpactNodes = transitiveDependents(node.ID, impact, nodeNames)
		item.ImpactCount = len(item.ImpactNodes)
		result.Nodes = append(result.Nodes, item)
		if node.Status == "ok" {
			result.HealthyNodes++
		} else if node.Status == "failed" {
			result.FailedNodes++
		}
		if item.Anomaly {
			result.AnomalyNodes++
		}
	}

	result.Checks = totalChecks
	result.HasData = totalChecks > 0
	if totalChecks > 0 {
		result.Availability = float64(totalSuccess) / float64(totalChecks) * 100
		allowedFailure := (100 - sloTarget) / 100
		failureRate := 1 - float64(totalSuccess)/float64(totalChecks)
		if allowedFailure > 0 {
			consumed := failureRate / allowedFailure
			result.ErrorBudgetRemaining = clampFloat((1-consumed)*100, 0, 100)
			result.BurnRate = consumed
			if consumed > 0 {
				result.ProjectedExhaustionHrs = result.ErrorBudgetRemaining / 100 * float64(windowHours) / consumed
			}
		}
	}

	result.BurnRates = calculateBurnRates(samples, sloTarget)
	result.RootCauses = rankRootCauses(result.Nodes, result.Relations, dependsOn)
	return result, nil
}

func (a *App) handleClusterReliability(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	windowHours, _ := strconv.Atoi(r.URL.Query().Get("windowHours"))
	result, err := a.clusterReliability(r.Context(), clusterID, windowHours)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "集群不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "计算集群可靠性失败")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleClusterNodeChecks(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	clusterID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "集群 ID 无效")
		return
	}
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("nodeId"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, node_id, status, latency_ms, detail, checked_at FROM cluster_node_checks
		WHERE cluster_id = ?`
	args := []any{clusterID}
	if nodeID > 0 {
		query += ` AND node_id = ?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY checked_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := a.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取检查历史失败")
		return
	}
	defer rows.Close()
	items := make([]clusterCheckSample, 0, limit)
	for rows.Next() {
		var item clusterCheckSample
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Status, &item.LatencyMs, &item.Detail, &item.CheckedAt); err != nil {
			continue
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func countOK(list []clusterCheckSample) int {
	total := 0
	for _, item := range list {
		if item.Status == "ok" {
			total++
		}
	}
	return total
}

func failureStreak(list []clusterCheckSample) int {
	streak := 0
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Status == "ok" {
			break
		}
		streak++
	}
	return streak
}

// latencyBaseline 使用中位数与 MAD 计算稳健基线，返回中位数、MAD 与当前样本 z 分数。
func latencyBaseline(list []clusterCheckSample) (int64, float64, float64) {
	latencies := make([]float64, 0, len(list))
	for _, item := range list {
		if item.Status == "ok" && item.LatencyMs > 0 {
			latencies = append(latencies, float64(item.LatencyMs))
		}
	}
	if len(latencies) == 0 {
		return 0, 0, 0
	}
	median := medianFloat(latencies)
	deviations := make([]float64, 0, len(latencies))
	for _, value := range latencies {
		deviations = append(deviations, math.Abs(value-median))
	}
	mad := medianFloat(deviations)
	current := latencies[len(latencies)-1]
	scale := mad
	if scale < 1 {
		scale = 1
	}
	z := 0.6745 * (current - median) / scale
	return int64(math.Round(median)), mad, z
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	mid := len(copyValues) / 2
	if len(copyValues)%2 == 0 {
		return (copyValues[mid-1] + copyValues[mid]) / 2
	}
	return copyValues[mid]
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func calculateBurnRates(samples map[int64][]clusterCheckSample, sloTarget float64) []clusterBurnRate {
	defs := []struct {
		label string
		hours int
		warn  float64
	}{
		{"1h", 1, 14.4},
		{"6h", 6, 6},
		{"24h", 24, 3},
		{"3d", 72, 1},
	}
	now := nowT()
	out := make([]clusterBurnRate, 0, len(defs))
	allowedFailure := (100 - sloTarget) / 100
	for _, def := range defs {
		cutoff := now.Add(-time.Duration(def.hours) * time.Hour)
		total, success := 0, 0
		for _, list := range samples {
			for _, item := range list {
				ts, err := parseT(item.CheckedAt)
				if err != nil || ts.Before(cutoff) {
					continue
				}
				total++
				if item.Status == "ok" {
					success++
				}
			}
		}
		rate := clusterBurnRate{Window: def.label, Hours: def.hours}
		if total > 0 && allowedFailure > 0 {
			rate.HasData = true
			rate.Availability = float64(success) / float64(total) * 100
			rate.BurnRate = (1 - float64(success)/float64(total)) / allowedFailure
			switch {
			case rate.BurnRate >= def.warn:
				rate.Severity = "critical"
			case rate.BurnRate >= def.warn/2:
				rate.Severity = "warn"
			default:
				rate.Severity = "ok"
			}
		} else {
			rate.Severity = "none"
		}
		out = append(out, rate)
	}
	return out
}

func transitiveDependents(nodeID int64, impact map[int64][]int64, names map[int64]string) []string {
	seen := map[int64]bool{}
	queue := append([]int64(nil), impact[nodeID]...)
	out := make([]string, 0, len(queue))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nodeID || seen[current] {
			continue
		}
		seen[current] = true
		if name := strings.TrimSpace(names[current]); name != "" {
			out = append(out, name)
		}
		queue = append(queue, impact[current]...)
	}
	sort.Strings(out)
	return out
}

func rankRootCauses(nodes []clusterReliabilityNode, relations []clusterNodeRelation, dependsOn map[int64][]int64) []clusterRootCause {
	nodeMap := make(map[int64]clusterReliabilityNode, len(nodes))
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}
	upstreamFailed := map[int64]int{}
	for _, rel := range relations {
		if node, ok := nodeMap[rel.ToNodeID]; ok && node.Status == "failed" {
			upstreamFailed[rel.FromNodeID]++
		}
	}
	out := make([]clusterRootCause, 0, len(nodes))
	for _, node := range nodes {
		if node.Status != "failed" && !node.Anomaly {
			continue
		}
		score := 0.0
		reasons := make([]string, 0, 3)
		if node.Status == "failed" {
			score += 60
			reasons = append(reasons, "当前检查失败")
		}
		if node.Anomaly {
			score += 20
			reasons = append(reasons, node.AnomalyReason)
		}
		score += float64(node.ImpactCount) * 8
		if node.ImpactCount > 0 {
			reasons = append(reasons, fmt.Sprintf("影响 %d 个下游节点", node.ImpactCount))
		}
		if node.Role == "database" || node.Role == "cache" || node.Role == "storage" {
			score += 5
			reasons = append(reasons, "共享基础依赖")
		}
		if count := upstreamFailed[node.ID]; count > 0 {
			score -= float64(count) * 15
			reasons = append(reasons, fmt.Sprintf("自身依赖 %d 个异常节点，可能为故障传播", count))
		}
		out = append(out, clusterRootCause{
			NodeID: node.ID, NodeName: node.Name, Role: node.Role,
			Reason: strings.Join(reasons, "；"), Score: math.Round(score),
			ImpactCount: node.ImpactCount, ImpactNodes: node.ImpactNodes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].ImpactCount > out[j].ImpactCount
		}
		return out[i].Score > out[j].Score
	})
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
