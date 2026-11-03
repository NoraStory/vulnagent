package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"vulnagent/server/internal/domain/harness"
)

// clusterHealthNode 供 Agent 工具使用的节点摘要（不含凭据）
type clusterHealthNode struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	URL       string `json:"url"`
	SSHHostID int64  `json:"sshHostId"`
	Status    string `json:"status"`
	LatencyMs int64  `json:"latencyMs"`
	Detail    string `json:"detail"`
	CheckedAt string `json:"checkedAt"`
	DBEngine  string `json:"dbEngine,omitempty"`
}

// clusterHealthSummary 集群与节点状态快照
type clusterHealthSummary struct {
	ID           int64               `json:"id"`
	Name         string              `json:"name"`
	ProjectID    int64               `json:"projectId"`
	ProjectName  string              `json:"projectName"`
	Environment  string              `json:"environment"`
	NodeCount    int                 `json:"nodeCount"`
	Healthy      int                 `json:"healthy"`
	Failed       int                 `json:"failed"`
	OpenFindings int                 `json:"openFindings"`
	P0           int                 `json:"p0"`
	P1           int                 `json:"p1"`
	Nodes        []clusterHealthNode `json:"nodes"`
}

// clusterHealthSnapshots 返回全部集群及其节点状态，供 Agent 先看全局
func (a *App) clusterHealthSnapshots(ctx context.Context) ([]clusterHealthSummary, error) {
	clusters, err := a.listClusters(ctx, 0)
	if err != nil {
		return nil, err
	}
	out := make([]clusterHealthSummary, 0, len(clusters))
	for _, cluster := range clusters {
		summary := clusterHealthSummary{
			ID: cluster.ID, Name: cluster.Name, ProjectID: cluster.ProjectID, ProjectName: cluster.ProjectName,
			Environment: cluster.Environment, NodeCount: cluster.NodeCount, Healthy: cluster.HealthyNodes,
			Failed: cluster.NodeCount - cluster.HealthyNodes, OpenFindings: cluster.OpenFindings,
			P0: cluster.P0, P1: cluster.P1, Nodes: []clusterHealthNode{},
		}
		rows, err := a.db.QueryContext(ctx, `SELECT id, name, role, host, port, url, ssh_host_id, status, latency_ms,
			detail, checked_at, db_engine FROM cluster_nodes WHERE cluster_id = ? ORDER BY id`, cluster.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var node clusterHealthNode
			if err := rows.Scan(&node.ID, &node.Name, &node.Role, &node.Host, &node.Port, &node.URL,
				&node.SSHHostID, &node.Status, &node.LatencyMs, &node.Detail, &node.CheckedAt, &node.DBEngine); err != nil {
				rows.Close()
				return nil, err
			}
			summary.Nodes = append(summary.Nodes, node)
		}
		rows.Close()
		out = append(out, summary)
	}
	return out, nil
}

func (a *App) toolListClusters() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("list_clusters", "列出项目/集群/节点及最近一次健康状态。涉及集群、节点或跨主机操作时必须先调用本工具。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{},"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			snapshots, err := a.clusterHealthSnapshots(context.Background())
			if err != nil {
				return nil, err
			}
			totalNodes, healthy, failed := 0, 0, 0
			for _, item := range snapshots {
				totalNodes += item.NodeCount
				healthy += item.Healthy
				failed += item.Failed
			}
			return map[string]any{
				"clusters": snapshots,
				"summary": map[string]int{
					"clusters": len(snapshots), "nodes": totalNodes, "healthy": healthy, "failed": failed,
				},
			}, nil
		},
	}
}

func (a *App) toolCheckCluster() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("check_cluster", "对指定集群的所有节点执行只读健康检查（HTTP/TCP/SSH/数据库深检），返回每个节点状态与错误原因。执行集群或主机操作前应先调用。", harness.RiskLow, "operator", `{
			"type":"object","properties":{
				"clusterId":{"type":"integer","minimum":1,"description":"集群 ID，可先从 list_clusters 获取"}
			},"required":["clusterId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var args struct {
				ClusterID int64 `json:"clusterId"`
			}
			if err := decodeArgs(raw, &args); err != nil {
				return nil, err
			}
			if args.ClusterID <= 0 {
				return nil, fmt.Errorf("clusterId 必须大于 0")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var clusterName string
			if err := a.db.QueryRowContext(ctx, `SELECT name FROM clusters WHERE id = ?`, args.ClusterID).Scan(&clusterName); err != nil {
				return nil, fmt.Errorf("集群不存在：%w", err)
			}
			rows, err := a.db.QueryContext(ctx, `SELECT `+clusterNodeColumns+` FROM cluster_nodes WHERE cluster_id = ? ORDER BY id`, args.ClusterID)
			if err != nil {
				return nil, err
			}
			nodes := make([]clusterNodeRecord, 0, 8)
			for rows.Next() {
				node, scanErr := scanClusterNode(rows)
				if scanErr != nil {
					rows.Close()
					return nil, scanErr
				}
				nodes = append(nodes, node)
			}
			rows.Close()
			if len(nodes) == 0 {
				return nil, fmt.Errorf("集群 #%d 没有节点", args.ClusterID)
			}
			results := make([]clusterHealthNode, 0, len(nodes))
			healthy, failed := 0, 0
			for _, node := range nodes {
				checked := a.runClusterNodeCheck(ctx, node)
				if checked.Status == "ok" {
					healthy++
				} else {
					failed++
				}
				results = append(results, clusterHealthNode{
					ID: checked.ID, Name: checked.Name, Role: checked.Role, Host: checked.Host, Port: checked.Port,
					URL: checked.URL, SSHHostID: checked.SSHHostID, Status: checked.Status,
					LatencyMs: checked.LatencyMs, Detail: checked.Detail, CheckedAt: checked.CheckedAt,
					DBEngine: checked.DBEngine,
				})
			}
			reliability, relErr := a.clusterReliability(ctx, args.ClusterID, 0)
			out := map[string]any{
				"clusterId": args.ClusterID, "clusterName": clusterName, "checkedAt": fmtT(nowT()),
				"results": results,
				"summary": map[string]int{"total": len(results), "healthy": healthy, "failed": failed},
			}
			if relErr == nil {
				out["reliability"] = reliability
			}
			return out, nil
		},
	}
}

func (a *App) toolClusterReliability() harness.Tool {
	return harness.Tool{
		Spec: toolSpec("cluster_reliability", "读取集群可靠性快照：SLO 可用率、错误预算、多窗口燃烧率、节点延迟基线/异常、依赖影响范围与根因候选。诊断集群异常或评估影响面时使用。", harness.RiskLow, "viewer", `{
			"type":"object","properties":{
				"clusterId":{"type":"integer","minimum":1,"description":"集群 ID，可先从 list_clusters 获取"},
				"windowHours":{"type":"integer","minimum":1,"maximum":720,"description":"统计窗口小时数（最多 30 天），缺省使用集群 SLO 配置"}
			},"required":["clusterId"],"additionalProperties":false}`),
		Run: func(raw json.RawMessage) (any, error) {
			var args struct {
				ClusterID   int64 `json:"clusterId"`
				WindowHours int   `json:"windowHours"`
			}
			if err := decodeArgs(raw, &args); err != nil {
				return nil, err
			}
			if args.ClusterID <= 0 {
				return nil, fmt.Errorf("clusterId 必须大于 0")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, err := a.clusterReliability(ctx, args.ClusterID, args.WindowHours)
			if err != nil {
				return nil, err
			}
			return result, nil
		},
	}
}
