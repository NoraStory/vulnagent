package main

import (
	"context"
	"testing"
	"time"
)

func TestClusterReliabilitySLOAndRootCause(t *testing.T) {
	app := newRuntimeTestApp(t)
	now := fmtT(nowT())
	res, err := app.db.Exec(`INSERT INTO clusters (project_id, name, created_at, updated_at) VALUES (1, 'prod-a', ?, ?)`, now, now)
	if err != nil {
		t.Fatalf("写入集群失败：%v", err)
	}
	clusterID, _ := res.LastInsertId()

	insertNode := func(name, role, status string, latency int64) int64 {
		res, err := app.db.Exec(`INSERT INTO cluster_nodes
			(cluster_id, name, role, status, latency_ms, checked_at, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?)`, clusterID, name, role, status, latency, now, now, now)
		if err != nil {
			t.Fatalf("写入节点失败：%v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	backendID := insertNode("backend-1", "backend", "ok", 45)
	dbID := insertNode("db-1", "database", "failed", 0)

	if _, err := app.db.Exec(`INSERT INTO cluster_node_relations
		(cluster_id, from_node_id, to_node_id, kind, created_at) VALUES (?,?,?,'depends_on',?)`,
		clusterID, backendID, dbID, now); err != nil {
		t.Fatalf("写入依赖失败：%v", err)
	}

	insertCheck := func(nodeID int64, status string, latency int64, ago time.Duration) {
		if _, err := app.db.Exec(`INSERT INTO cluster_node_checks
			(cluster_id, node_id, status, latency_ms, detail, checked_at) VALUES (?,?,?,?,?,?)`,
			clusterID, nodeID, status, latency, "", fmtT(nowT().Add(-ago))); err != nil {
			t.Fatalf("写入检查历史失败：%v", err)
		}
	}
	for i := 0; i < 10; i++ {
		insertCheck(backendID, "ok", 45, time.Duration(i+1)*time.Minute)
	}
	for i := 0; i < 9; i++ {
		insertCheck(dbID, "ok", 3, time.Duration(i+2)*time.Minute)
	}
	insertCheck(dbID, "failed", 0, 30*time.Second)

	rel, err := app.clusterReliability(context.Background(), clusterID, 0)
	if err != nil {
		t.Fatalf("计算可靠性失败：%v", err)
	}
	if !rel.HasData || rel.Checks != 20 {
		t.Fatalf("检查样本数异常：%+v", rel)
	}
	if rel.FailedNodes != 1 || rel.HealthyNodes != 1 {
		t.Fatalf("节点健康统计异常：%+v", rel)
	}
	if rel.Availability >= 100 || rel.ErrorBudgetRemaining > 0 {
		t.Fatalf("可用率/错误预算异常：%.2f / %.2f", rel.Availability, rel.ErrorBudgetRemaining)
	}
	if len(rel.Relations) != 1 {
		t.Fatalf("依赖关系数量异常：%d", len(rel.Relations))
	}
	var backend clusterReliabilityNode
	for _, node := range rel.Nodes {
		if node.ID == backendID {
			backend = node
		}
	}
	if len(backend.DependsOn) != 1 || backend.DependsOn[0] != dbID {
		t.Fatalf("后端依赖未回填：%+v", backend.DependsOn)
	}
	if len(rel.RootCauses) == 0 || rel.RootCauses[0].NodeName != "db-1" || rel.RootCauses[0].ImpactCount != 1 {
		t.Fatalf("根因排序异常：%+v", rel.RootCauses)
	}
	if len(rel.BurnRates) != 4 || !rel.BurnRates[0].HasData {
		t.Fatalf("多窗口燃烧率异常：%+v", rel.BurnRates)
	}
}
