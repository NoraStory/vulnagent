package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProjectsClustersAndHealthCheck(t *testing.T) {
	app := newRuntimeTestApp(t)

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "POST", "/api/v1/projects",
		map[string]any{"name": "核心交易", "description": "联调项目", "owner": "ops"}, "admin")
	app.handleProjectCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("创建项目失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/clusters",
		map[string]any{"projectId": created.ID, "name": "prod-a", "environment": "prod", "provider": "aliyun"}, "admin")
	app.handleClusterCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("创建集群失败：%d %s", rec.Code, rec.Body.String())
	}
	var clusterCreated struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &clusterCreated)

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer health.Close()

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/clusters/x/nodes", map[string]any{
		"name": "backend-1", "role": "backend", "url": health.URL, "checkType": "http",
	}, "operator")
	req.SetPathValue("id", strconv.FormatInt(clusterCreated.ID, 10))
	app.handleClusterNodeCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("创建节点失败：%d %s", rec.Code, rec.Body.String())
	}
	var nodeCreated struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &nodeCreated)

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/cluster-nodes/x/check", nil, "operator")
	req.SetPathValue("id", strconv.FormatInt(nodeCreated.ID, 10))
	app.handleClusterNodeCheck(rec, req)
	if rec.Code != 200 {
		t.Fatalf("健康检查失败：%d %s", rec.Code, rec.Body.String())
	}
	var checked clusterNodeRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &checked)
	if checked.Status != "ok" || checked.LatencyMs < 0 {
		t.Fatalf("健康检查结果异常：%+v", checked)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/clusters/x", nil, "viewer")
	req.SetPathValue("id", strconv.FormatInt(clusterCreated.ID, 10))
	app.handleClusterDetail(rec, req)
	if rec.Code != 200 {
		t.Fatalf("读取集群详情失败：%d %s", rec.Code, rec.Body.String())
	}
	var detail clusterDetail
	_ = json.Unmarshal(rec.Body.Bytes(), &detail)
	if detail.Cluster.Name != "prod-a" || len(detail.Nodes) != 1 || detail.Cluster.ProjectName != "核心交易" {
		t.Fatalf("集群详情异常：%+v", detail)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "DELETE", "/api/v1/projects/x", nil, "admin")
	req.SetPathValue("id", strconv.FormatInt(created.ID, 10))
	app.handleProjectDelete(rec, req)
	if rec.Code != 200 {
		t.Fatalf("删除项目失败：%d %s", rec.Code, rec.Body.String())
	}
	var clusters int
	_ = app.db.QueryRow(`SELECT COUNT(*) FROM clusters`).Scan(&clusters)
	if clusters != 0 {
		t.Fatalf("删除项目后集群未清理：%d", clusters)
	}
}

func TestClusterHTTPCheckSecurityBoundaries(t *testing.T) {
	app := newRuntimeTestApp(t)
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data",
		"http://100.100.100.200/latest/meta-data",
		"http://metadata.google.internal/computeMetadata/v1",
	} {
		status, _, _ := app.checkClusterNode(context.Background(), clusterNodeRecord{Role: "backend", CheckType: "http", URL: target})
		if status != "failed" {
			t.Fatalf("元数据地址 %q 应检查失败", target)
		}
		if _, err := normalizeClusterNode("node", "backend", "", 0, target, 0, "http", "", ""); err == nil {
			t.Fatalf("节点地址 %q 应在保存时被拒绝", target)
		}
	}

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("internal-response-secret"))
	}))
	defer health.Close()
	status, _, detail := app.checkClusterNode(context.Background(), clusterNodeRecord{Role: "backend", CheckType: "http", URL: health.URL})
	if status != "ok" || detail != "HTTP 200" || strings.Contains(detail, "internal-response-secret") {
		t.Fatalf("健康检查不应返回响应正文：status=%s detail=%q", status, detail)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirect.Close()
	status, _, detail = app.checkClusterNode(context.Background(), clusterNodeRecord{Role: "backend", CheckType: "http", URL: redirect.URL})
	if status != "failed" || !strings.Contains(detail, "重定向目标不安全") {
		t.Fatalf("重定向到元数据地址应被阻断：status=%s detail=%q", status, detail)
	}
}

func TestClusterJobRunsAsync(t *testing.T) {
	app := newRuntimeTestApp(t)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer health.Close()

	res, err := app.db.Exec(`INSERT INTO projects(name, description, owner, created_at, updated_at)
		VALUES('项目 J','','tester','','')`)
	if err != nil {
		t.Fatalf("写入项目失败：%v", err)
	}
	projectID, _ := res.LastInsertId()
	res, err = app.db.Exec(`INSERT INTO clusters(project_id, name, environment, provider, region, description, created_at, updated_at)
		VALUES(?,'cluster-j','prod','','','','','')`, projectID)
	if err != nil {
		t.Fatalf("写入集群失败：%v", err)
	}
	clusterID, _ := res.LastInsertId()
	if _, err := app.db.Exec(`INSERT INTO cluster_nodes(cluster_id, name, role, host, port, url, ssh_host_id,
		check_type, path, note, status, latency_ms, detail, checked_at, created_at, updated_at)
		VALUES(?,'backend-j','backend','',0,?,0,'http','','','unknown',0,'','','','')`, clusterID, health.URL); err != nil {
		t.Fatalf("写入节点失败：%v", err)
	}

	job, err := app.startClusterJob(context.Background(), clusterID, "check", "tester")
	if err != nil {
		t.Fatalf("创建任务失败：%v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := app.clusterJobByID(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("读取任务失败：%v", err)
		}
		if current.Status != "queued" && current.Status != "running" {
			if current.Status != "succeeded" || current.Done != 1 || len(current.Items) != 1 || current.Items[0].Status != "ok" {
				t.Fatalf("任务结果异常：%+v", current)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("任务未在预期时间内完成")
}

func TestClusterNodeDBConfigEncrypted(t *testing.T) {
	app := newRuntimeTestApp(t)
	res, err := app.db.Exec(`INSERT INTO projects(name, description, owner, created_at, updated_at)
		VALUES('项目 D','','tester','','')`)
	if err != nil {
		t.Fatalf("写入项目失败：%v", err)
	}
	projectID, _ := res.LastInsertId()
	res, err = app.db.Exec(`INSERT INTO clusters(project_id, name, environment, provider, region, description, created_at, updated_at)
		VALUES(?,'cluster-d','prod','','','','','')`, projectID)
	if err != nil {
		t.Fatalf("写入集群失败：%v", err)
	}
	clusterID, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "POST", "/api/v1/clusters/x/nodes", map[string]any{
		"name": "mysql-1", "role": "database", "host": "127.0.0.1", "port": 3306,
		"dbEngine": "mysql", "dbName": "app", "dbUser": "vuln_readonly", "dbPassword": "s3cret-pass",
	}, "operator")
	req.SetPathValue("id", strconv.FormatInt(clusterID, 10))
	app.handleClusterNodeCreate(rec, req)
	if rec.Code != 201 {
		t.Fatalf("创建数据库节点失败：%d %s", rec.Code, rec.Body.String())
	}

	var nodeID int64
	var sealed, engine, user string
	if err := app.db.QueryRow(`SELECT id, db_secret, db_engine, db_user FROM cluster_nodes WHERE name = 'mysql-1'`).
		Scan(&nodeID, &sealed, &engine, &user); err != nil {
		t.Fatalf("读取数据库节点失败：%v", err)
	}
	if sealed == "" || sealed == "s3cret-pass" {
		t.Fatalf("数据库密码未加密存储：%q", sealed)
	}
	if engine != "mysql" || user != "vuln_readonly" {
		t.Fatalf("数据库配置未保存：%s %s", engine, user)
	}
	node, err := app.getClusterNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("读取节点失败：%v", err)
	}
	if !node.HasDBSecret || node.dbSecret == "s3cret-pass" {
		t.Fatalf("节点凭据标记异常：%+v", node)
	}
	plain, err := app.openSSHSecret(node.dbSecret)
	if err != nil || plain != "s3cret-pass" {
		t.Fatalf("凭据解密失败：%v %q", err, plain)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "PATCH", "/api/v1/cluster-nodes/x", map[string]any{"clearDbSecret": true}, "operator")
	req.SetPathValue("id", strconv.FormatInt(nodeID, 10))
	app.handleClusterNodeUpdate(rec, req)
	if rec.Code != 200 {
		t.Fatalf("清除凭据失败：%d %s", rec.Code, rec.Body.String())
	}
	var cleared string
	_ = app.db.QueryRow(`SELECT db_secret FROM cluster_nodes WHERE id = ?`, nodeID).Scan(&cleared)
	if cleared != "" {
		t.Fatalf("凭据未清除：%q", cleared)
	}
}

func TestBuildDatabaseDSN(t *testing.T) {
	mysqlNode := clusterNodeRecord{DBEngine: "mysql", Host: "127.0.0.1", Port: 3306, DBUser: "ro", DBName: "app", DBSSLMode: "require"}
	driver, dsn := buildDatabaseDSN(mysqlNode, "p@ss word")
	if driver != "mysql" || !strings.Contains(dsn, "tls=skip-verify") || !strings.Contains(dsn, "app") {
		t.Fatalf("MySQL DSN 异常：%s %s", driver, dsn)
	}
	pgNode := clusterNodeRecord{DBEngine: "postgresql", Host: "10.0.0.2", Port: 5432, DBUser: "ro", DBName: "", DBSSLMode: "disable"}
	driver, dsn = buildDatabaseDSN(pgNode, "secret")
	if driver != "postgres" || !strings.Contains(dsn, "/postgres") || !strings.Contains(dsn, "sslmode=disable") {
		t.Fatalf("PostgreSQL DSN 异常：%s %s", driver, dsn)
	}
}

func TestClusterHealthSnapshotAndCheckTool(t *testing.T) {
	app := newRuntimeTestApp(t)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer health.Close()

	res, err := app.db.Exec(`INSERT INTO projects(name, description, owner, created_at, updated_at)
		VALUES('项目 H','','tester','','')`)
	if err != nil {
		t.Fatalf("写入项目失败：%v", err)
	}
	projectID, _ := res.LastInsertId()
	res, err = app.db.Exec(`INSERT INTO clusters(project_id, name, environment, provider, region, description, created_at, updated_at)
		VALUES(?,'cluster-h','prod','','','','','')`, projectID)
	if err != nil {
		t.Fatalf("写入集群失败：%v", err)
	}
	clusterID, _ := res.LastInsertId()
	if _, err := app.db.Exec(`INSERT INTO cluster_nodes(cluster_id, name, role, host, port, url, ssh_host_id,
		check_type, path, note, status, latency_ms, detail, checked_at, created_at, updated_at)
		VALUES(?,'backend-h','backend','',0,?,0,'http','','','unknown',0,'','','','')`, clusterID, health.URL); err != nil {
		t.Fatalf("写入节点失败：%v", err)
	}

	snapshots, err := app.clusterHealthSnapshots(context.Background())
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("集群快照异常：%+v / %v", snapshots, err)
	}
	if snapshots[0].NodeCount != 1 || len(snapshots[0].Nodes) != 1 || snapshots[0].Nodes[0].Name != "backend-h" {
		t.Fatalf("集群节点快照异常：%+v", snapshots[0])
	}

	tool := app.toolCheckCluster()
	out, err := tool.Run(json.RawMessage(fmt.Sprintf(`{"clusterId":%d}`, clusterID)))
	if err != nil {
		t.Fatalf("集群检查工具失败：%v", err)
	}
	payload, _ := out.(map[string]any)
	summary, _ := payload["summary"].(map[string]int)
	if summary["healthy"] != 1 || summary["failed"] != 0 {
		t.Fatalf("集群检查结果异常：%+v", payload)
	}
	var status string
	_ = app.db.QueryRow(`SELECT status FROM cluster_nodes WHERE cluster_id = ?`, clusterID).Scan(&status)
	if status != "ok" {
		t.Fatalf("节点状态未更新：%s", status)
	}
}

func TestClusterScanLinksAsset(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	app := newRuntimeTestApp(t)
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatalf("加密凭据失败：%v", err)
	}
	res, err := app.db.Exec(`INSERT INTO ssh_hosts(name, host, port, username, auth_type, secret, passphrase,
		host_key, note, tags, created_by, created_at, updated_at, last_connected_at)
		VALUES('scan-host', ?, ?, 'tester', 'password', ?, '', ?, '', '', 'tester', '', '', '')`,
		host, port, sealed, fingerprint)
	if err != nil {
		t.Fatalf("写入 SSH 主机失败：%v", err)
	}
	sshHostID, _ := res.LastInsertId()

	res, err = app.db.Exec(`INSERT INTO projects(name, description, owner, created_at, updated_at)
		VALUES('项目 A','','tester','','')`)
	if err != nil {
		t.Fatalf("写入项目失败：%v", err)
	}
	projectID, _ := res.LastInsertId()
	res, err = app.db.Exec(`INSERT INTO clusters(project_id, name, environment, provider, region, description, created_at, updated_at)
		VALUES(?,'cluster-a','prod','','','','','')`, projectID)
	if err != nil {
		t.Fatalf("写入集群失败：%v", err)
	}
	clusterID, _ := res.LastInsertId()
	res, err = app.db.Exec(`INSERT INTO cluster_nodes(cluster_id, name, role, host, port, url, ssh_host_id,
		check_type, path, note, status, latency_ms, detail, checked_at, created_at, updated_at)
		VALUES(?,'target-1','scan_target','',0,'',?,'ssh','','','unknown',0,'','','','')`, clusterID, sshHostID)
	if err != nil {
		t.Fatalf("写入节点失败：%v", err)
	}
	nodeID, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "POST", "/api/v1/cluster-nodes/x/scan", nil, "operator")
	req.SetPathValue("id", strconv.FormatInt(nodeID, 10))
	app.handleClusterNodeScan(rec, req)
	if rec.Code != 200 {
		t.Fatalf("节点扫描失败：%d %s", rec.Code, rec.Body.String())
	}

	var assetID int64
	if err := app.db.QueryRow(`SELECT id FROM assets WHERE hostname = ?`, host).Scan(&assetID); err != nil {
		t.Fatalf("扫描未生成资产：%v", err)
	}
	var clusterOfAsset int64
	_ = app.db.QueryRow(`SELECT cluster_id FROM assets WHERE id = ?`, assetID).Scan(&clusterOfAsset)
	if clusterOfAsset != clusterID {
		t.Fatalf("扫描资产未关联集群：%d != %d", clusterOfAsset, clusterID)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/clusters/x", nil, "viewer")
	req.SetPathValue("id", strconv.FormatInt(clusterID, 10))
	app.handleClusterDetail(rec, req)
	var detail clusterDetail
	_ = json.Unmarshal(rec.Body.Bytes(), &detail)
	if detail.Cluster.AssetCount != 1 || len(detail.Assets) != 1 {
		t.Fatalf("集群资产统计异常：%+v", detail.Cluster)
	}
}
