package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
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
