package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"vulnagent/server/internal/domain/risk"
)

func newCatalogTestApp(t *testing.T) *App {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &App{db: db}
}

func newCatalogRequest(t *testing.T, method, target string, body any, role string) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求失败：%v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: "tester", Name: "测试员", Role: role}))
}

func TestBusinessTierRecompute(t *testing.T) {
	app := newCatalogTestApp(t)
	now := fmtT(nowT())
	res, err := app.db.Exec(`INSERT INTO assets(hostname, ip, business_system, exposure, tier, source, last_seen_at)
		VALUES('biz-host','10.0.0.8','交易系统','public','core','agent',?)`, now)
	if err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}
	assetID, _ := res.LastInsertId()
	if _, err := app.db.Exec(`INSERT INTO findings(asset_id, purl, component_name, component_version, cve_id,
		cvss, epss, exploit, asset_weight, risk, priority, score_breakdown, first_seen, last_seen)
		VALUES(?,'pkg:npm/x@1.0.0','x','1.0.0','CVE-TEST-BIZ',9.8,0.9,'kev',0.8,90,'P0','[]',?,?)`,
		assetID, now, now); err != nil {
		t.Fatalf("写入漏洞失败：%v", err)
	}

	// 一般业务系统：默认系数 0.8
	rec := httptest.NewRecorder()
	app.handleBusinessSystemUpsert(rec, withPathValue(
		newCatalogRequest(t, "PUT", "/api/v1/business-systems/x",
			map[string]any{"tier": "normal"}, "admin"), "name", "交易系统"))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存业务系统失败：%d %s", rec.Code, rec.Body.String())
	}
	var normalRisk int
	if err := app.db.QueryRow(`SELECT risk FROM findings WHERE asset_id = ?`, assetID).Scan(&normalRisk); err != nil {
		t.Fatalf("读取风险分失败：%v", err)
	}

	// 核心业务系统：系数 1.0，风险分应上升
	rec = httptest.NewRecorder()
	app.handleBusinessSystemUpsert(rec, withPathValue(
		newCatalogRequest(t, "PUT", "/api/v1/business-systems/x",
			map[string]any{"tier": "core"}, "admin"), "name", "交易系统"))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存业务系统失败：%d %s", rec.Code, rec.Body.String())
	}
	var coreRisk int
	if err := app.db.QueryRow(`SELECT risk FROM findings WHERE asset_id = ?`, assetID).Scan(&coreRisk); err != nil {
		t.Fatalf("读取风险分失败：%v", err)
	}
	want, _, _ := risk.DefaultPolicy().Score(9.8, 0.9, "kev", "public", "core", "core")
	if coreRisk != want {
		t.Fatalf("核心业务系统风险分 = %d，期望 %d", coreRisk, want)
	}
	if coreRisk <= normalRisk {
		t.Fatalf("核心业务系统风险分应高于一般：core=%d normal=%d", coreRisk, normalRisk)
	}

	rec = httptest.NewRecorder()
	app.handleBusinessSystems(rec, newCatalogRequest(t, "GET", "/api/v1/business-systems", nil, "viewer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("查询业务系统失败：%d", rec.Code)
	}
	var list struct {
		Items []struct {
			Name       string `json:"name"`
			Tier       string `json:"tier"`
			AssetCount int    `json:"assetCount"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("业务系统列表异常：%v %s", err, rec.Body.String())
	}
	if list.Items[0].Tier != "core" || list.Items[0].AssetCount != 1 {
		t.Fatalf("业务系统列表内容异常：%+v", list.Items[0])
	}
}

func TestAssetBatchUpdate(t *testing.T) {
	app := newCatalogTestApp(t)
	now := fmtT(nowT())
	for _, host := range []string{"batch-a", "batch-b"} {
		if _, err := app.db.Exec(`INSERT INTO assets(hostname, owner, source, last_seen_at) VALUES(?, '', 'agent', ?)`, host, now); err != nil {
			t.Fatalf("写入资产失败：%v", err)
		}
	}

	rec := httptest.NewRecorder()
	app.handleAssetBatch(rec, newCatalogRequest(t, "POST", "/api/v1/assets/batch", map[string]any{
		"ids":   []int64{1, 2},
		"patch": map[string]any{"owner": "王五", "department": "基础架构", "status": "retired"},
	}, "operator"))
	if rec.Code != http.StatusOK {
		t.Fatalf("批量更新失败：%d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Updated int `json:"updated"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result.Updated != 2 {
		t.Fatalf("应更新 2 台资产：%s", rec.Body.String())
	}
	detail, err := app.assetRepo().Detail(context.Background(), 1)
	if err != nil || detail.Owner != "王五" || detail.Status != "retired" || detail.Department != "基础架构" {
		t.Fatalf("批量字段未生效：%+v err=%v", detail, err)
	}

	rec = httptest.NewRecorder()
	app.handleAssetBatch(rec, newCatalogRequest(t, "POST", "/api/v1/assets/batch", map[string]any{
		"ids": []int64{1}, "patch": map[string]any{"status": "invalid"},
	}, "operator"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法状态应返回 400，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.handleAssetBatch(rec, newCatalogRequest(t, "POST", "/api/v1/assets/batch", map[string]any{
		"ids": []int64{1}, "patch": map[string]any{"owner": "x"},
	}, "viewer"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 批量更新应返回 403，实际 %d", rec.Code)
	}
}

func TestRelationEndpoints(t *testing.T) {
	app := newCatalogTestApp(t)
	now := fmtT(nowT())
	for _, host := range []string{"rel-a", "rel-b"} {
		if _, err := app.db.Exec(`INSERT INTO assets(hostname, source, last_seen_at) VALUES(?, 'agent', ?)`, host, now); err != nil {
			t.Fatalf("写入资产失败：%v", err)
		}
	}

	req := withPathValue(newCatalogRequest(t, "POST", "/api/v1/assets/1/relations",
		map[string]any{"toAssetId": 2, "relation": "depends_on"}, "operator"), "id", "1")
	rec := httptest.NewRecorder()
	app.handleAssetRelationCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("创建关系失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleAssetRelations(rec, withPathValue(newCatalogRequest(t, "GET", "/api/v1/assets/1/relations", nil, "viewer"), "id", "1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("查询关系失败：%d", rec.Code)
	}
	var list struct {
		Items []struct {
			ID        int64  `json:"id"`
			Direction string `json:"direction"`
			Asset     struct {
				Hostname string `json:"hostname"`
			} `json:"asset"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("关系列表异常：%v %s", err, rec.Body.String())
	}
	if list.Items[0].Direction != "out" || list.Items[0].Asset.Hostname != "rel-b" {
		t.Fatalf("关系内容异常：%+v", list.Items[0])
	}

	// 自身关系与非法关系类型应被拒绝
	req = withPathValue(newCatalogRequest(t, "POST", "/api/v1/assets/1/relations",
		map[string]any{"toAssetId": 1, "relation": "depends_on"}, "operator"), "id", "1")
	rec = httptest.NewRecorder()
	app.handleAssetRelationCreate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("自身关系应返回 400，实际 %d", rec.Code)
	}
	req = withPathValue(newCatalogRequest(t, "POST", "/api/v1/assets/1/relations",
		map[string]any{"toAssetId": 2, "relation": "unknown"}, "operator"), "id", "1")
	rec = httptest.NewRecorder()
	app.handleAssetRelationCreate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法关系类型应返回 400，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.handleAssetRelationDelete(rec, withPathValue(
		newCatalogRequest(t, "DELETE", "/api/v1/assets/relations/1", nil, "operator"), "id", "1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("删除关系失败：%d", rec.Code)
	}
}

func TestTopologyEndpoint(t *testing.T) {
	app := newCatalogTestApp(t)
	now := fmtT(nowT())
	for _, item := range []struct{ host, business, env string }{
		{"topo-a", "交易系统", "prod"},
		{"topo-b", "交易系统", "prod"},
		{"topo-c", "订单系统", "dev"},
	} {
		if _, err := app.db.Exec(`INSERT INTO assets(hostname, business_system, env, source, last_seen_at)
			VALUES(?,?,?, 'agent', ?)`, item.host, item.business, item.env, now); err != nil {
			t.Fatalf("写入资产失败：%v", err)
		}
	}
	if _, err := app.db.Exec(`INSERT INTO asset_relations(from_asset_id, to_asset_id, relation, created_at)
		VALUES(1,2,'depends_on',?)`, now); err != nil {
		t.Fatalf("写入关系失败：%v", err)
	}

	params := url.Values{}
	params.Set("businessSystem", "交易系统")
	params.Set("env", "prod")
	rec := httptest.NewRecorder()
	app.handleTopology(rec, newCatalogRequest(t, "GET", "/api/v1/topology?"+params.Encode(), nil, "viewer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("拓扑查询失败：%d %s", rec.Code, rec.Body.String())
	}
	var topo struct {
		Assets []struct {
			Hostname string `json:"hostname"`
		} `json:"assets"`
		Relations []struct {
			Relation string `json:"relation"`
		} `json:"relations"`
		BusinessSystems []struct {
			Name string `json:"name"`
		} `json:"businessSystems"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &topo); err != nil {
		t.Fatalf("解析拓扑失败：%v %s", err, rec.Body.String())
	}
	if len(topo.Assets) != 2 || len(topo.Relations) != 1 || topo.Truncated {
		t.Fatalf("拓扑筛选异常：assets=%d relations=%d truncated=%v", len(topo.Assets), len(topo.Relations), topo.Truncated)
	}
	if len(topo.BusinessSystems) != 2 {
		t.Fatalf("业务系统列表应为 2 个，实际 %d", len(topo.BusinessSystems))
	}
}

func TestGovernanceEndpoints(t *testing.T) {
	app := newCatalogTestApp(t)
	now := fmtT(nowT())
	if _, err := app.db.Exec(`INSERT INTO assets(hostname, owner, source, last_seen_at) VALUES('gov-a','', 'agent', ?)`, now); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}

	rec := httptest.NewRecorder()
	app.handleGovernanceSummary(rec, newCatalogRequest(t, "GET", "/api/v1/governance/summary", nil, "viewer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("治理汇总失败：%d %s", rec.Code, rec.Body.String())
	}
	var summary struct {
		Summary struct {
			OwnerMissing int `json:"ownerMissing"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &summary)
	if summary.Summary.OwnerMissing != 1 {
		t.Fatalf("责任人缺失统计异常：%s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleGovernanceTodos(rec, newCatalogRequest(t, "GET", "/api/v1/governance/todos?type=owner_missing", nil, "viewer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("治理列表失败：%d %s", rec.Code, rec.Body.String())
	}
	var todos struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &todos)
	if todos.Total != 1 {
		t.Fatalf("责任人缺失待办应为 1，实际 %d", todos.Total)
	}

	rec = httptest.NewRecorder()
	app.handleGovernanceTodos(rec, newCatalogRequest(t, "GET", "/api/v1/governance/todos?type=unknown", nil, "viewer"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法类型应返回 400，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.handleAssetBatch(rec, newCatalogRequest(t, "POST", "/api/v1/assets/batch", map[string]any{
		"ids": []int64{1}, "patch": map[string]any{"owner": "赵六"},
	}, "operator"))
	if rec.Code != http.StatusOK {
		t.Fatalf("批量分配责任人失败：%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	app.handleGovernanceSummary(rec, newCatalogRequest(t, "GET", "/api/v1/governance/summary", nil, "viewer"))
	_ = json.Unmarshal(rec.Body.Bytes(), &summary)
	if summary.Summary.OwnerMissing != 0 {
		t.Fatalf("分配责任人后统计应归零：%s", rec.Body.String())
	}
}

// withPathValue 设置 ServeMux 路径参数
func withPathValue(req *http.Request, key, value string) *http.Request {
	req.SetPathValue(key, value)
	return req
}
