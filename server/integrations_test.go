package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"vulnagent/server/internal/application/ports"
)

func newIntegrationTestApp(t *testing.T) *App {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "integrations.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &App{db: db, dataDir: t.TempDir()}
}

func TestIntegrationSourceCRUD(t *testing.T) {
	app := newIntegrationTestApp(t)

	rec := httptest.NewRecorder()
	app.handleIntegrations(rec, newCatalogRequest(t, "POST", "/api/v1/integrations", map[string]any{
		"kind": "cmdb_api", "name": "外部 CMDB",
		"config":          map[string]any{"url": "http://127.0.0.1:1/assets", "authType": "none"},
		"intervalMinutes": 60,
	}, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建集成源失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Item struct {
			ID            int64  `json:"id"`
			Kind          string `json:"kind"`
			HasCredential bool   `json:"hasCredential"`
		} `json:"item"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Item.ID == 0 {
		t.Fatalf("解析创建结果失败：%v %s", err, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleIntegrations(rec, newCatalogRequest(t, "GET", "/api/v1/integrations", nil, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("查询集成源失败：%d", rec.Code)
	}
	var list struct {
		Items []map[string]any `json:"items"`
		Kinds []string         `json:"kinds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("集成源列表异常：%v %s", err, rec.Body.String())
	}
	if _, exists := list.Items[0]["secret"]; exists {
		t.Fatal("列表不应返回凭据密文")
	}
	if len(list.Kinds) != 4 {
		t.Fatalf("应返回 4 种集成类型，实际 %d", len(list.Kinds))
	}

	rec = httptest.NewRecorder()
	app.handleIntegrationUpdate(rec, withPathValue(newCatalogRequest(t, "PUT", "/api/v1/integrations/x", map[string]any{
		"name": "外部 CMDB（停用）", "enabled": false, "intervalMinutes": 120,
	}, "admin"), "id", strconv.FormatInt(created.Item.ID, 10)))
	if rec.Code != http.StatusOK {
		t.Fatalf("更新集成源失败：%d %s", rec.Code, rec.Body.String())
	}
	src, err := app.integrationRepo().Get(context.Background(), created.Item.ID)
	if err != nil || src.Enabled || src.IntervalMinutes != 120 || src.Name != "外部 CMDB（停用）" {
		t.Fatalf("更新未生效：%+v err=%v", src, err)
	}

	rec = httptest.NewRecorder()
	app.handleIntegrationUpdate(rec, withPathValue(newCatalogRequest(t, "DELETE", "/api/v1/integrations/x", nil, "admin"),
		"id", strconv.FormatInt(created.Item.ID, 10)))
	if rec.Code != http.StatusOK {
		t.Fatalf("删除集成源失败：%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	app.handleIntegrations(rec, newCatalogRequest(t, "GET", "/api/v1/integrations", nil, "operator"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator 查询集成源应返回 403，实际 %d", rec.Code)
	}
}

func TestIntegrationCMDBSyncEndToEnd(t *testing.T) {
	app := newIntegrationTestApp(t)

	var payload atomic.Value
	payload.Store(`{"items":[
	  {"id":"cmdb-1","hostname":"cmdb-web-01","private_ip":"10.9.0.11","os":"Ubuntu 22.04",
	   "business_system":"交易系统","tags":{"env":"prod"},"serial":"SN-CMDB-01"},
	  {"id":"cmdb-2","hostname":"cmdb-db-01","private_ip":"10.9.0.12","os":"Rocky Linux 9","owner":"李四"}
	]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload.Load().(string)))
	}))
	defer server.Close()

	rec := httptest.NewRecorder()
	app.handleIntegrations(rec, newCatalogRequest(t, "POST", "/api/v1/integrations", map[string]any{
		"kind": "cmdb_api", "name": "测试 CMDB",
		"config":      map[string]any{"url": server.URL, "authType": "bearer"},
		"credentials": map[string]string{"token": "secret-token"},
	}, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建集成源失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Item struct {
			ID int64 `json:"id"`
		} `json:"item"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	sourcePath := strconv.FormatInt(created.Item.ID, 10)

	// 只读测试：返回样例但不写资产
	rec = httptest.NewRecorder()
	app.handleIntegrationTest(rec, withPathValue(newCatalogRequest(t, "POST", "/api/v1/integrations/x/test", nil, "admin"), "id", sourcePath))
	if rec.Code != http.StatusOK {
		t.Fatalf("测试集成失败：%d %s", rec.Code, rec.Body.String())
	}
	var testResult struct {
		OK     bool  `json:"ok"`
		Count  int   `json:"count"`
		Sample []any `json:"sample"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &testResult); err != nil || !testResult.OK || testResult.Count != 2 || len(testResult.Sample) != 2 {
		t.Fatalf("测试结果异常：%v %s", err, rec.Body.String())
	}
	if _, total, _ := app.assetRepo().List(context.Background(), ports.AssetFilter{}, 10, 0); total != 0 {
		t.Fatalf("测试模式不应写入资产，实际 %d", total)
	}

	// 首次同步：创建 2 台
	rec = httptest.NewRecorder()
	app.handleIntegrationSync(rec, withPathValue(newCatalogRequest(t, "POST", "/api/v1/integrations/x/sync", nil, "admin"), "id", sourcePath))
	if rec.Code != http.StatusOK {
		t.Fatalf("同步失败：%d %s", rec.Code, rec.Body.String())
	}
	var syncResult struct {
		OK    bool                 `json:"ok"`
		Stats integrationSyncStats `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &syncResult); err != nil || !syncResult.OK {
		t.Fatalf("同步结果异常：%v %s", err, rec.Body.String())
	}
	if syncResult.Stats.Fetched != 2 || syncResult.Stats.Created != 2 || syncResult.Stats.Failed != 0 {
		t.Fatalf("首次同步统计异常：%+v", syncResult.Stats)
	}
	web, found, err := app.assetRepo().FindByHostname(context.Background(), "cmdb-web-01")
	if err != nil || !found {
		t.Fatalf("同步后未找到资产：%v", err)
	}
	detail, _ := app.assetRepo().Detail(context.Background(), web)
	if detail.Source != "cloud" || detail.CloudProvider != "cmdb" || detail.CloudAccount != "测试 CMDB" ||
		detail.BusinessSystem != "交易系统" || detail.Env != "prod" {
		t.Fatalf("云同步资产字段异常：%+v", detail)
	}
	identifiers, _ := app.assetRepo().Identifiers(context.Background(), web)
	if len(identifiers) < 4 {
		t.Fatalf("云标识未写入：%+v", identifiers)
	}
	src, _ := app.integrationRepo().Get(context.Background(), created.Item.ID)
	if src.LastStatus != "ok" || src.LastCount != 2 {
		t.Fatalf("同步状态未记录：%+v", src)
	}

	// 第二次同步：owner 变更，仅更新不新增
	payload.Store(`{"items":[
	  {"id":"cmdb-1","hostname":"cmdb-web-01","private_ip":"10.9.0.11","os":"Ubuntu 22.04",
	   "business_system":"交易系统","owner":"王五","tags":{"env":"prod"},"serial":"SN-CMDB-01"},
	  {"id":"cmdb-2","hostname":"cmdb-db-01","private_ip":"10.9.0.12","os":"Rocky Linux 9","owner":"李四"}
	]}`)
	rec = httptest.NewRecorder()
	app.handleIntegrationSync(rec, withPathValue(newCatalogRequest(t, "POST", "/api/v1/integrations/x/sync", nil, "admin"), "id", sourcePath))
	if rec.Code != http.StatusOK {
		t.Fatalf("二次同步失败：%d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &syncResult)
	if syncResult.Stats.Created != 0 || syncResult.Stats.Updated < 1 {
		t.Fatalf("二次同步统计异常：%+v", syncResult.Stats)
	}
	if _, total, _ := app.assetRepo().List(context.Background(), ports.AssetFilter{}, 10, 0); total != 2 {
		t.Fatalf("二次同步不应新增资产，实际 %d", total)
	}
	detail, _ = app.assetRepo().Detail(context.Background(), web)
	if detail.Owner != "王五" {
		t.Fatalf("owner 未更新：%+v", detail)
	}
}

func TestIntegrationSyncFailureRecorded(t *testing.T) {
	app := newIntegrationTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	rec := httptest.NewRecorder()
	app.handleIntegrations(rec, newCatalogRequest(t, "POST", "/api/v1/integrations", map[string]any{
		"kind": "cmdb_api", "name": "故障 CMDB",
		"config": map[string]any{"url": server.URL, "authType": "none"},
	}, "admin"))
	var created struct {
		Item struct {
			ID int64 `json:"id"`
		} `json:"item"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = httptest.NewRecorder()
	app.handleIntegrationSync(rec, withPathValue(newCatalogRequest(t, "POST", "/api/v1/integrations/x/sync", nil, "admin"),
		"id", strconv.FormatInt(created.Item.ID, 10)))
	if rec.Code != http.StatusOK {
		t.Fatalf("同步失败应返回可读结果：%d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result.OK || result.Error == "" {
		t.Fatalf("同步失败结果异常：%s", rec.Body.String())
	}
	src, _ := app.integrationRepo().Get(context.Background(), created.Item.ID)
	if src.LastStatus != "failed" || src.LastError == "" {
		t.Fatalf("失败状态未记录：%+v", src)
	}
}

func TestValidateIntegrationCMDMPagination(t *testing.T) {
	base := map[string]any{"url": "https://cmdb.example.com/api/assets", "authType": "none"}
	if err := validateIntegration("cmdb_api", base, nil, false); err != nil {
		t.Fatalf("默认配置应通过校验：%v", err)
	}
	for _, mode := range []string{"auto", "none", "page", "cursor"} {
		config := map[string]any{"url": "https://cmdb.example.com/api/assets", "pagination": mode}
		if err := validateIntegration("cmdb_api", config, nil, false); err != nil {
			t.Fatalf("分页方式 %s 应通过校验：%v", mode, err)
		}
	}
	invalid := map[string]any{"url": "https://cmdb.example.com/api/assets", "pagination": "offset"}
	if err := validateIntegration("cmdb_api", invalid, nil, false); err == nil {
		t.Fatal("未知分页方式应被拒绝")
	}
	tooLarge := map[string]any{"url": "https://cmdb.example.com/api/assets", "pagination": "page", "pageSize": float64(5000)}
	if err := validateIntegration("cmdb_api", tooLarge, nil, false); err == nil {
		t.Fatal("超大页大小应被拒绝")
	}
	tooMany := map[string]any{"url": "https://cmdb.example.com/api/assets", "maxPages": "9999"}
	if err := validateIntegration("cmdb_api", tooMany, nil, false); err == nil {
		t.Fatal("超大翻页数应被拒绝")
	}
}
