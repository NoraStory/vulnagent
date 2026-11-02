package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestAssetSSHLinkReusesExistingHost(t *testing.T) {
	app := newRuntimeTestApp(t)

	res, err := app.db.Exec(`INSERT INTO assets (hostname, ip) VALUES (?, ?)`, "web-01", "10.20.1.11")
	if err != nil {
		t.Fatalf("写入测试资产失败：%v", err)
	}
	assetID, _ := res.LastInsertId()
	pathID := strconv.FormatInt(assetID, 10)

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "GET", "/api/v1/assets/x/ssh-host", nil, "viewer")
	req.SetPathValue("id", pathID)
	app.handleAssetSSHHost(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未关联时应返回 404，实际 %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/assets/x/ssh-host", map[string]any{
		"username": "root",
		"port":     22,
		"password": "secret-pass",
	}, "operator")
	req.SetPathValue("id", pathID)
	app.handleAssetSSHHostLink(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("首次关联应创建 SSH 主机：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Host struct {
			ID   int64  `json:"id"`
			Host string `json:"host"`
		} `json:"host"`
		Created bool `json:"created"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("解析创建结果失败：%v", err)
	}
	if !created.Created || created.Host.ID == 0 || created.Host.Host != "10.20.1.11" {
		t.Fatalf("首次关联结果异常：%+v", created)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "POST", "/api/v1/assets/x/ssh-host", map[string]any{
		"username": "root",
		"port":     22,
		"password": "secret-pass-new",
	}, "operator")
	req.SetPathValue("id", pathID)
	app.handleAssetSSHHostLink(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("重复关联应复用已有主机：%d %s", rec.Code, rec.Body.String())
	}
	var reused struct {
		Host struct {
			ID int64 `json:"id"`
		} `json:"host"`
		Created bool `json:"created"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &reused)
	if reused.Created || reused.Host.ID != created.Host.ID {
		t.Fatalf("重复关联不应新建主机：%+v", reused)
	}

	var count int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM ssh_hosts`).Scan(&count); err != nil {
		t.Fatalf("统计 SSH 主机失败：%v", err)
	}
	if count != 1 {
		t.Fatalf("重复关联产生了 %d 台 SSH 主机，期望 1 台", count)
	}

	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/assets/x/ssh-host", nil, "viewer")
	req.SetPathValue("id", pathID)
	app.handleAssetSSHHost(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("关联后应能查询到 SSH 主机：%d %s", rec.Code, rec.Body.String())
	}
}
