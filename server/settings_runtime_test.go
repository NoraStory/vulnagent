package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRuntimeTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "settings.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &App{db: db, dataDir: dir}
}

func TestRuntimeSettingsRolesAndSecrets(t *testing.T) {
	app := newRuntimeTestApp(t)
	t.Cleanup(func() {
		_ = os.Unsetenv("VA_LLM_BASE_URL")
		_ = os.Unsetenv("VA_LLM_API_KEY")
		_ = os.Unsetenv("VA_LLM_MODEL")
	})

	// 运维可修改模型名称
	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "PUT", "/api/v1/settings/runtime",
		map[string]any{"values": map[string]string{"VA_LLM_MODEL": "ops-model"}}, "operator")
	app.handleRuntimeSettingsUpdate(rec, req)
	if rec.Code != 200 {
		t.Fatalf("运维修改模型名称失败：%d %s", rec.Code, rec.Body.String())
	}
	if os.Getenv("VA_LLM_MODEL") != "ops-model" {
		t.Fatalf("模型名称未写入环境")
	}

	// 运维不能修改管理员专属的模型地址
	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "PUT", "/api/v1/settings/runtime",
		map[string]any{"values": map[string]string{"VA_LLM_BASE_URL": "https://example.com/v1"}}, "operator")
	app.handleRuntimeSettingsUpdate(rec, req)
	if rec.Code != 403 {
		t.Fatalf("越权修改应返回 403，实际 %d", rec.Code)
	}

	// 管理员保存地址与密钥
	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "PUT", "/api/v1/settings/runtime", map[string]any{"values": map[string]string{
		"VA_LLM_BASE_URL": "https://example.com/v1",
		"VA_LLM_API_KEY":  "sk-secret",
	}}, "admin")
	app.handleRuntimeSettingsUpdate(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "restartRequired") {
		t.Fatalf("管理员保存失败：%d %s", rec.Code, rec.Body.String())
	}

	var stored string
	if err := app.db.QueryRow(`SELECT value FROM app_settings WHERE key = 'VA_LLM_API_KEY'`).Scan(&stored); err != nil {
		t.Fatalf("读取密钥失败：%v", err)
	}
	if stored == "sk-secret" || stored == "" {
		t.Fatalf("密钥应加密存储，实际 %q", stored)
	}

	// 读取时密钥不回显
	rec = httptest.NewRecorder()
	req = newCatalogRequest(t, "GET", "/api/v1/settings/runtime", nil, "viewer")
	app.handleRuntimeSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("读取运行配置失败：%d", rec.Code)
	}
	var payload struct {
		Items []runtimeSettingValue `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析运行配置失败：%v", err)
	}
	var secretItem *runtimeSettingValue
	for index := range payload.Items {
		if payload.Items[index].Key == "VA_LLM_API_KEY" {
			secretItem = &payload.Items[index]
		}
	}
	if secretItem == nil || secretItem.Value != "" || !secretItem.HasValue || secretItem.Source != "db" {
		t.Fatalf("密钥读取结果异常：%+v", secretItem)
	}

	// 启动时能把加密密钥写回环境
	_ = os.Unsetenv("VA_LLM_API_KEY")
	if err := app.applyStoredRuntimeSettings(t.Context()); err != nil {
		t.Fatalf("应用运行配置失败：%v", err)
	}
	if os.Getenv("VA_LLM_API_KEY") != "sk-secret" {
		t.Fatalf("启动应用密钥失败：%q", os.Getenv("VA_LLM_API_KEY"))
	}
}

func TestRuntimeSettingsValidation(t *testing.T) {
	app := newRuntimeTestApp(t)
	cases := []map[string]string{
		{"VA_LLM_BASE_URL": "ftp://example.com"},
		{"VA_AGENT_CONTEXT_BUDGET": "100"},
		{"VA_SYNC_INTERVAL": "abc"},
		{"VA_COOKIE_SECURE": "maybe"},
	}
	for _, values := range cases {
		rec := httptest.NewRecorder()
		req := newCatalogRequest(t, "PUT", "/api/v1/settings/runtime", map[string]any{"values": values}, "admin")
		app.handleRuntimeSettingsUpdate(rec, req)
		if rec.Code != 400 {
			t.Fatalf("非法配置应返回 400，实际 %d：%s", rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "PUT", "/api/v1/settings/runtime",
		map[string]any{"values": map[string]string{"VA_UNKNOWN_KEY": "x"}}, "admin")
	app.handleRuntimeSettingsUpdate(rec, req)
	if rec.Code != 400 {
		t.Fatalf("未知配置项应返回 400，实际 %d", rec.Code)
	}
}

func TestRuntimeSettingMaxKeyLength(t *testing.T) {
	app := newRuntimeTestApp(t)
	rec := httptest.NewRecorder()
	req := newCatalogRequest(t, "PUT", "/api/v1/settings/runtime",
		map[string]any{"values": map[string]string{"VA_LLM_MODEL": strings.Repeat("x", 5000)}}, "admin")
	app.handleRuntimeSettingsUpdate(rec, req)
	if rec.Code != 400 {
		t.Fatalf("超长内容应返回 400，实际 %d", rec.Code)
	}
}
