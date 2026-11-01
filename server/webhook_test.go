package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vulnagent/server/internal/application/ports"
)

func TestAssetUpdatedWebhook(t *testing.T) {
	app := newCatalogTestApp(t)
	events := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		events <- r.Header.Get("X-VulnAgent-Event") + "|" + string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := app.notifyRepo().Save(context.Background(), ports.NotifySettings{
		URL: server.URL, Secret: "test-secret", Events: []string{"asset.updated"},
	}, fmtT(nowT())); err != nil {
		t.Fatalf("保存通知配置失败：%v", err)
	}
	if _, err := app.db.Exec(`INSERT INTO assets(hostname, owner) VALUES('hook-host','')`); err != nil {
		t.Fatalf("写入资产失败：%v", err)
	}

	rec := httptest.NewRecorder()
	app.handleAssetPatch(rec, withPathValue(newCatalogRequest(t, "PATCH", "/api/v1/assets/1",
		map[string]any{"owner": "王五"}, "operator"), "id", "1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("更新资产失败：%d %s", rec.Code, rec.Body.String())
	}

	select {
	case got := <-events:
		if !strings.HasPrefix(got, "asset.updated|") {
			t.Fatalf("事件类型不正确：%s", got)
		}
		if !strings.Contains(got, `"assetId":1`) || !strings.Contains(got, "owner") {
			t.Fatalf("事件负载缺少资产信息：%s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 asset.updated Webhook")
	}
}

func TestNotifyEventCatalogIncludesAssetEvents(t *testing.T) {
	for _, event := range []string{"asset.created", "asset.updated", "asset.merged", "integration.sync_failed"} {
		if !containsString(notifyEventCatalog, event) {
			t.Fatalf("事件目录缺少 %s", event)
		}
	}
}
