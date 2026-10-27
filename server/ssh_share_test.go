package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type memoryWriteCloser struct {
	buf bytes.Buffer
}

func (m *memoryWriteCloser) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *memoryWriteCloser) Close() error                { return nil }

func serveSSHAs(role string, app *App, method, target string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: role + "-user", Name: role, Role: role}))
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	app.routes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSharePermission(t *testing.T) {
	for _, value := range []string{"", "read", "READONLY"} {
		if got, err := sharePermission(value); err != nil || got != "read" {
			t.Fatalf("%q 应解析为 read，实际 %q err=%v", value, got, err)
		}
	}
	if got, err := sharePermission("write"); err != nil || got != "write" {
		t.Fatalf("write 解析失败：%q %v", got, err)
	}
	if _, err := sharePermission("admin"); err == nil {
		t.Fatal("非法权限应被拒绝")
	}
}

func TestShareLifecycle(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	stdin := &memoryWriteCloser{}
	live := app.registerLiveSession("sess-live", "web-01", "10.0.0.1:22", "tester", "SSH-2.0-Go", stdin)
	defer app.releaseLiveSession("sess-live")

	rec := serveSSHAs("operator", app, http.MethodPost, "/api/v1/ssh/sessions/sess-live/share",
		map[string]any{"permission": "read", "ttlMinutes": 30})
	if rec.Code != http.StatusOK {
		t.Fatalf("创建分享失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token      string `json:"token"`
		Path       string `json:"path"`
		Permission string `json:"permission"`
		ExpiresAt  string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("创建响应异常：%s", rec.Body.String())
	}
	if created.Path != "/share/"+created.Token {
		t.Fatalf("分享路径异常：%s", created.Path)
	}

	rec = serveSSHAs("viewer", app, http.MethodGet, "/api/v1/ssh/shared/"+created.Token+"/info", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("读取分享信息失败：%d %s", rec.Code, rec.Body.String())
	}
	var info struct {
		HostName   string `json:"hostName"`
		Permission string `json:"permission"`
		CanWrite   bool   `json:"canWrite"`
		Viewers    int    `json:"viewers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.HostName != "web-01" || info.Permission != "read" || info.CanWrite {
		t.Fatalf("分享信息异常：%+v", info)
	}

	rec = serveSSHAs("operator", app, http.MethodGet, "/api/v1/ssh/sessions/sess-live/shares", nil)
	var shares struct {
		Items []struct {
			ID         int64  `json:"id"`
			Permission string `json:"permission"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &shares); err != nil || len(shares.Items) != 1 {
		t.Fatalf("分享列表异常：%s", rec.Body.String())
	}

	rec = serveSSHAs("operator", app, http.MethodDelete, "/api/v1/ssh/shares/"+snippetID(shares.Items[0].ID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("撤销分享失败：%d %s", rec.Code, rec.Body.String())
	}
	rec = serveSSHAs("viewer", app, http.MethodGet, "/api/v1/ssh/shared/"+created.Token+"/info", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("撤销后应返回 404，实际 %d", rec.Code)
	}
	if live.viewerCount() != 0 {
		t.Fatalf("不应残留协作者，实际 %d", live.viewerCount())
	}
}

func TestShareCreateRequiresLiveSession(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	rec := serveSSHAs("operator", app, http.MethodPost, "/api/v1/ssh/sessions/missing/share", map[string]any{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("离线会话应返回 409，实际 %d", rec.Code)
	}
}

func TestShareWritePermissionDowngrade(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	stdin := &memoryWriteCloser{}
	app.registerLiveSession("sess-write", "db-01", "10.0.0.2:22", "tester", "SSH-2.0-Go", stdin)
	defer app.releaseLiveSession("sess-write")

	rec := serveSSHAs("operator", app, http.MethodPost, "/api/v1/ssh/sessions/sess-write/share",
		map[string]any{"permission": "write", "ttlMinutes": 5})
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("创建可写分享失败：%s", rec.Body.String())
	}

	// viewer 角色只能读，权限应降级而非报错
	rec = serveSSHAs("viewer", app, http.MethodGet, "/api/v1/ssh/shared/"+created.Token+"/info", nil)
	var info struct {
		Permission string `json:"permission"`
		CanWrite   bool   `json:"canWrite"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Permission != "write" || info.CanWrite {
		t.Fatalf("viewer 权限应降级为只读：%+v", info)
	}
}

func TestShareBroadcastAndWrite(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	stdin := &memoryWriteCloser{}
	live := app.registerLiveSession("sess-broadcast", "app-01", "10.0.0.3:22", "tester", "SSH-2.0-Go", stdin)

	viewer, ok := live.addViewer(true)
	if !ok {
		t.Fatal("添加协作者失败")
	}
	live.broadcast([]byte("hello"))
	deadline := time.After(time.Second)
	for {
		select {
		case frame := <-viewer.frames:
			if frame.Type == "viewers" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(frame.Data)
			if err != nil || string(raw) != "hello" || frame.Type != "output" {
				t.Fatalf("广播帧异常：%+v raw=%q err=%v", frame, string(raw), err)
			}
			goto received
		case <-deadline:
			t.Fatal("未收到广播帧")
		}
	}

received:

	if got := string(live.recentOutput()); got != "hello" {
		t.Fatalf("最近输出快照异常：%q", got)
	}
	if live.viewerCount() != 1 {
		t.Fatalf("协作者人数异常：%d", live.viewerCount())
	}

	if err := live.write([]byte("uptime\r")); err != nil {
		t.Fatal(err)
	}
	if stdin.buf.String() != "uptime\r" {
		t.Fatalf("协作者输入未写入远端：%q", stdin.buf.String())
	}

	app.releaseLiveSession("sess-broadcast")
	select {
	case <-viewer.done:
	case <-time.After(time.Second):
		t.Fatal("会话结束后协作者未被关闭")
	}
	if app.liveSession("sess-broadcast") != nil {
		t.Fatal("会话结束后在线表未清理")
	}
}

func TestShareTokenExpiry(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	now := nowT()
	expired := now.Add(-time.Minute)
	if _, err := app.db.Exec(`INSERT INTO ssh_share_links
		(token_hash, session_id, host_name, permission, created_by, created_at, expires_at)
		VALUES(?,?,?,?,?,?,?)`,
		hashShareToken("expired-token"), "sess-x", "h", "read", "tester", fmtT(now), fmtT(expired)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.resolveShareToken("expired-token"); err != errShareExpired {
		t.Fatalf("过期令牌应返回 errShareExpired，实际 %v", err)
	}
	var count int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM ssh_share_links`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("过期令牌应被清理，剩余 %d err=%v", count, err)
	}
	if _, err := app.resolveShareToken("missing-token"); err != errShareNotFound {
		t.Fatalf("缺失令牌应返回 errShareNotFound，实际 %v", err)
	}
}
