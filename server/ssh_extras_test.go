package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

func snippetID(id int64) string { return strconv.FormatInt(id, 10) }

func newSSHWorkspaceApp(t *testing.T) *App {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "workspace.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &App{db: db, dataDir: t.TempDir()}
}

func serveSSHWorkspace(app *App, method, target string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, target, reader)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: "ops", Name: "运维", Role: "operator"}))
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	app.routes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSSHRecorderPersistsChunks(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	recorder := newSSHRecorder(app, "sess-rec", sshHost{ID: 7, Name: "demo"}, "tester", nowT())
	recorder.Record([]byte("hello "))
	recorder.Record([]byte("world"))
	recorder.Stop()

	var chunks, bytes int64
	var duration int64
	var truncated int
	if err := app.db.QueryRow(`SELECT chunks, bytes, duration_ms, truncated FROM ssh_recordings WHERE session_id='sess-rec'`).
		Scan(&chunks, &bytes, &duration, &truncated); err != nil {
		t.Fatalf("录制元数据缺失：%v", err)
	}
	if chunks != 2 || bytes != 11 || duration < 0 || truncated != 0 {
		t.Fatalf("录制元数据异常：chunks=%d bytes=%d duration=%d truncated=%d", chunks, bytes, duration, truncated)
	}

	rows, err := app.db.Query(`SELECT seq, offset_ms, data FROM ssh_recording_chunks WHERE session_id='sess-rec' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var collected string
	seq := 0
	for rows.Next() {
		var gotSeq, offset int64
		var data string
		if err := rows.Scan(&gotSeq, &offset, &data); err != nil {
			t.Fatal(err)
		}
		if gotSeq != int64(seq) || offset < 0 {
			t.Fatalf("分片顺序异常：seq=%d offset=%d", gotSeq, offset)
		}
		raw, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			t.Fatal(err)
		}
		collected += string(raw)
		seq++
	}
	if collected != "hello world" {
		t.Fatalf("回放内容异常：%q", collected)
	}
}

func TestSSHRecorderDropsEmptyRecording(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	recorder := newSSHRecorder(app, "sess-empty", sshHost{ID: 1, Name: "demo"}, "tester", nowT())
	recorder.Stop()
	var count int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM ssh_recordings WHERE session_id='sess-empty'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("空会话不应保留录制，实际 %d 条", count)
	}
}

func TestNormalizeSnippetInput(t *testing.T) {
	if _, err := normalizeSnippetInput("", "ls", "", ""); err == nil {
		t.Fatal("空名称应被拒绝")
	}
	if _, err := normalizeSnippetInput("查看磁盘", "df -h\nrm -rf /", "", ""); err == nil {
		t.Fatal("多行命令应被拒绝")
	}
	snippet, err := normalizeSnippetInput(" 查看磁盘 ", " df -h ", " 磁盘使用率 ", " disk ")
	if err != nil {
		t.Fatalf("合法输入不应失败：%v", err)
	}
	if snippet.Name != "查看磁盘" || snippet.Command != "df -h" || snippet.Description != "磁盘使用率" || snippet.Tags != "disk" {
		t.Fatalf("输入未正确裁剪：%+v", snippet)
	}
}

func TestSSHSnippetCRUD(t *testing.T) {
	app := newSSHWorkspaceApp(t)

	rec := serveSSHWorkspace(app, http.MethodPost, "/api/v1/ssh/snippets", map[string]any{
		"name": "磁盘巡检", "command": "df -h", "description": "查看磁盘使用率", "tags": "disk",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("创建快捷命令失败：%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Snippet sshSnippet `json:"snippet"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Snippet.ID == 0 {
		t.Fatalf("创建响应异常：%s", rec.Body.String())
	}

	rec = serveSSHWorkspace(app, http.MethodGet, "/api/v1/ssh/snippets", nil)
	var list struct {
		Items []sshSnippet `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("列表异常：%s", rec.Body.String())
	}

	rec = serveSSHWorkspace(app, http.MethodPatch, "/api/v1/ssh/snippets/"+snippetID(created.Snippet.ID), map[string]any{
		"name": "磁盘巡检", "command": "df -hT", "description": "查看磁盘使用率", "tags": "disk",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("更新快捷命令失败：%d %s", rec.Code, rec.Body.String())
	}

	rec = serveSSHWorkspace(app, http.MethodPatch, "/api/v1/ssh/snippets/"+snippetID(created.Snippet.ID), map[string]any{
		"name": "非法", "command": "df -h\nuptime",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("多行命令应返回 400，实际 %d", rec.Code)
	}

	rec = serveSSHWorkspace(app, http.MethodPost, "/api/v1/ssh/snippets/"+snippetID(created.Snippet.ID)+"/use", map[string]any{
		"hostNames": []string{"web-01", "web-02"}, "broadcast": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("记录使用失败：%d %s", rec.Code, rec.Body.String())
	}
	var used struct {
		UsageCount int64 `json:"usageCount"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &used); err != nil || used.UsageCount != 1 {
		t.Fatalf("使用次数异常：%s", rec.Body.String())
	}

	rec = serveSSHWorkspace(app, http.MethodDelete, "/api/v1/ssh/snippets/"+snippetID(created.Snippet.ID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("删除快捷命令失败：%d %s", rec.Code, rec.Body.String())
	}
	rec = serveSSHWorkspace(app, http.MethodGet, "/api/v1/ssh/snippets", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Items) != 0 {
		t.Fatalf("删除后仍存在：%s", rec.Body.String())
	}
}

func TestSSHRecordingAPIAndSessionFlags(t *testing.T) {
	app := newSSHWorkspaceApp(t)
	now := fmtT(nowT())
	if _, err := app.db.Exec(`INSERT INTO ssh_sessions
		(id, host_id, host_name, addr, actor, role, status, error, client_ip, started_at, ended_at, bytes_in, bytes_out)
		VALUES('sess-view', 1, 'demo', '127.0.0.1:22', 'tester', 'operator', 'closed', '', '127.0.0.1', ?, ?, 10, 20)`,
		now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec(`INSERT INTO ssh_recordings
		(session_id, host_id, host_name, actor, started_at, ended_at, duration_ms, chunks, bytes, truncated)
		VALUES('sess-view', 1, 'demo', 'tester', ?, ?, 5000, 1, 5, 0)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.db.Exec(`INSERT INTO ssh_recording_chunks(session_id, seq, offset_ms, data, created_at)
		VALUES('sess-view', 0, 120, ?, ?)`, base64.StdEncoding.EncodeToString([]byte("hello")), now); err != nil {
		t.Fatal(err)
	}

	rec := serveSSHWorkspace(app, http.MethodGet, "/api/v1/ssh/sessions", nil)
	var sessions struct {
		Items []struct {
			ID            string `json:"id"`
			HasRecording  bool   `json:"hasRecording"`
			RecordingMs   int64  `json:"recordingMs"`
			RecordingSize int64  `json:"recordingBytes"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sessions); err != nil || len(sessions.Items) != 1 {
		t.Fatalf("会话列表异常：%s", rec.Body.String())
	}
	if !sessions.Items[0].HasRecording || sessions.Items[0].RecordingMs != 5000 || sessions.Items[0].RecordingSize != 5 {
		t.Fatalf("录制标记异常：%+v", sessions.Items[0])
	}

	rec = serveSSHWorkspace(app, http.MethodGet, "/api/v1/ssh/sessions/sess-view/recording", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("读取录制失败：%d %s", rec.Code, rec.Body.String())
	}
	var recording struct {
		DurationMs int64 `json:"durationMs"`
		Chunks     []struct {
			OffsetMs int64  `json:"offsetMs"`
			Data     string `json:"data"`
		} `json:"chunks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &recording); err != nil || len(recording.Chunks) != 1 || recording.DurationMs != 5000 {
		t.Fatalf("录制响应异常：%s", rec.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(recording.Chunks[0].Data)
	if err != nil || string(raw) != "hello" {
		t.Fatalf("录制内容异常：%q err=%v", string(raw), err)
	}
}
