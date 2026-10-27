package main

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ---------- 会话录制 ----------

const (
	sshRecordingLimit = 2 << 20 // 单会话最多录制 2MB 原始输出
	sshRecordingBatch = 24
)

type sshRecordingChunk struct {
	offsetMs int64
	data     []byte
}

// sshRecorder 将 PTY 输出按时间偏移异步落库，写入失败或超过上限时标记截断，
// 不阻塞终端转发路径。
type sshRecorder struct {
	app       *App
	sessionID string
	started   time.Time
	ch        chan sshRecordingChunk
	stopCh    chan struct{}
	done      chan struct{}
	bytes     atomic.Int64
	truncated atomic.Bool
	stopped   atomic.Bool
}

func newSSHRecorder(app *App, sessionID string, host sshHost, actor string, started time.Time) *sshRecorder {
	recorder := &sshRecorder{
		app:       app,
		sessionID: sessionID,
		started:   started,
		ch:        make(chan sshRecordingChunk, 256),
		stopCh:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	if _, err := app.db.Exec(`INSERT OR REPLACE INTO ssh_recordings
		(session_id, host_id, host_name, actor, started_at, ended_at, duration_ms, bytes, truncated)
		VALUES(?,?,?,?,?,'',0,0,0)`,
		sessionID, host.ID, host.Name, actor, fmtT(started)); err != nil {
		slog.Warn("创建会话录制失败", "session", sessionID, "err", err)
	}
	go recorder.loop()
	return recorder
}

// Record 非阻塞写入；超过上限或缓冲拥塞时丢弃并标记截断。
func (r *sshRecorder) Record(p []byte) {
	if r == nil || len(p) == 0 || r.stopped.Load() {
		return
	}
	if r.bytes.Load()+int64(len(p)) > sshRecordingLimit {
		r.truncated.Store(true)
		return
	}
	chunk := sshRecordingChunk{offsetMs: time.Since(r.started).Milliseconds(), data: append([]byte(nil), p...)}
	r.bytes.Add(int64(len(p)))
	select {
	case r.ch <- chunk:
	case <-r.stopCh:
	default:
		r.truncated.Store(true)
	}
}

func (r *sshRecorder) loop() {
	defer close(r.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]sshRecordingChunk, 0, sshRecordingBatch)
	seq := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := r.app.db.Begin()
		if err != nil {
			batch = batch[:0]
			return
		}
		stmt, err := tx.Prepare(`INSERT INTO ssh_recording_chunks(session_id, seq, offset_ms, data, created_at)
			VALUES(?,?,?,?,?)`)
		if err != nil {
			_ = tx.Rollback()
			batch = batch[:0]
			return
		}
		createdAt := fmtT(nowT())
		for _, chunk := range batch {
			if _, err := stmt.Exec(r.sessionID, seq, chunk.offsetMs, base64.StdEncoding.EncodeToString(chunk.data), createdAt); err != nil {
				slog.Warn("写入会话录制失败", "session", r.sessionID, "err", err)
				break
			}
			seq++
		}
		_ = stmt.Close()
		_ = tx.Commit()
		batch = batch[:0]
	}
	for {
		select {
		case chunk := <-r.ch:
			batch = append(batch, chunk)
			if len(batch) >= sshRecordingBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-r.stopCh:
			for {
				select {
				case chunk := <-r.ch:
					batch = append(batch, chunk)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Stop 停止录制并回写元数据；没有输出的会话会直接删除空记录。
func (r *sshRecorder) Stop() {
	if r == nil || !r.stopped.CompareAndSwap(false, true) {
		return
	}
	close(r.stopCh)
	<-r.done
	var chunks int
	if err := r.app.db.QueryRow(`SELECT COUNT(*) FROM ssh_recording_chunks WHERE session_id=?`, r.sessionID).Scan(&chunks); err != nil {
		return
	}
	if chunks == 0 {
		_, _ = r.app.db.Exec(`DELETE FROM ssh_recordings WHERE session_id=?`, r.sessionID)
		return
	}
	truncated := 0
	if r.truncated.Load() {
		truncated = 1
	}
	if _, err := r.app.db.Exec(`UPDATE ssh_recordings SET ended_at=?, duration_ms=?, chunks=?, bytes=?, truncated=? WHERE session_id=?`,
		fmtT(nowT()), time.Since(r.started).Milliseconds(), chunks, r.bytes.Load(), truncated, r.sessionID); err != nil {
		slog.Warn("更新会话录制失败", "session", r.sessionID, "err", err)
	}
}

// handleSSHRecording 返回一次会话的录制元数据与回放分片（data 为 base64）。
func (a *App) handleSSHRecording(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	sessionID := r.PathValue("id")
	var (
		hostName, actor, startedAt, endedAt string
		durationMs, bytes                   int64
		truncated                           int
	)
	err := a.db.QueryRowContext(r.Context(), `SELECT host_name, actor, started_at, ended_at, duration_ms, bytes, truncated
		FROM ssh_recordings WHERE session_id=?`, sessionID).
		Scan(&hostName, &actor, &startedAt, &endedAt, &durationMs, &bytes, &truncated)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "该会话没有录制")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取会话录制失败")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT offset_ms, data FROM ssh_recording_chunks
		WHERE session_id=? ORDER BY seq ASC`, sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取录制分片失败")
		return
	}
	defer rows.Close()
	chunks := make([]map[string]any, 0, 128)
	for rows.Next() {
		var offsetMs int64
		var data string
		if err := rows.Scan(&offsetMs, &data); err != nil {
			continue
		}
		chunks = append(chunks, map[string]any{"offsetMs": offsetMs, "data": data})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId": sessionID, "hostName": hostName, "actor": actor,
		"startedAt": startedAt, "endedAt": endedAt, "durationMs": durationMs,
		"bytes": bytes, "truncated": truncated == 1, "chunks": chunks,
	})
}

// ---------- 快捷命令（脚本库） ----------

type sshSnippet struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Command     string `json:"command"`
	Description string `json:"description"`
	Tags        string `json:"tags"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	UsageCount  int64  `json:"usageCount"`
}

func normalizeSnippetInput(name, command, description, tags string) (sshSnippet, error) {
	snippet := sshSnippet{
		Name:        strings.TrimSpace(name),
		Command:     strings.TrimSpace(command),
		Description: strings.TrimSpace(description),
		Tags:        strings.TrimSpace(tags),
	}
	switch {
	case snippet.Name == "":
		return snippet, errors.New("名称不能为空")
	case utf8.RuneCountInString(snippet.Name) > 64:
		return snippet, errors.New("名称不能超过 64 个字符")
	case snippet.Command == "":
		return snippet, errors.New("命令不能为空")
	case len(snippet.Command) > 2000:
		return snippet, errors.New("命令不能超过 2000 字节")
	case strings.ContainsAny(snippet.Command, "\r\n"):
		return snippet, errors.New("命令必须为单行")
	case utf8.RuneCountInString(snippet.Description) > 200:
		return snippet, errors.New("说明不能超过 200 个字符")
	case utf8.RuneCountInString(snippet.Tags) > 120:
		return snippet, errors.New("标签不能超过 120 个字符")
	}
	return snippet, nil
}

func (a *App) getSSHSnippet(r *http.Request, id int64) (sshSnippet, error) {
	var snippet sshSnippet
	err := a.db.QueryRowContext(r.Context(), `SELECT id, name, command, description, tags, created_by, created_at, updated_at, usage_count
		FROM ssh_snippets WHERE id=?`, id).
		Scan(&snippet.ID, &snippet.Name, &snippet.Command, &snippet.Description, &snippet.Tags,
			&snippet.CreatedBy, &snippet.CreatedAt, &snippet.UpdatedAt, &snippet.UsageCount)
	return snippet, err
}

func (a *App) handleSSHSnippets(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	limit := clampInt(queryInt(r, "limit", 100), 1, 200)
	rows, err := a.db.QueryContext(r.Context(), `SELECT id, name, command, description, tags, created_by, created_at, updated_at, usage_count
		FROM ssh_snippets ORDER BY usage_count DESC, updated_at DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取快捷命令失败")
		return
	}
	defer rows.Close()
	items := make([]sshSnippet, 0, limit)
	for rows.Next() {
		var snippet sshSnippet
		if err := rows.Scan(&snippet.ID, &snippet.Name, &snippet.Command, &snippet.Description, &snippet.Tags,
			&snippet.CreatedBy, &snippet.CreatedAt, &snippet.UpdatedAt, &snippet.UsageCount); err != nil {
			continue
		}
		items = append(items, snippet)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleSSHSnippetCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Command     string `json:"command"`
		Description string `json:"description"`
		Tags        string `json:"tags"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	snippet, err := normalizeSnippetInput(req.Name, req.Command, req.Description, req.Tags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	now := fmtT(nowT())
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO ssh_snippets
		(name, command, description, tags, created_by, created_at, updated_at, usage_count)
		VALUES(?,?,?,?,?,?,?,0)`,
		snippet.Name, snippet.Command, snippet.Description, snippet.Tags, u.Username, now, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存快捷命令失败")
		return
	}
	snippet.ID, _ = res.LastInsertId()
	snippet.CreatedBy, snippet.CreatedAt, snippet.UpdatedAt = u.Username, now, now
	a.audit(r, "ssh.snippet.create", snippet.Name, snippet.Command)
	writeJSON(w, http.StatusOK, map[string]any{"snippet": snippet})
}

func (a *App) handleSSHSnippetUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "id 无效")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Command     string `json:"command"`
		Description string `json:"description"`
		Tags        string `json:"tags"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	existing, err := a.getSSHSnippet(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "快捷命令不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取快捷命令失败")
		return
	}
	snippet, err := normalizeSnippetInput(req.Name, req.Command, req.Description, req.Tags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	now := fmtT(nowT())
	if _, err := a.db.ExecContext(r.Context(), `UPDATE ssh_snippets SET name=?, command=?, description=?, tags=?, updated_at=? WHERE id=?`,
		snippet.Name, snippet.Command, snippet.Description, snippet.Tags, now, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新快捷命令失败")
		return
	}
	snippet.ID, snippet.CreatedBy, snippet.CreatedAt, snippet.UpdatedAt = id, existing.CreatedBy, existing.CreatedAt, now
	snippet.UsageCount = existing.UsageCount
	a.audit(r, "ssh.snippet.update", snippet.Name, snippet.Command)
	writeJSON(w, http.StatusOK, map[string]any{"snippet": snippet})
}

func (a *App) handleSSHSnippetDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "id 无效")
		return
	}
	snippet, err := a.getSSHSnippet(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "快捷命令不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取快捷命令失败")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM ssh_snippets WHERE id=?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除快捷命令失败")
		return
	}
	a.audit(r, "ssh.snippet.delete", snippet.Name, snippet.Command)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSSHSnippetUse 记录一次使用（可带主机名与是否广播），用于排序与审计。
func (a *App) handleSSHSnippetUse(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "id 无效")
		return
	}
	var req struct {
		HostNames []string `json:"hostNames"`
		Broadcast bool     `json:"broadcast"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if len(req.HostNames) > 20 {
		req.HostNames = req.HostNames[:20]
	}
	snippet, err := a.getSSHSnippet(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "快捷命令不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取快捷命令失败")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE ssh_snippets SET usage_count=usage_count+1 WHERE id=?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新使用次数失败")
		return
	}
	detail := snippet.Command
	if len(req.HostNames) > 0 {
		detail += " @ " + strings.Join(req.HostNames, ", ")
	}
	if req.Broadcast {
		detail += "（广播）"
	}
	a.audit(r, "ssh.snippet.use", snippet.Name, truncateRunes(detail, 300))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "usageCount": snippet.UsageCount + 1})
}
