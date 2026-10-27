package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ---------- 在线会话与协同 ----------

type sshShareViewer struct {
	canWrite bool
	frames   chan sshTerminalFrame
	done     chan struct{}
	closeOne sync.Once
}

func (v *sshShareViewer) push(frame sshTerminalFrame) {
	select {
	case v.frames <- frame:
	default:
		/* 慢客户端丢弃分片，不阻塞主会话 */
	}
}

func (v *sshShareViewer) close() {
	v.closeOne.Do(func() { close(v.done) })
}

// sshLiveSession 一次活动中的终端会话，负责向协作者广播输出并接收可写协作者的输入。
type sshLiveSession struct {
	id            string
	hostName      string
	addr          string
	owner         string
	serverVersion string
	stdin         io.WriteCloser

	inputMu sync.Mutex
	mu      sync.Mutex
	viewers map[*sshShareViewer]struct{}
	recent  []byte
	closed  bool
}

const sshLiveRecentLimit = 16 << 10

func (s *sshLiveSession) addViewer(canWrite bool) (*sshShareViewer, bool) {
	viewer := &sshShareViewer{canWrite: canWrite, frames: make(chan sshTerminalFrame, 256), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false
	}
	s.viewers[viewer] = struct{}{}
	s.mu.Unlock()
	s.pushViewers()
	return viewer, true
}

func (s *sshLiveSession) removeViewer(viewer *sshShareViewer) {
	s.mu.Lock()
	_, exists := s.viewers[viewer]
	delete(s.viewers, viewer)
	s.mu.Unlock()
	viewer.close()
	if exists {
		s.pushViewers()
	}
}

func (s *sshLiveSession) pushViewers() {
	s.mu.Lock()
	frame := sshTerminalFrame{Type: "viewers", Viewers: len(s.viewers)}
	for viewer := range s.viewers {
		viewer.push(frame)
	}
	s.mu.Unlock()
}

func (s *sshLiveSession) viewerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.viewers)
}

// recentOutput 返回最近的输出快照，供新加入的协作者补齐上下文。
func (s *sshLiveSession) recentOutput() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recent) == 0 {
		return nil
	}
	return append([]byte(nil), s.recent...)
}

func (s *sshLiveSession) broadcast(p []byte) {
	if len(p) == 0 {
		return
	}
	frame := sshTerminalFrame{Type: "output", Data: base64.StdEncoding.EncodeToString(p)}
	s.mu.Lock()
	s.recent = append(s.recent, p...)
	if len(s.recent) > sshLiveRecentLimit {
		s.recent = s.recent[len(s.recent)-sshLiveRecentLimit:]
	}
	for viewer := range s.viewers {
		viewer.push(frame)
	}
	s.mu.Unlock()
}

func (s *sshLiveSession) write(p []byte) error {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	_, err := s.stdin.Write(p)
	return err
}

func (s *sshLiveSession) closeAll() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for viewer := range s.viewers {
		viewer.close()
	}
	s.viewers = nil
	s.mu.Unlock()
}

func (a *App) registerLiveSession(id, hostName, addr, owner, serverVersion string, stdin io.WriteCloser) *sshLiveSession {
	live := &sshLiveSession{
		id: id, hostName: hostName, addr: addr, owner: owner, serverVersion: serverVersion,
		stdin: stdin, viewers: make(map[*sshShareViewer]struct{}),
	}
	a.liveMu.Lock()
	if a.live == nil {
		a.live = make(map[string]*sshLiveSession)
	}
	a.live[id] = live
	a.liveMu.Unlock()
	return live
}

func (a *App) liveSession(id string) *sshLiveSession {
	a.liveMu.Lock()
	defer a.liveMu.Unlock()
	return a.live[id]
}

func (a *App) releaseLiveSession(id string) {
	a.liveMu.Lock()
	live := a.live[id]
	delete(a.live, id)
	a.liveMu.Unlock()
	if live != nil {
		live.closeAll()
	}
}

// ---------- 分享链接 ----------

type sshShareLink struct {
	ID         int64
	SessionID  string
	HostName   string
	Permission string
	CreatedBy  string
	CreatedAt  string
	ExpiresAt  string
}

var (
	errShareNotFound = errors.New("分享链接不存在")
	errShareExpired  = errors.New("分享链接已过期")
)

func hashShareToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newShareToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (a *App) resolveShareToken(token string) (sshShareLink, error) {
	var link sshShareLink
	err := a.db.QueryRow(`SELECT id, session_id, host_name, permission, created_by, created_at, expires_at
		FROM ssh_share_links WHERE token_hash=?`, hashShareToken(token)).
		Scan(&link.ID, &link.SessionID, &link.HostName, &link.Permission, &link.CreatedBy, &link.CreatedAt, &link.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return link, errShareNotFound
	}
	if err != nil {
		return link, err
	}
	expires, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil || nowT().After(expires) {
		_, _ = a.db.Exec(`DELETE FROM ssh_share_links WHERE id=?`, link.ID)
		return link, errShareExpired
	}
	return link, nil
}

func sharePermission(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "read", "readonly":
		return "read", nil
	case "write", "readwrite":
		return "write", nil
	}
	return "", errors.New("permission 必须为 read 或 write")
}

// handleSSHShareCreate 为活动会话生成一次性分享链接（令牌只返回一次）。
func (a *App) handleSSHShareCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	sessionID := r.PathValue("id")
	live := a.liveSession(sessionID)
	if live == nil {
		writeErr(w, http.StatusConflict, "session_not_live", "会话不在线，无法分享")
		return
	}
	var req struct {
		Permission string `json:"permission"`
		TTLMinutes int    `json:"ttlMinutes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	permission, err := sharePermission(req.Permission)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ttl := req.TTLMinutes
	if ttl <= 0 {
		ttl = 60
	}
	ttl = clampInt(ttl, 5, 1440)
	token, err := newShareToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "生成分享链接失败")
		return
	}
	now := nowT()
	expiresAt := now.Add(time.Duration(ttl) * time.Minute)
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO ssh_share_links
		(token_hash, session_id, host_name, permission, created_by, created_at, expires_at)
		VALUES(?,?,?,?,?,?,?)`,
		hashShareToken(token), sessionID, live.hostName, permission, u.Username, fmtT(now), fmtT(expiresAt)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存分享链接失败")
		return
	}
	a.audit(r, "ssh.share.create", live.hostName, fmt.Sprintf("会话 %s，权限 %s，有效期 %d 分钟", sessionID, permission, ttl))
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "path": "/share/" + token, "permission": permission,
		"expiresAt": fmtT(expiresAt), "sessionId": sessionID, "hostName": live.hostName,
	})
}

// handleSSHShares 列出会话当前有效的分享链接（不含令牌）。
func (a *App) handleSSHShares(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	sessionID := r.PathValue("id")
	rows, err := a.db.QueryContext(r.Context(), `SELECT id, permission, created_by, created_at, expires_at
		FROM ssh_share_links WHERE session_id=? ORDER BY id DESC`, sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取分享链接失败")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0, 4)
	now := nowT()
	for rows.Next() {
		var (
			id                               int64
			permission, createdBy, createdAt string
			expiresAt                        string
		)
		if err := rows.Scan(&id, &permission, &createdBy, &createdAt, &expiresAt); err != nil {
			continue
		}
		expires, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil || now.After(expires) {
			continue
		}
		items = append(items, map[string]any{
			"id": id, "permission": permission, "createdBy": createdBy,
			"createdAt": createdAt, "expiresAt": expiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleSSHShareRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "id 无效")
		return
	}
	var sessionID, hostName string
	if err := a.db.QueryRowContext(r.Context(), `SELECT session_id, host_name FROM ssh_share_links WHERE id=?`, id).
		Scan(&sessionID, &hostName); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "分享链接不存在")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取分享链接失败")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM ssh_share_links WHERE id=?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "撤销分享链接失败")
		return
	}
	a.audit(r, "ssh.share.revoke", hostName, "会话 "+sessionID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSSHShareInfo 返回分享元信息，供协同页面在建立 WebSocket 前展示。
func (a *App) handleSSHShareInfo(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	link, err := a.resolveShareToken(r.PathValue("token"))
	if errors.Is(err, errShareNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "分享链接不存在")
		return
	}
	if errors.Is(err, errShareExpired) {
		writeErr(w, http.StatusGone, "share_expired", "分享链接已过期")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取分享链接失败")
		return
	}
	live := a.liveSession(link.SessionID)
	if live == nil {
		writeErr(w, http.StatusGone, "session_ended", "会话已结束")
		return
	}
	canWrite := link.Permission == "write" && roleRank(u.Role) >= roleRank("operator")
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId": link.SessionID, "hostName": live.hostName, "addr": live.addr, "owner": live.owner,
		"permission": link.Permission, "canWrite": canWrite,
		"expiresAt": link.ExpiresAt, "viewers": live.viewerCount(), "serverVersion": live.serverVersion,
	})
}

// handleSharedTerminal 让已登录用户通过分享令牌接入活动会话；只读链接不转发输入。
func (a *App) handleSharedTerminal(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "viewer")
	if !ok {
		return
	}
	link, err := a.resolveShareToken(r.PathValue("token"))
	if errors.Is(err, errShareNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "分享链接不存在")
		return
	}
	if errors.Is(err, errShareExpired) {
		writeErr(w, http.StatusGone, "share_expired", "分享链接已过期")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取分享链接失败")
		return
	}
	live := a.liveSession(link.SessionID)
	if live == nil {
		writeErr(w, http.StatusGone, "session_ended", "会话已结束")
		return
	}
	canWrite := link.Permission == "write" && roleRank(u.Role) >= roleRank("operator")
	viewer, ok := live.addViewer(canWrite)
	if !ok {
		writeErr(w, http.StatusGone, "session_ended", "会话已结束")
		return
	}
	defer live.removeViewer(viewer)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(1 << 20)
	defer conn.CloseNow()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex
	send := func(frame sshTerminalFrame) error {
		payload, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.Write(ctx, websocket.MessageText, payload)
	}

	if err := send(sshTerminalFrame{
		Type: "status", Status: "connected", SessionID: live.id,
		HostName: live.hostName, Permission: link.Permission, CanWrite: canWrite,
		ServerVersion: live.serverVersion, Viewers: live.viewerCount(),
	}); err != nil {
		return
	}
	if snapshot := live.recentOutput(); len(snapshot) > 0 {
		if err := send(sshTerminalFrame{Type: "output", Data: base64.StdEncoding.EncodeToString(snapshot)}); err != nil {
			return
		}
	}
	a.audit(r, "ssh.share.join", live.hostName, fmt.Sprintf("会话 %s，权限 %s", live.id, link.Permission))
	slog.Info("SSH 协同会话接入", "session", live.id, "viewer", u.Username, "permission", link.Permission)

	go func() {
		var typed strings.Builder
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				cancel()
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var msg sshTerminalFrame
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "input":
				if !canWrite || msg.Data == "" {
					continue
				}
				for _, line := range extractTypedLines(&typed, msg.Data) {
					if _, err := a.db.Exec(`INSERT INTO ssh_events(session_id, kind, data, created_at) VALUES(?,?,?,?)`,
						live.id, "shared_input", truncateRunes(line, 500), fmtT(nowT())); err != nil {
						slog.Warn("记录协同输入失败", "session", live.id, "err", err)
					}
				}
				if err := live.write([]byte(msg.Data)); err != nil {
					cancel()
					return
				}
			case "resize":
				/* 协同端不改变主会话的终端尺寸 */
			case "ping":
				_ = send(sshTerminalFrame{Type: "pong"})
			}
		}
	}()

	for {
		select {
		case frame := <-viewer.frames:
			if err := send(frame); err != nil {
				return
			}
		case <-viewer.done:
			_ = send(sshTerminalFrame{Type: "exit", Message: "会话已结束"})
			return
		case <-ctx.Done():
			return
		}
	}
}
