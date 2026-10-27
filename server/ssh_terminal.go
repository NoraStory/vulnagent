package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// sshTerminalFrame WebSocket 双向消息；输出统一使用 base64，避免二进制被 JSON 破坏
type sshTerminalFrame struct {
	Type          string `json:"type"`
	Data          string `json:"data,omitempty"`
	Cols          int    `json:"cols,omitempty"`
	Rows          int    `json:"rows,omitempty"`
	Message       string `json:"message,omitempty"`
	SessionID     string `json:"sessionId,omitempty"`
	Status        string `json:"status,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	ServerVersion string `json:"serverVersion,omitempty"`
	Code          int    `json:"code,omitempty"`
}

func newSSHSessionID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("ssh-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// handleSSHTerminal 将浏览器 WebSocket 与远端 SSH PTY 双向桥接
func (a *App) handleSSHTerminal(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	hostID, err := strconv.ParseInt(r.URL.Query().Get("hostId"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "hostId 无效")
		return
	}
	host, err := a.getSSHHost(r.Context(), hostID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	cols := clampInt(queryInt(r, "cols", 120), 20, 400)
	rows := clampInt(queryInt(r, "rows", 32), 5, 200)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // 已由 Cookie 会话鉴权，允许反向代理后的同源访问
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
	send := func(frame sshTerminalFrame) {
		payload, err := json.Marshal(frame)
		if err != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.Write(ctx, websocket.MessageText, payload)
	}

	sessionID := newSSHSessionID()
	startedTime := nowT()
	startedAt := fmtT(startedTime)
	clientIP := clientIP(r)

	fail := func(message string) {
		send(sshTerminalFrame{Type: "error", Message: message})
		_, _ = a.db.Exec(`INSERT INTO ssh_sessions
			(id, host_id, host_name, addr, actor, role, status, error, client_ip, started_at, ended_at, bytes_in, bytes_out)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0)`,
			sessionID, host.ID, host.Name, host.addr(), u.Username, u.Role, "failed", message, clientIP, startedAt, fmtT(nowT()))
		a.audit(r, "ssh.connect", host.Name, "失败："+message)
		_ = conn.Close(websocket.StatusPolicyViolation, "连接失败")
	}

	client, fingerprint, err := a.dialSSHHost(ctx, host)
	if err != nil {
		fail(err.Error())
		return
	}
	defer client.Close()

	if host.HostKey == "" {
		if _, err := a.db.ExecContext(ctx, `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			fingerprint, fmtT(nowT()), host.ID); err != nil {
			slog.Warn("保存 SSH 主机指纹失败", "host", host.Name, "err", err)
		}
	}

	shell, err := client.NewSession()
	if err != nil {
		fail("建立 SSH 会话失败：" + err.Error())
		return
	}
	defer shell.Close()

	if err := shell.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		fail("申请 PTY 失败：" + err.Error())
		return
	}
	stdin, err := shell.StdinPipe()
	if err != nil {
		fail("打开输入通道失败：" + err.Error())
		return
	}

	var bytesIn, bytesOut atomic.Int64
	recorder := newSSHRecorder(a, sessionID, host, u.Username, startedTime)
	defer recorder.Stop()
	writer := sshStreamWriter{
		bytes: &bytesOut,
		send: func(p []byte) {
			recorder.Record(p)
			send(sshTerminalFrame{Type: "output", Data: base64.StdEncoding.EncodeToString(p)})
		},
	}
	shell.Stdout = writer
	shell.Stderr = writer

	if err := shell.Shell(); err != nil {
		fail("启动远程 shell 失败：" + err.Error())
		return
	}

	if _, err := a.db.ExecContext(ctx, `INSERT INTO ssh_sessions
		(id, host_id, host_name, addr, actor, role, status, error, client_ip, started_at, ended_at, bytes_in, bytes_out)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0)`,
		sessionID, host.ID, host.Name, host.addr(), u.Username, u.Role, "connected", "", clientIP, startedAt, ""); err != nil {
		slog.Warn("写入 SSH 会话失败", "session", sessionID, "err", err)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE ssh_hosts SET last_connected_at = ? WHERE id = ?`, startedAt, host.ID); err != nil {
		slog.Warn("更新 SSH 主机连接时间失败", "host", host.Name, "err", err)
	}
	a.audit(r, "ssh.connect", host.Name, "会话 "+sessionID+" "+host.addr())
	slog.Info("SSH 终端已连接", "session", sessionID, "host", host.addr(), "actor", u.Username)

	send(sshTerminalFrame{
		Type: "status", Status: "connected", SessionID: sessionID,
		Fingerprint: fingerprint, ServerVersion: string(client.ServerVersion()),
	})

	exitCode := 0
	go func() {
		err := shell.Wait()
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		}
		send(sshTerminalFrame{Type: "exit", Code: exitCode})
		_ = conn.Close(websocket.StatusNormalClosure, "会话结束")
	}()

	var typed strings.Builder
	defer func() {
		endedAt := fmtT(nowT())
		status := "closed"
		if _, err := a.db.Exec(`UPDATE ssh_sessions SET status=?, ended_at=?, bytes_in=?, bytes_out=? WHERE id=?`,
			status, endedAt, bytesIn.Load(), bytesOut.Load(), sessionID); err != nil {
			slog.Warn("更新 SSH 会话失败", "session", sessionID, "err", err)
		}
		a.audit(r, "ssh.disconnect", host.Name, fmt.Sprintf("会话 %s，输入 %d B，输出 %d B", sessionID, bytesIn.Load(), bytesOut.Load()))
		slog.Info("SSH 终端已断开", "session", sessionID, "host", host.addr(), "bytesIn", bytesIn.Load(), "bytesOut", bytesOut.Load())
	}()

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			break
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
			if msg.Data == "" {
				continue
			}
			bytesIn.Add(int64(len(msg.Data)))
			for _, line := range extractTypedLines(&typed, msg.Data) {
				if _, err := a.db.Exec(`INSERT INTO ssh_events(session_id, kind, data, created_at) VALUES(?,?,?,?)`,
					sessionID, "input", truncateRunes(line, 500), fmtT(nowT())); err != nil {
					slog.Warn("记录 SSH 输入失败", "session", sessionID, "err", err)
				}
			}
			if _, err := io.WriteString(stdin, msg.Data); err != nil {
				break
			}
		case "resize":
			if msg.Cols >= 20 && msg.Rows >= 5 {
				_ = shell.WindowChange(msg.Rows, msg.Cols)
			}
		case "ping":
			send(sshTerminalFrame{Type: "pong"})
		}
	}
}

// sshStreamWriter 将 SSH 输出转发到 WebSocket，并累计输出字节数
type sshStreamWriter struct {
	bytes *atomic.Int64
	send  func([]byte)
}

func (w sshStreamWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.bytes.Add(int64(len(p)))
		w.send(p)
	}
	return len(p), nil
}

// extractTypedLines 从原始输入流中提取用户按回车提交的命令行，用于审计
func extractTypedLines(buf *strings.Builder, chunk string) []string {
	var lines []string
	for _, r := range chunk {
		if r == '\r' || r == '\n' {
			line := strings.TrimSpace(ansiPattern.ReplaceAllString(buf.String(), ""))
			if line != "" {
				lines = append(lines, line)
			}
			buf.Reset()
			continue
		}
		if r == 0x7f || r == '\b' {
			current := buf.String()
			if current != "" {
				buf.Reset()
				buf.WriteString(current[:len(current)-1])
			}
			continue
		}
		if r < 0x20 && r != '\t' {
			continue
		}
		buf.WriteRune(r)
		if buf.Len() > 1024 {
			buf.Reset()
		}
	}
	return lines
}

func queryInt(r *http.Request, key string, fallback int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "…"
}

// handleSSHSessions 返回最近的 SSH 会话记录
func (a *App) handleSSHSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	limit := clampInt(queryInt(r, "limit", 50), 1, 200)
	rows, err := a.db.QueryContext(r.Context(), `SELECT s.id, s.host_id, s.host_name, s.addr, s.actor, s.role, s.status, s.error,
		s.client_ip, s.started_at, s.ended_at, s.bytes_in, s.bytes_out,
		COALESCE(r.chunks,0), COALESCE(r.bytes,0), COALESCE(r.duration_ms,0), COALESCE(r.truncated,0)
		FROM ssh_sessions s LEFT JOIN ssh_recordings r ON r.session_id = s.id
		ORDER BY s.started_at DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 SSH 会话失败")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	for rows.Next() {
		var (
			id, hostName, addr, actor, role, status, errText, ip, startedAt, endedAt string
			hostID                                                                   int64
			bytesIn, bytesOut                                                        int64
			recordingChunks, recordingBytes, recordingMs, recordingTruncated         int64
		)
		if err := rows.Scan(&id, &hostID, &hostName, &addr, &actor, &role, &status, &errText, &ip,
			&startedAt, &endedAt, &bytesIn, &bytesOut,
			&recordingChunks, &recordingBytes, &recordingMs, &recordingTruncated); err != nil {
			continue
		}
		items = append(items, map[string]any{
			"id": id, "hostId": hostID, "hostName": hostName, "addr": addr,
			"actor": actor, "role": role, "status": status, "error": errText,
			"clientIp": ip, "startedAt": startedAt, "endedAt": endedAt,
			"bytesIn": bytesIn, "bytesOut": bytesOut,
			"hasRecording": recordingChunks > 0, "recordingBytes": recordingBytes,
			"recordingMs": recordingMs, "recordingTruncated": recordingTruncated == 1,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
