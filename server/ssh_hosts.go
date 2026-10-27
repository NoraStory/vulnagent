package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshHostCredentialFile 保存本机 SSH 凭据加密密钥，首次使用时自动生成（0600）
const sshHostCredentialFile = "ssh.key"

// sshHost 一台可连接的 SSH 主机；Secret 与 Passphrase 仅在服务端使用，永不返回给前端
type sshHost struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	AuthType        string `json:"authType"`
	HostKey         string `json:"hostKey"`
	Note            string `json:"note"`
	Tags            string `json:"tags"`
	CreatedBy       string `json:"createdBy"`
	CreatedAt       string `json:"createdAt"`
	UpdatedAt       string `json:"updatedAt"`
	LastConnectedAt string `json:"lastConnectedAt"`
	HasSecret       bool   `json:"hasSecret"`

	Secret     string `json:"-"`
	Passphrase string `json:"-"`
}

const sshHostColumns = `id, name, host, port, username, auth_type, secret, passphrase, host_key,
	note, tags, created_by, created_at, updated_at, last_connected_at`

func scanSSHHost(row interface{ Scan(dest ...any) error }) (sshHost, error) {
	var h sshHost
	err := row.Scan(&h.ID, &h.Name, &h.Host, &h.Port, &h.Username, &h.AuthType, &h.Secret, &h.Passphrase,
		&h.HostKey, &h.Note, &h.Tags, &h.CreatedBy, &h.CreatedAt, &h.UpdatedAt, &h.LastConnectedAt)
	h.HasSecret = h.Secret != ""
	return h, err
}

func (h sshHost) addr() string {
	return net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
}

// ---------- 凭据加密 ----------

// sshAEADFor 惰性加载或生成 32 字节密钥，并使用 AES-256-GCM 保护凭据
func (a *App) sshAEADFor() (cipher.AEAD, error) {
	a.sshOnce.Do(func() {
		key, err := a.loadSSHKey()
		if err != nil {
			a.sshKeyErr = err
			return
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			a.sshKeyErr = err
			return
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			a.sshKeyErr = err
			return
		}
		a.sshAEAD = aead
	})
	return a.sshAEAD, a.sshKeyErr
}

func (a *App) loadSSHKey() ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv("VA_SSH_KEY")); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, errors.New("VA_SSH_KEY 必须是 32 字节密钥的 base64")
		}
		return key, nil
	}
	path := filepath.Join(a.dataDir, sshHostCredentialFile)
	if data, err := os.ReadFile(path); err == nil {
		if len(data) == 32 {
			return data, nil
		}
		if key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); decErr == nil && len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf("SSH 凭据密钥文件格式无效：%s", path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (a *App) sealSSHSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	aead, err := a.sshAEADFor()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(plain), []byte("vulnagent-ssh"))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (a *App) openSSHSecret(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	aead, err := a.sshAEADFor()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("凭据密文格式错误")
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("凭据密文过短")
	}
	nonce, data := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, data, []byte("vulnagent-ssh"))
	if err != nil {
		return "", errors.New("凭据解密失败，可能更换过数据目录")
	}
	return string(plain), nil
}

// ---------- 查询与校验 ----------

func (a *App) listSSHHosts(ctx context.Context) ([]sshHost, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT `+sshHostColumns+` FROM ssh_hosts ORDER BY name COLLATE NOCASE ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]sshHost, 0, 8)
	for rows.Next() {
		h, err := scanSSHHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (a *App) getSSHHost(ctx context.Context, id int64) (sshHost, error) {
	row := a.db.QueryRowContext(ctx, `SELECT `+sshHostColumns+` FROM ssh_hosts WHERE id = ?`, id)
	h, err := scanSSHHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return sshHost{}, sql.ErrNoRows
	}
	return h, err
}

type sshHostInput struct {
	Name       *string `json:"name"`
	Host       *string `json:"host"`
	Port       *int    `json:"port"`
	Username   *string `json:"username"`
	AuthType   *string `json:"authType"`
	Password   *string `json:"password"`
	PrivateKey *string `json:"privateKey"`
	Passphrase *string `json:"passphrase"`
	Note       *string `json:"note"`
	Tags       *string `json:"tags"`
	ClearKey   bool    `json:"clearHostKey"`
}

func normalizeSSHHostInput(in sshHostInput) (sshHost, error) {
	var h sshHost
	if in.Name != nil {
		h.Name = strings.TrimSpace(*in.Name)
	}
	if in.Host != nil {
		h.Host = strings.TrimSpace(*in.Host)
	}
	if in.Username != nil {
		h.Username = strings.TrimSpace(*in.Username)
	}
	if in.AuthType != nil {
		h.AuthType = strings.ToLower(strings.TrimSpace(*in.AuthType))
	}
	if in.Note != nil {
		h.Note = strings.TrimSpace(*in.Note)
	}
	if in.Tags != nil {
		h.Tags = strings.TrimSpace(*in.Tags)
	}
	h.Port = 22
	if in.Port != nil {
		h.Port = *in.Port
	}
	if h.AuthType == "" {
		h.AuthType = "password"
	}
	if h.AuthType != "password" && h.AuthType != "key" {
		return h, errors.New("认证方式必须为 password 或 key")
	}
	if h.Host != "" {
		if strings.ContainsAny(h.Host, " /\\") || strings.Contains(h.Host, "://") {
			return h, errors.New("主机地址不能包含协议前缀或空格")
		}
		if len(h.Host) > 253 {
			return h, errors.New("主机地址过长")
		}
	}
	if h.Port <= 0 || h.Port > 65535 {
		return h, errors.New("端口必须在 1-65535 之间")
	}
	if len(h.Name) > 80 || len(h.Username) > 64 || len(h.Note) > 500 || len(h.Tags) > 200 {
		return h, errors.New("字段长度超出限制")
	}
	return h, nil
}

// sanitize 返回可安全下发给前端的主机信息
func (h sshHost) sanitize() sshHost {
	if h.Secret != "" {
		h.HasSecret = true
	}
	h.Secret = ""
	h.Passphrase = ""
	return h
}

// ---------- HTTP 处理 ----------

func (a *App) handleSSHHosts(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	items, err := a.listSSHHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 SSH 主机失败")
		return
	}
	for i := range items {
		items[i] = items[i].sanitize()
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleSSHHostCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var in sshHostInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	h, err := normalizeSSHHostInput(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if h.Name == "" || h.Host == "" || h.Username == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "名称、主机与用户名不能为空")
		return
	}
	secret := ""
	if in.Password != nil {
		secret = *in.Password
	}
	if h.AuthType == "key" {
		if in.PrivateKey == nil || strings.TrimSpace(*in.PrivateKey) == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "私钥认证需要填写私钥内容")
			return
		}
		secret = *in.PrivateKey
	}
	if secret == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "口令认证需要填写口令")
		return
	}
	if _, err := ssh.ParsePrivateKey([]byte(secret)); err != nil && h.AuthType == "key" {
		if in.Passphrase == nil || strings.TrimSpace(*in.Passphrase) == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "私钥解析失败，请检查内容或补充私钥口令")
			return
		}
	}
	sealed, err := a.sealSSHSecret(secret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存凭据失败")
		return
	}
	passphrase := ""
	if in.Passphrase != nil && strings.TrimSpace(*in.Passphrase) != "" {
		if passphrase, err = a.sealSSHSecret(*in.Passphrase); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "保存凭据失败")
			return
		}
	}
	now := fmtT(nowT())
	res, err := a.db.ExecContext(r.Context(), `INSERT INTO ssh_hosts
		(name, host, port, username, auth_type, secret, passphrase, host_key, note, tags, created_by, created_at, updated_at, last_connected_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.Name, h.Host, h.Port, h.Username, h.AuthType, sealed, passphrase, "", h.Note, h.Tags, u.Username, now, now, "")
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "host_exists", "该主机与账号已存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建 SSH 主机失败")
		return
	}
	id, _ := res.LastInsertId()
	h.ID = id
	h.Secret, h.Passphrase = sealed, passphrase
	h.HasSecret = true
	a.audit(r, "ssh.host.create", h.Name, fmt.Sprintf("%s@%s:%d", h.Username, h.Host, h.Port))
	writeJSON(w, http.StatusCreated, map[string]any{"host": h.sanitize()})
}

func (a *App) handleSSHHostUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	current, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	var in sshHostInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	patch, err := normalizeSSHHostInput(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	next := current
	if in.Name != nil {
		next.Name = patch.Name
	}
	if in.Host != nil {
		next.Host = patch.Host
	}
	if in.Port != nil {
		next.Port = patch.Port
	}
	if in.Username != nil {
		next.Username = patch.Username
	}
	if in.AuthType != nil {
		next.AuthType = patch.AuthType
	}
	if in.Note != nil {
		next.Note = patch.Note
	}
	if in.Tags != nil {
		next.Tags = patch.Tags
	}
	if next.Name == "" || next.Host == "" || next.Username == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "名称、主机与用户名不能为空")
		return
	}
	if in.AuthType != nil && patch.AuthType != current.AuthType {
		if patch.AuthType == "password" && (in.Password == nil || *in.Password == "") {
			writeErr(w, http.StatusBadRequest, "bad_request", "切换为口令认证时需要填写新口令")
			return
		}
		if patch.AuthType == "key" && (in.PrivateKey == nil || strings.TrimSpace(*in.PrivateKey) == "") {
			writeErr(w, http.StatusBadRequest, "bad_request", "切换为私钥认证时需要粘贴私钥内容")
			return
		}
	}
	if in.ClearKey || next.Host != current.Host || next.Port != current.Port {
		next.HostKey = ""
	}
	secret := current.Secret
	if in.Password != nil && *in.Password != "" {
		secret, err = a.sealSSHSecret(*in.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "保存凭据失败")
			return
		}
	}
	if in.PrivateKey != nil && strings.TrimSpace(*in.PrivateKey) != "" {
		secret, err = a.sealSSHSecret(*in.PrivateKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "保存凭据失败")
			return
		}
	}
	passphrase := current.Passphrase
	if in.Passphrase != nil {
		if strings.TrimSpace(*in.Passphrase) == "" {
			passphrase = ""
		} else if passphrase, err = a.sealSSHSecret(*in.Passphrase); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "保存凭据失败")
			return
		}
	}
	now := fmtT(nowT())
	if _, err := a.db.ExecContext(r.Context(), `UPDATE ssh_hosts SET name=?, host=?, port=?, username=?, auth_type=?,
		secret=?, passphrase=?, host_key=?, note=?, tags=?, updated_at=? WHERE id=?`,
		next.Name, next.Host, next.Port, next.Username, next.AuthType, secret, passphrase, next.HostKey,
		next.Note, next.Tags, now, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "host_exists", "该主机与账号已存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新 SSH 主机失败")
		return
	}
	next.ID = id
	next.Secret, next.Passphrase = secret, passphrase
	next.HasSecret = secret != ""
	next.UpdatedAt = now
	a.audit(r, "ssh.host.update", next.Name, fmt.Sprintf("%s@%s:%d", next.Username, next.Host, next.Port))
	writeJSON(w, http.StatusOK, map[string]any{"host": next.sanitize()})
}

func (a *App) handleSSHHostDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	h, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM ssh_hosts WHERE id = ?`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除 SSH 主机失败")
		return
	}
	a.audit(r, "ssh.host.delete", h.Name, fmt.Sprintf("%s@%s:%d", h.Username, h.Host, h.Port))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleSSHHostTest(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	h, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	start := time.Now()
	client, fingerprint, err := a.dialSSHHost(r.Context(), h)
	if err != nil {
		a.audit(r, "ssh.host.test", h.Name, "失败："+err.Error())
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	defer client.Close()
	if h.HostKey == "" {
		if _, err := a.db.ExecContext(r.Context(), `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			fingerprint, fmtT(nowT()), id); err != nil {
			slog.Warn("保存 SSH 主机指纹失败", "host", h.Name, "err", err)
		}
	}
	a.audit(r, "ssh.host.test", h.Name, "成功："+h.addr())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"fingerprint":   fingerprint,
		"serverVersion": string(client.ServerVersion()),
		"elapsedMs":     time.Since(start).Milliseconds(),
		"trusted":       h.HostKey == "" || strings.EqualFold(h.HostKey, fingerprint),
		"actor":         u.Username,
	})
}

// dialSSHHost 使用主机配置建立 SSH 连接；首次连接采用 TOFU 记录指纹，之后强制校验
func (a *App) dialSSHHost(ctx context.Context, h sshHost) (*ssh.Client, string, error) {
	secret, err := a.openSSHSecret(h.Secret)
	if err != nil {
		return nil, "", err
	}
	passphrase := ""
	if h.Passphrase != "" {
		if passphrase, err = a.openSSHSecret(h.Passphrase); err != nil {
			return nil, "", err
		}
	}
	var auth []ssh.AuthMethod
	if h.AuthType == "key" {
		var (
			signer ssh.Signer
			err    error
		)
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(secret), []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(secret))
		}
		if err != nil {
			return nil, "", fmt.Errorf("解析私钥失败：%w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		auth = append(auth, ssh.Password(secret))
	}

	observed := ""
	config := &ssh.ClientConfig{
		User: h.Username,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed = ssh.FingerprintSHA256(key)
			if h.HostKey != "" && !strings.EqualFold(h.HostKey, observed) {
				return fmt.Errorf("主机指纹不匹配：期望 %s，实际 %s", h.HostKey, observed)
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	dialer := net.Dialer{Timeout: 12 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", h.addr())
	if err != nil {
		return nil, "", fmt.Errorf("连接 %s 失败：%w", h.addr(), err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, h.addr(), config)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("SSH 握手失败：%w", err)
	}
	return ssh.NewClient(clientConn, chans, reqs), observed, nil
}
