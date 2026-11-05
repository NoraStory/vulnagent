package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// assetSSHLink 返回资产与 SSH 主机的关联结果，避免前端重复创建同一台主机。
type assetSSHLink struct {
	Host      sshHost `json:"host"`
	Created   bool    `json:"created"`
	MatchedBy string  `json:"matchedBy"`
}

// assetSSHAddresses 按优先级返回资产可用于 SSH 连接的地址：IP 优先，其次主机名。
func (a *App) assetSSHAddresses(ctx context.Context, assetID int64) ([]string, error) {
	var hostname, ip string
	err := a.db.QueryRowContext(ctx, `SELECT hostname, ip FROM assets WHERE id = ?`, assetID).Scan(&hostname, &ip)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 2)
	ip = strings.TrimSpace(ip)
	hostname = strings.TrimSpace(hostname)
	if ip != "" {
		out = append(out, ip)
	}
	if hostname != "" && !strings.EqualFold(hostname, ip) {
		out = append(out, hostname)
	}
	return out, nil
}

// findAssetSSHHost 查找资产已存在的 SSH 主机，优先匹配 IP，其次主机名。
func (a *App) findAssetSSHHost(ctx context.Context, assetID int64) (sshHost, string, error) {
	addresses, err := a.assetSSHAddresses(ctx, assetID)
	if err != nil {
		return sshHost{}, "", err
	}
	for _, addr := range addresses {
		row := a.db.QueryRowContext(ctx, `SELECT `+sshHostColumns+` FROM ssh_hosts
			WHERE lower(host) = lower(?) ORDER BY id ASC LIMIT 1`, addr)
		h, err := scanSSHHost(row)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return sshHost{}, "", err
		}
		return h, addr, nil
	}
	return sshHost{}, "", sql.ErrNoRows
}

// handleAssetSSHHost 返回资产已关联的 SSH 主机；未关联时返回 404。
func (a *App) handleAssetSSHHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	assetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	host, matchedBy, err := a.findAssetSSHHost(r.Context(), assetID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "该资产尚未关联 SSH 主机")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产 SSH 主机失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":      host.sanitize(),
		"matchedBy": matchedBy,
	})
}

// handleAssetSSHHostLink 从资产创建或更新 SSH 凭据，重复调用不会产生重复主机。
func (a *App) handleAssetSSHHostLink(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	assetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	addresses, err := a.assetSSHAddresses(r.Context(), assetID)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "资产不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取资产失败")
		return
	}
	if len(addresses) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "资产缺少 IP 与主机名，无法创建 SSH 主机")
		return
	}
	target := addresses[0]

	var in sshHostInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	hostPtr := target
	in.Host = &hostPtr
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		name := target
		in.Name = &name
	}
	h, err := normalizeSSHHostInput(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if h.Username == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "用户名不能为空")
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

	existing, matchedBy, findErr := a.findAssetSSHHost(r.Context(), assetID)
	if findErr == nil {
		_, err = a.db.ExecContext(r.Context(), `UPDATE ssh_hosts
			SET name = ?, port = ?, username = ?, auth_type = ?, secret = ?, passphrase = ?, updated_at = ?
			WHERE id = ?`,
			h.Name, h.Port, h.Username, h.AuthType, sealed, passphrase, now, existing.ID)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				writeErr(w, http.StatusConflict, "host_exists", "该主机与账号已存在，请改用已有凭据")
				return
			}
			writeErr(w, http.StatusInternalServerError, "internal_error", "更新 SSH 主机失败")
			return
		}
		a.invalidateSSHHost(existing.ID)
		existing.Name, existing.Port = h.Name, h.Port
		existing.Username, existing.AuthType = h.Username, h.AuthType
		existing.Secret, existing.Passphrase = sealed, passphrase
		existing.HasSecret = true
		existing.UpdatedAt = now
		a.audit(r, "ssh.host.link", h.Name, fmt.Sprintf("%s@%s:%d · asset:%d", h.Username, target, h.Port, assetID))
		writeJSON(w, http.StatusOK, map[string]any{
			"host":      existing.sanitize(),
			"created":   false,
			"matchedBy": matchedBy,
		})
		return
	}
	if !errors.Is(findErr, sql.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询资产 SSH 主机失败")
		return
	}

	res, err := a.db.ExecContext(r.Context(), `INSERT INTO ssh_hosts
		(name, host, port, username, auth_type, secret, passphrase, host_key, note, tags, created_by, created_at, updated_at, last_connected_at, gpu_accel)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.Name, target, h.Port, h.Username, h.AuthType, sealed, passphrase, "", h.Note, h.Tags, u.Username, now, now, "", h.GPUAccel)
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
	h.Host = target
	h.Secret, h.Passphrase = sealed, passphrase
	h.HasSecret = true
	h.CreatedBy = u.Username
	h.CreatedAt, h.UpdatedAt = now, now
	a.audit(r, "ssh.host.link", h.Name, fmt.Sprintf("%s@%s:%d · asset:%d", h.Username, target, h.Port, assetID))
	writeJSON(w, http.StatusCreated, map[string]any{
		"host":      h.sanitize(),
		"created":   true,
		"matchedBy": target,
	})
}
