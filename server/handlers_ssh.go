package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/sshscan"
)

type sshScanRequest struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	PrivateKey         string `json:"privateKey"`
	Passphrase         string `json:"passphrase"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
}

// handleSSHScan 无 Agent 兜底：控制面直连目标机执行只读采集脚本。
// 凭据仅用于本次连接，不写入数据库与日志。
func (a *App) handleSSHScan(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req sshScanRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	req.Username = strings.TrimSpace(req.Username)
	req.PrivateKey = strings.TrimSpace(req.PrivateKey)

	if req.Host == "" || req.Username == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机与用户名不能为空")
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "需要口令或私钥")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}

	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()

	res, err := sshscan.Scan(ctx, sshscan.Config{
		Host:               req.Host,
		Port:               req.Port,
		User:               req.Username,
		Password:           req.Password,
		PrivateKeyPEM:      req.PrivateKey,
		Passphrase:         req.Passphrase,
		HostKeyFingerprint: req.HostKeyFingerprint,
		Timeout:            25 * time.Second,
	})
	if err != nil {
		a.auditAs(u.Name, u.Role, clientIP(r), r.UserAgent(), "scan.ssh", req.Host+"@"+req.Username,
			"SSH 兜底采集失败："+err.Error())
		writeErr(w, http.StatusBadGateway, "ssh_scan_failed", err.Error())
		return
	}
	if len(res.Components) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "no_components",
			"未采集到软件包：目标可能不是 deb/rpm/apk 发行版，或账号权限不足")
		return
	}

	ip := ""
	if net.ParseIP(req.Host) != nil {
		ip = req.Host
	}
	outcome, err := a.ingestComponents(req.Host, ip, res.OS, res.OSVersion, "ssh", res.Components)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db_error", "写入资产失败")
		return
	}

	a.auditAs(u.Name, u.Role, clientIP(r), r.UserAgent(), "scan.ssh", req.Host+"@"+req.Username,
		fmt.Sprintf("SSH 兜底采集成功：%d 个组件，新增 %d 条漏洞", outcome.Components, outcome.Created))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"assetId":            outcome.AssetID,
		"components":         outcome.Components,
		"created":            outcome.Created,
		"updated":            outcome.Updated,
		"verified":           outcome.Verified,
		"closed":             outcome.Closed,
		"reopened":           outcome.Reopened,
		"os":                 res.OS,
		"osVersion":          res.OSVersion,
		"hostKeyFingerprint": res.HostKeyFingerprint,
		"elapsedMs":          res.Elapsed.Milliseconds(),
	})
}

// handleSSHHostScan 复用已保存的 SSH 主机凭据做一次只读软件清单采集，
// 结果直接进入资产与漏洞流水线，让终端主机可以参与现有漏洞运营。
func (a *App) handleSSHHostScan(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "id 无效")
		return
	}
	host, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	secret, err := a.openSSHSecret(host.Secret)
	if err != nil || secret == "" {
		writeErr(w, http.StatusBadRequest, "credential_error", "主机凭据不可用，请重新编辑保存")
		return
	}
	passphrase := ""
	if host.Passphrase != "" {
		if passphrase, err = a.openSSHSecret(host.Passphrase); err != nil {
			writeErr(w, http.StatusBadRequest, "credential_error", "私钥口令解密失败")
			return
		}
	}
	password, privateKey := "", ""
	if host.AuthType == "key" {
		privateKey = secret
	} else {
		password = secret
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := sshscan.Scan(ctx, sshscan.Config{
		Host:               host.Host,
		Port:               host.Port,
		User:               host.Username,
		Password:           password,
		PrivateKeyPEM:      privateKey,
		Passphrase:         passphrase,
		HostKeyFingerprint: host.HostKey,
		Timeout:            30 * time.Second,
	})
	if err != nil {
		a.audit(r, "scan.ssh", host.Name+"@"+host.Username, "SSH 采集失败："+err.Error())
		writeErr(w, http.StatusBadGateway, "ssh_scan_failed", err.Error())
		return
	}
	if len(res.Components) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "no_components",
			"未采集到软件包：目标可能不是 deb/rpm/apk 发行版，或账号权限不足")
		return
	}
	if host.HostKey == "" && res.HostKeyFingerprint != "" {
		_, _ = a.db.ExecContext(r.Context(), `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			res.HostKeyFingerprint, fmtT(nowT()), host.ID)
	}
	ip := ""
	if net.ParseIP(host.Host) != nil {
		ip = host.Host
	}
	outcome, err := a.ingestComponents(host.Host, ip, res.OS, res.OSVersion, "ssh", res.Components)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db_error", "写入资产失败")
		return
	}
	a.audit(r, "scan.ssh", host.Name+"@"+host.Username,
		fmt.Sprintf("SSH 主机扫描成功：%d 个组件，新增 %d / 更新 %d 条漏洞", outcome.Components, outcome.Created, outcome.Updated))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"assetId":            outcome.AssetID,
		"hostId":             host.ID,
		"hostName":           host.Name,
		"host":               host.Host,
		"username":           host.Username,
		"scanUser":           u.Username,
		"components":         outcome.Components,
		"created":            outcome.Created,
		"updated":            outcome.Updated,
		"verified":           outcome.Verified,
		"closed":             outcome.Closed,
		"reopened":           outcome.Reopened,
		"os":                 res.OS,
		"osVersion":          res.OSVersion,
		"hostKeyFingerprint": res.HostKeyFingerprint,
		"elapsedMs":          res.Elapsed.Milliseconds(),
	})
}
