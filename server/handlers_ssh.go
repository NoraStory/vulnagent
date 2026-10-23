package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
