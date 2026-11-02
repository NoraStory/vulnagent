package main

import (
	"context"
	"net"
	"time"

	"vulnagent/server/internal/sshscan"
)

// sshHostScanResult 一次 SSH 只读采集的汇总结果
type sshHostScanResult struct {
	AssetID     int64
	HostID      int64
	HostName    string
	Host        string
	Username    string
	ScanUser    string
	Components  int
	Created     int
	Updated     int
	Verified    int
	Closed      int
	Reopened    int
	OS          string
	OSVersion   string
	Fingerprint string
	ElapsedMs   int64
}

// sshScanFailure 携带 HTTP 状态与错误码，供 handler 保持既有契约
type sshScanFailure struct {
	Status  int
	Code    string
	Message string
}

func (e *sshScanFailure) Error() string { return e.Message }

// scanSSHHost 复用已保存凭据做只读软件清单采集，并写入资产与漏洞流水线。
func (a *App) scanSSHHost(ctx context.Context, host sshHost, scanUser string) (sshHostScanResult, error) {
	result := sshHostScanResult{
		HostID: host.ID, HostName: host.Name, Host: host.Host, Username: host.Username, ScanUser: scanUser,
	}
	secret, err := a.openSSHSecret(host.Secret)
	if err != nil || secret == "" {
		return result, &sshScanFailure{Status: 400, Code: "credential_error", Message: "主机凭据不可用，请重新编辑保存"}
	}
	passphrase := ""
	if host.Passphrase != "" {
		if passphrase, err = a.openSSHSecret(host.Passphrase); err != nil {
			return result, &sshScanFailure{Status: 400, Code: "credential_error", Message: "私钥口令解密失败"}
		}
	}
	password, privateKey := "", ""
	if host.AuthType == "key" {
		privateKey = secret
	} else {
		password = secret
	}

	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := sshscan.Scan(scanCtx, sshscan.Config{
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
		return result, &sshScanFailure{Status: 502, Code: "ssh_scan_failed", Message: err.Error()}
	}
	if len(res.Components) == 0 {
		return result, &sshScanFailure{Status: 422, Code: "no_components",
			Message: "未采集到软件包：目标可能不是 deb/rpm/apk 发行版，或账号权限不足"}
	}
	if host.HostKey == "" && res.HostKeyFingerprint != "" {
		_, _ = a.db.ExecContext(ctx, `UPDATE ssh_hosts SET host_key=?, updated_at=? WHERE id=?`,
			res.HostKeyFingerprint, fmtT(nowT()), host.ID)
	}
	ip := ""
	if net.ParseIP(host.Host) != nil {
		ip = host.Host
	}
	outcome, err := a.ingestComponents(host.Host, ip, res.OS, res.OSVersion, "ssh", res.Components)
	if err != nil {
		return result, &sshScanFailure{Status: 500, Code: "db_error", Message: "写入资产失败"}
	}
	result.AssetID = outcome.AssetID
	result.Components = outcome.Components
	result.Created = outcome.Created
	result.Updated = outcome.Updated
	result.Verified = outcome.Verified
	result.Closed = outcome.Closed
	result.Reopened = outcome.Reopened
	result.OS = res.OS
	result.OSVersion = res.OSVersion
	result.Fingerprint = res.HostKeyFingerprint
	result.ElapsedMs = res.Elapsed.Milliseconds()
	return result, nil
}
