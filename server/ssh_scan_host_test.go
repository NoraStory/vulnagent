package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
)

func TestSSHHostScanEndpoint(t *testing.T) {
	addr, fingerprint, _ := startTestSSHServerEx(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	app := newSSHWorkspaceApp(t)
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	now := fmtT(nowT())
	res, err := app.db.Exec(`INSERT INTO ssh_hosts
		(name, host, port, username, auth_type, secret, passphrase, host_key, note, tags, created_by, created_at, updated_at, last_connected_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"扫描测试机", host, port, "tester", "password", sealed, "", fingerprint, "", "", "tester", now, now, "")
	if err != nil {
		t.Fatal(err)
	}
	hostID, _ := res.LastInsertId()

	rec := serveSSHWorkspace(app, http.MethodPost, fmt.Sprintf("/api/v1/ssh/hosts/%d/scan", hostID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("SSH 主机扫描失败：%d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		AssetID    int64  `json:"assetId"`
		Components int    `json:"components"`
		OS         string `json:"os"`
		HostName   string `json:"hostName"`
		Username   string `json:"username"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.AssetID == 0 || result.Components != 2 || result.OS != "ubuntu" {
		t.Fatalf("扫描结果异常：%+v", result)
	}
	if result.HostName != "扫描测试机" || result.Username != "tester" {
		t.Fatalf("主机信息异常：%+v", result)
	}

	var assets int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id=?`, result.AssetID).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Fatalf("资产未写入，实际 %d 条", assets)
	}
}
