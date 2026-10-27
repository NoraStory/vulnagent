package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

func TestNormalizeSFTPPath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"/var/log", "/var/log", false},
		{"var/log", "/var/log", false},
		{"/var/log/../log/./syslog", "/var/log/syslog", false},
		{"/", "/", false},
		{"", "", true},
		{"/tmp/\x00evil", "", true},
	}
	for _, item := range cases {
		got, err := normalizeSFTPPath(item.in)
		if item.wantErr {
			if err == nil {
				t.Fatalf("%q 应被拒绝", item.in)
			}
			continue
		}
		if err != nil || got != item.want {
			t.Fatalf("%q 解析为 %q（err=%v），期望 %q", item.in, got, err, item.want)
		}
	}
}

func TestDeleteRootRejected(t *testing.T) {
	app := &App{db: nil}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/ssh/files?hostId=1&path=%2F", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyUser{}, User{Username: "tester", Name: "Tester", Role: "operator"}))
	rec := httptest.NewRecorder()
	app.handleSFTPDelete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("删除根目录应返回 400，实际 %d", rec.Code)
	}
}

func TestSFTPClientOperations(t *testing.T) {
	addr, _, _ := startTestSSHServerEx(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	db, err := openDB(filepath.Join(t.TempDir(), "sftp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app := &App{db: db, dataDir: t.TempDir()}
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	now := fmtT(nowT())
	res, err := db.Exec(`INSERT INTO ssh_hosts
		(name, host, port, username, auth_type, secret, passphrase, host_key, note, tags, created_by, created_at, updated_at, last_connected_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"test", host, port, "tester", "password", sealed, "", "", "", "", "tester", now, now, "")
	if err != nil {
		t.Fatal(err)
	}
	hostID, _ := res.LastInsertId()

	conn, err := app.openSFTP(context.Background(), hostID)
	if err != nil {
		t.Fatalf("打开 SFTP 失败：%v", err)
	}
	defer conn.Close()

	file, err := conn.sftp.Create("hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("hello sftp")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := conn.sftp.Stat("hello.txt")
	if err != nil || info.Size() != 10 {
		t.Fatalf("文件写入异常：%+v err=%v", info, err)
	}

	if err := conn.sftp.Mkdir("docs"); err != nil {
		t.Fatal(err)
	}
	if err := conn.sftp.Rename("hello.txt", "docs/hello.txt"); err != nil {
		t.Fatal(err)
	}
	entries, err := conn.sftp.ReadDir("docs")
	if err != nil || len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Fatalf("目录列表异常：%+v err=%v", entries, err)
	}

	read, err := conn.sftp.Open("docs/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ := read.Read(buf)
	_ = read.Close()
	if string(buf[:n]) != "hello sftp" {
		t.Fatalf("文件内容异常：%q", string(buf[:n]))
	}

	if err := conn.sftp.Remove("docs/hello.txt"); err != nil {
		t.Fatal(err)
	}
	if err := conn.sftp.RemoveDirectory("docs"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.sftp.Stat("docs"); err == nil {
		t.Fatal("目录应已删除")
	}

	hostRow, err := app.getSSHHost(context.Background(), hostID)
	if err != nil || hostRow.HostKey == "" {
		t.Fatalf("首次连接应记录主机指纹：%+v err=%v", hostRow, err)
	}
}
