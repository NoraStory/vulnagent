package agentexec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOptions(root string) Options {
	return Options{
		ReadRoots:     []string{root},
		WriteRoots:    []string{root},
		AllowCommands: []string{"whoami", "echo"},
		SnapshotRoot:  filepath.Join(root, "snapshots"),
	}
}

func TestWriteFileDryRunAndAtomicWrite(t *testing.T) {
	root := t.TempDir()
	opts := testOptions(root)
	path := filepath.Join(root, "config.conf")

	raw, _ := json.Marshal(writeFileParams{Path: path, Content: "a=1\n", DryRun: true})
	res := Execute(context.Background(), Request{Action: ActionWriteFile, Params: raw}, opts)
	if res.Status != "succeeded" || !strings.Contains(res.Output, "dry-run") {
		t.Fatalf("dry-run 应成功：%+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("dry-run 不应创建文件")
	}

	raw, _ = json.Marshal(writeFileParams{Path: path, Content: "a=1\n"})
	res = Execute(context.Background(), Request{Action: ActionWriteFile, Params: raw}, opts)
	if res.Status != "succeeded" {
		t.Fatalf("写入失败：%+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "a=1\n" {
		t.Fatalf("文件内容异常：%q err=%v", data, err)
	}

	raw, _ = json.Marshal(writeFileParams{Path: path, Content: "a=2\n"})
	if res = Execute(context.Background(), Request{Action: ActionWriteFile, Params: raw}, opts); res.Status != "succeeded" {
		t.Fatalf("二次写入失败：%+v", res)
	}
	backups, _ := filepath.Glob(path + ".va-bak-*")
	if len(backups) != 1 {
		t.Fatalf("应生成一份备份，实际 %d", len(backups))
	}
	backup, _ := os.ReadFile(backups[0])
	if string(backup) != "a=1\n" {
		t.Fatalf("备份内容应为旧版本：%q", backup)
	}
}

func TestPathTraversalAndReadFile(t *testing.T) {
	root := t.TempDir()
	opts := testOptions(root)
	if err := os.WriteFile(filepath.Join(root, "app.log"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(readFileParams{Path: filepath.Join(root, "app.log")})
	res := Execute(context.Background(), Request{Action: ActionReadFile, Params: raw}, opts)
	if res.Status != "succeeded" || res.Output != "hello" {
		t.Fatalf("读取失败：%+v", res)
	}

	raw, _ = json.Marshal(writeFileParams{Path: filepath.Join(root, "..", "escape.conf"), Content: "x"})
	res = Execute(context.Background(), Request{Action: ActionWriteFile, Params: raw}, opts)
	if res.Status != "failed" || !strings.Contains(res.Error, "允许范围") {
		t.Fatalf("越界路径应被拒绝：%+v", res)
	}
}

func TestCommandAllowlistAndSubcommands(t *testing.T) {
	root := t.TempDir()
	opts := testOptions(root)

	raw, _ := json.Marshal(runCommandParams{Argv: []string{"whoami"}})
	res := Execute(context.Background(), Request{Action: ActionRunCommand, Params: raw}, opts)
	if res.Status != "succeeded" || strings.TrimSpace(res.Output) == "" {
		t.Fatalf("whoami 应执行成功：%+v", res)
	}

	raw, _ = json.Marshal(runCommandParams{Argv: []string{"curl", "http://example.com"}})
	res = Execute(context.Background(), Request{Action: ActionRunCommand, Params: raw}, opts)
	if res.Status != "failed" || !strings.Contains(res.Error, "白名单") {
		t.Fatalf("非白名单命令应被拒绝：%+v", res)
	}

	raw, _ = json.Marshal(runCommandParams{Argv: []string{"/tmp/whoami"}})
	res = Execute(context.Background(), Request{Action: ActionRunCommand, Params: raw}, opts)
	if res.Status != "failed" || !strings.Contains(res.Error, "分隔符") {
		t.Fatalf("带路径的命令应被拒绝：%+v", res)
	}

	if err := validateSubcommand("systemctl", []string{"systemctl", "restart", "nginx"}); err == nil {
		t.Fatal("systemctl restart 不应被只读命令放行")
	}
	if err := validateSubcommand("systemctl", []string{"systemctl", "status", "nginx"}); err != nil {
		t.Fatalf("systemctl status 应允许：%v", err)
	}
}

func TestSnapshotAndRestore(t *testing.T) {
	root := t.TempDir()
	opts := testOptions(root)
	path := filepath.Join(root, "app.conf")
	if err := os.WriteFile(path, []byte("version=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshotParams{Paths: []string{path}, Note: "变更前"})
	res := Execute(context.Background(), Request{Action: ActionSnapshot, Params: raw}, opts)
	if res.Status != "succeeded" || !strings.Contains(res.Output, "snapshotId") {
		t.Fatalf("创建快照失败：%+v", res)
	}
	var created struct {
		SnapshotID string `json:"snapshotId"`
	}
	if err := json.Unmarshal([]byte(res.Output), &created); err != nil || created.SnapshotID == "" {
		t.Fatalf("快照输出不可解析：%s", res.Output)
	}
	if err := os.WriteFile(path, []byte("version=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(restoreParams{SnapshotID: created.SnapshotID})
	res = Execute(context.Background(), Request{Action: ActionRestoreSnapshot, Params: raw}, opts)
	if res.Status != "succeeded" {
		t.Fatalf("恢复快照失败：%+v", res)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "version=1\n" {
		t.Fatalf("恢复内容不一致：%q", got)
	}
	if res := Execute(context.Background(), Request{Action: ActionRestoreSnapshot,
		Params: json.RawMessage(`{"snapshotId":"../../etc/passwd"}`)}, opts); res.Status != "failed" {
		t.Fatalf("非法快照 ID 应被拒绝：%+v", res)
	}

	// 篡改快照内容后必须因哈希不一致拒绝恢复
	dir := filepath.Join(opts.SnapshotRoot, created.SnapshotID)
	manifestData, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files []struct {
			Stored string `json:"stored"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil || len(manifest.Files) != 1 {
		t.Fatalf("快照清单异常：%v", err)
	}
	if err := os.WriteFile(manifest.Files[0].Stored, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(restoreParams{SnapshotID: created.SnapshotID})
	if res := Execute(context.Background(), Request{Action: ActionRestoreSnapshot, Params: raw}, opts); res.Status != "failed" ||
		!strings.Contains(res.Error, "校验失败") {
		t.Fatalf("篡改快照应被拒绝：%+v", res)
	}
}

func TestServiceActionValidation(t *testing.T) {
	root := t.TempDir()
	opts := testOptions(root)
	raw, _ := json.Marshal(serviceParams{Service: "nginx; rm -rf /", Action: "restart"})
	res := Execute(context.Background(), Request{Action: ActionServiceAction, Params: raw}, opts)
	if res.Status != "failed" || !strings.Contains(res.Error, "服务名") {
		t.Fatalf("非法服务名应被拒绝：%+v", res)
	}
	raw, _ = json.Marshal(serviceParams{Service: "nginx", Action: "explode"})
	res = Execute(context.Background(), Request{Action: ActionServiceAction, Params: raw}, opts)
	if res.Status != "failed" || !strings.Contains(res.Error, "服务动作") {
		t.Fatalf("非法服务动作应被拒绝：%+v", res)
	}
}
