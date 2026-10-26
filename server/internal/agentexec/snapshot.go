package agentexec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type snapshotParams struct {
	Paths []string `json:"paths"`
	Note  string   `json:"note"`
}

type snapshotFile struct {
	Original string `json:"original"`
	Stored   string `json:"stored"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type snapshotManifest struct {
	ID        string         `json:"id"`
	Note      string         `json:"note"`
	CreatedAt string         `json:"createdAt"`
	Files     []snapshotFile `json:"files"`
}

type restoreParams struct {
	SnapshotID string   `json:"snapshotId"`
	Files      []string `json:"files"`
}

var snapshotIDPattern = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$`)

func createSnapshot(raw json.RawMessage, opts Options) (string, error) {
	var p snapshotParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	if len(p.Paths) == 0 || len(p.Paths) > 50 {
		return "", fmt.Errorf("paths 数量需在 1-50 之间")
	}
	if opts.SnapshotRoot == "" {
		return "", fmt.Errorf("未配置快照目录")
	}
	if err := os.MkdirAll(opts.SnapshotRoot, 0o700); err != nil {
		return "", err
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	id := time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(suffix)
	dir := filepath.Join(opts.SnapshotRoot, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return "", err
	}
	manifest := snapshotManifest{ID: id, Note: strings.TrimSpace(p.Note), CreatedAt: time.Now().Format(time.RFC3339)}
	for index, rawPath := range p.Paths {
		path, err := safePath(rawPath, opts.ReadRoots)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("仅支持快照普通文件：%s", path)
		}
		if info.Size() > 20<<20 {
			return "", fmt.Errorf("文件超过 20MB，不支持快照：%s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		stored := filepath.Join(dir, "files", fmt.Sprintf("%02d-%s", index, filepath.Base(path)))
		if err := os.WriteFile(stored, data, 0o600); err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, snapshotFile{
			Original: path, Stored: stored, Size: info.Size(), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	encoded, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), encoded, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf(`{"snapshotId":%q,"dir":%q,"files":%d}`, id, dir, len(manifest.Files)), nil
}

func restoreSnapshot(raw json.RawMessage, opts Options) (string, error) {
	var p restoreParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	if !snapshotIDPattern.MatchString(p.SnapshotID) {
		return "", fmt.Errorf("快照 ID 格式不合法")
	}
	dir := filepath.Join(opts.SnapshotRoot, p.SnapshotID)
	if err := ensureRealPath(dir, opts.WriteRoots); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return "", fmt.Errorf("读取快照清单失败：%w", err)
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", err
	}
	selected := map[string]bool{}
	for _, path := range p.Files {
		selected[path] = true
	}
	restored := 0
	for _, file := range manifest.Files {
		if len(selected) > 0 && !selected[file.Original] {
			continue
		}
		target, err := safePath(file.Original, opts.WriteRoots)
		if err != nil {
			return "", err
		}
		if err := ensureRealPath(filepath.Dir(target), opts.WriteRoots); err != nil {
			return "", err
		}
		content, err := os.ReadFile(file.Stored)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return "", fmt.Errorf("快照文件校验失败：%s", file.Original)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			return "", err
		}
		restored++
	}
	return fmt.Sprintf("已从快照 %s 恢复 %d 个文件", p.SnapshotID, restored), nil
}

type packageParams struct {
	Package string `json:"package"`
	Action  string `json:"action"`
	Version string `json:"version"`
	DryRun  bool   `json:"dryRun"`
}

var packagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,127}$`)

func packageAction(ctx context.Context, raw json.RawMessage) (string, error) {
	var p packageParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	if !packagePattern.MatchString(p.Package) {
		return "", fmt.Errorf("包名不合法")
	}
	if p.Version != "" && !packagePattern.MatchString(p.Version) {
		return "", fmt.Errorf("版本号不合法")
	}
	action := strings.ToLower(strings.TrimSpace(p.Action))
	if action == "" {
		action = "upgrade"
	}
	if action != "upgrade" && action != "install" {
		return "", fmt.Errorf("包动作仅支持 upgrade/install")
	}
	argv, err := packageCommand(p, action)
	if err != nil {
		return "", err
	}
	plan := strings.Join(argv, " ")
	if p.DryRun {
		return "dry-run: " + plan, nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	text := truncate(string(out), 256<<10)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return text, fmt.Errorf("包操作超时")
		}
		return text, err
	}
	return text, nil
}

func packageCommand(p packageParams, action string) ([]string, error) {
	target := p.Package
	if p.Version != "" {
		if runtime.GOOS == "windows" {
			target = p.Package
		} else {
			target = p.Package + "=" + p.Version
		}
	}
	switch {
	case hasCommand("apt-get"):
		if action == "upgrade" && p.Version == "" {
			return []string{"apt-get", "install", "-y", "--only-upgrade", p.Package}, nil
		}
		return []string{"apt-get", "install", "-y", target}, nil
	case hasCommand("dnf"):
		if action == "upgrade" {
			return []string{"dnf", "upgrade", "-y", target}, nil
		}
		return []string{"dnf", "install", "-y", target}, nil
	case hasCommand("apk"):
		if action == "upgrade" {
			return []string{"apk", "add", "-u", target}, nil
		}
		return []string{"apk", "add", target}, nil
	case hasCommand("zypper"):
		return []string{"zypper", "--non-interactive", "update", target}, nil
	case hasCommand("pacman"):
		return []string{"pacman", "-S", "--noconfirm", p.Package}, nil
	case hasCommand("winget"):
		if action == "upgrade" {
			return []string{"winget", "upgrade", "--id", p.Package, "--silent",
				"--accept-package-agreements", "--accept-source-agreements"}, nil
		}
		return []string{"winget", "install", "--id", p.Package, "--silent",
			"--accept-package-agreements", "--accept-source-agreements"}, nil
	}
	return nil, fmt.Errorf("未找到受支持的包管理器")
}

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
