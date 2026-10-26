// Package agentexec 在主机侧执行受控动作：只读命令、文件读写与服务操作。
// 所有动作使用结构化参数与白名单校验，不接受任意 shell 字符串。
package agentexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// 动作常量
const (
	ActionReadFile        = "read_file"
	ActionWriteFile       = "write_file"
	ActionRunCommand      = "run_command"
	ActionServiceAction   = "service_action"
	ActionSnapshot        = "snapshot"
	ActionRestoreSnapshot = "restore_snapshot"
	ActionPackageAction   = "package_action"
)

// Request 一次主机动作请求
type Request struct {
	JobID  string          `json:"jobId"`
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

// Result 执行结果
type Result struct {
	Status     string `json:"status"`
	Output     string `json:"output"`
	Error      string `json:"error"`
	ExitCode   int    `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	Retryable  bool   `json:"retryable"`
}

// Options 执行策略
type Options struct {
	ReadRoots     []string
	WriteRoots    []string
	AllowCommands []string
	SnapshotRoot  string
	HelperMode    bool
}

// DefaultOptions 按平台给出最小可用根目录与命令白名单
func DefaultOptions() Options {
	if runtime.GOOS == "windows" {
		return Options{
			ReadRoots:     []string{`C:\ProgramData`, `C:\Windows\Logs`, `C:\Temp\vulnagent`},
			WriteRoots:    []string{`C:\ProgramData\VulnAgent`, `C:\Temp\vulnagent`},
			AllowCommands: []string{"sc", "wevtutil", "netstat", "ipconfig", "systeminfo", "whoami", "hostname", "type", "dir"},
			SnapshotRoot:  `C:\ProgramData\VulnAgent\snapshots`,
		}
	}
	return Options{
		ReadRoots:     []string{"/etc", "/var/log", "/proc", "/sys", "/opt", "/srv", "/tmp/vulnagent"},
		WriteRoots:    []string{"/etc/vulnagent", "/opt/vulnagent", "/var/lib/vulnagent", "/tmp/vulnagent"},
		AllowCommands: []string{"systemctl", "journalctl", "df", "free", "ss", "netstat", "ip", "uptime", "hostname", "whoami", "ps"},
		SnapshotRoot:  "/var/lib/vulnagent/snapshots",
	}
}

// NeedsPrivilege 判断动作是否需要 root/SYSTEM
func NeedsPrivilege(action string) bool {
	switch action {
	case ActionWriteFile, ActionServiceAction, ActionSnapshot, ActionRestoreSnapshot, ActionPackageAction:
		return true
	}
	return false
}

type readFileParams struct {
	Path     string `json:"path"`
	MaxBytes int    `json:"maxBytes"`
}

type writeFileParams struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	DryRun  bool   `json:"dryRun"`
}

type runCommandParams struct {
	Argv       []string `json:"argv"`
	Cwd        string   `json:"cwd"`
	TimeoutSec int      `json:"timeoutSec"`
}

type serviceParams struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)

// Execute 执行请求；校验失败返回 failed，不做任何写入
func Execute(ctx context.Context, req Request, opts Options) Result {
	start := time.Now()
	res := Result{Status: "failed"}
	finish := func() Result {
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer func() { _ = finish }()

	switch req.Action {
	case ActionReadFile:
		out, err := readFile(req.Params, opts)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	case ActionWriteFile:
		out, err := writeFile(req.Params, opts)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	case ActionRunCommand:
		out, code, err := runCommand(ctx, req.Params, opts)
		res.Output, res.Error, res.ExitCode = out, errText(err), code
		res.Status = statusOf(err)
		res.Retryable = err != nil && code == -1
	case ActionServiceAction:
		out, err := serviceAction(ctx, req.Params)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	case ActionSnapshot:
		out, err := createSnapshot(req.Params, opts)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	case ActionRestoreSnapshot:
		out, err := restoreSnapshot(req.Params, opts)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	case ActionPackageAction:
		out, err := packageAction(ctx, req.Params)
		res.Output, res.Error, res.Status = out, errText(err), statusOf(err)
	default:
		res.Error = "不支持的动作：" + req.Action
	}
	return finish()
}

func statusOf(err error) string {
	if err != nil {
		return "failed"
	}
	return "succeeded"
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func readFile(raw json.RawMessage, opts Options) (string, error) {
	var p readFileParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	path, err := safePath(p.Path, opts.ReadRoots)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("拒绝读取符号链接")
	}
	if err := ensureRealPath(path, opts.ReadRoots); err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("目标是目录，不能按文件读取")
	}
	maxBytes := p.MaxBytes
	if maxBytes <= 0 || maxBytes > 512<<10 {
		maxBytes = 256 << 10
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	truncated := false
	if len(data) > maxBytes {
		data = data[:maxBytes]
		truncated = true
	}
	text := string(data)
	if truncated {
		text += "\n…（已截断，最多 " + fmt.Sprint(maxBytes) + " 字节）"
	}
	return text, nil
}

func writeFile(raw json.RawMessage, opts Options) (string, error) {
	var p writeFileParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	if len(p.Content) > 512<<10 {
		return "", errors.New("内容超过 512KB 上限")
	}
	path, err := safePath(p.Path, opts.WriteRoots)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("拒绝写入符号链接")
	}
	if err := ensureRealPath(filepath.Dir(path), opts.WriteRoots); err != nil {
		return "", err
	}
	old, _ := os.ReadFile(path)
	oldHash := sha256.Sum256(old)
	newHash := sha256.Sum256([]byte(p.Content))
	summary := fmt.Sprintf("path=%s 旧=%d 字节(%s) 新=%d 字节(%s)",
		path, len(old), shortHash(oldHash), len(p.Content), shortHash(newHash))
	if p.DryRun {
		return "dry-run: " + summary, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if len(old) > 0 {
		backup := fmt.Sprintf("%s.va-bak-%d", path, time.Now().Unix())
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("备份原文件失败：%w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".va-write-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(p.Content); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return "已写入 " + summary, nil
}

func runCommand(ctx context.Context, raw json.RawMessage, opts Options) (string, int, error) {
	var p runCommandParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", -1, fmt.Errorf("参数格式错误：%w", err)
	}
	if len(p.Argv) == 0 || len(p.Argv) > 20 {
		return "", -1, errors.New("argv 长度必须在 1-20 之间")
	}
	if strings.ContainsAny(p.Argv[0], `/\`) {
		return "", -1, errors.New("argv[0] 必须是裸命令名，不能包含路径分隔符")
	}
	base := strings.ToLower(filepath.Base(p.Argv[0]))
	if !containsFold(opts.AllowCommands, base) {
		return "", -1, fmt.Errorf("命令不在白名单：%s", base)
	}
	if err := validateSubcommand(base, p.Argv); err != nil {
		return "", -1, err
	}
	resolved, err := exec.LookPath(p.Argv[0])
	if err != nil {
		return "", -1, fmt.Errorf("命令不可用：%s", p.Argv[0])
	}
	cwd := ""
	if strings.TrimSpace(p.Cwd) != "" {
		abs, err := safePath(p.Cwd, opts.ReadRoots)
		if err != nil {
			return "", -1, err
		}
		cwd = abs
	}
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, resolved, p.Argv[1:]...)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	text := truncate(string(out), 256<<10)
	code := 0
	if err != nil {
		code = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		if runCtx.Err() == context.DeadlineExceeded {
			err = errors.New("命令执行超时")
		}
	}
	return text, code, err
}

func validateSubcommand(base string, argv []string) error {
	if len(argv) < 2 {
		return nil
	}
	sub := strings.ToLower(argv[1])
	switch base {
	case "systemctl":
		switch sub {
		case "list-units", "list-unit-files", "status", "show", "is-active", "is-enabled", "cat", "list-timers":
			return nil
		}
		return fmt.Errorf("systemctl 子命令不允许：%s（变更操作请使用 service_action）", sub)
	case "sc", "sc.exe":
		if sub == "query" || sub == "qc" {
			return nil
		}
		return fmt.Errorf("sc 子命令不允许：%s（变更操作请使用 service_action）", sub)
	case "wevtutil":
		if sub == "qe" || sub == "gl" || sub == "el" {
			return nil
		}
		return fmt.Errorf("wevtutil 子命令不允许：%s", sub)
	}
	return nil
}

func serviceAction(ctx context.Context, raw json.RawMessage) (string, error) {
	var p serviceParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("参数格式错误：%w", err)
	}
	if !serviceNamePattern.MatchString(p.Service) {
		return "", errors.New("服务名不合法")
	}
	action := strings.ToLower(strings.TrimSpace(p.Action))
	switch action {
	case "start", "stop", "restart", "status", "enable", "disable":
	default:
		return "", errors.New("服务动作仅支持 start/stop/restart/status/enable/disable")
	}
	var commands [][]string
	if runtime.GOOS == "windows" {
		switch action {
		case "status":
			commands = [][]string{{"sc.exe", "query", p.Service}}
		case "start":
			commands = [][]string{{"sc.exe", "start", p.Service}}
		case "stop":
			commands = [][]string{{"sc.exe", "stop", p.Service}}
		case "restart":
			commands = [][]string{{"sc.exe", "stop", p.Service}, {"sc.exe", "start", p.Service}}
		case "enable":
			commands = [][]string{{"sc.exe", "config", p.Service, "start=", "auto"}}
		case "disable":
			commands = [][]string{{"sc.exe", "config", p.Service, "start=", "demand"}}
		}
	} else {
		commands = [][]string{{"systemctl", action, p.Service}}
	}
	var builder strings.Builder
	for _, argv := range commands {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		out, err := cmd.CombinedOutput()
		builder.Write(out)
		if err != nil {
			return truncate(builder.String(), 256<<10), err
		}
	}
	return truncate(builder.String(), 256<<10), nil
}

func safePath(raw string, roots []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("路径不能为空")
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if !withinRoots(abs, roots) {
		return "", fmt.Errorf("路径不在允许范围：%s", raw)
	}
	return abs, nil
}

// ensureRealPath 解析符号链接，防止父目录指向白名单之外。
func ensureRealPath(path string, roots []string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 新建路径由 safePath 做词法校验
		}
		return err
	}
	if !withinRoots(real, roots) {
		return fmt.Errorf("解析后的真实路径不在允许范围：%s", real)
	}
	return nil
}

func withinRoots(abs string, roots []string) bool {
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(rootAbs), abs)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}

func containsFold(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "\n…（输出已截断）"
}

func shortHash(sum [32]byte) string {
	encoded := hex.EncodeToString(sum[:])
	return encoded[:12]
}
