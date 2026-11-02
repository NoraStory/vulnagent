package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// hashcatBenchmarkCommand hashcat 基准命令：-D 1 仅 CPU、-D 2 仅 GPU，模式 0 为 MD5
func hashcatBenchmarkCommand(device int) string {
	return fmt.Sprintf(`hashcat -b -m 0 -D %d 2>&1 | tail -n 60`, device)
}

var (
	hashcatSpeedPattern  = regexp.MustCompile(`Speed\.#\d+[^:]*:\s*([0-9.]+)\s*([kKMGT]?)H/s`)
	hashcatDevicePattern = regexp.MustCompile(`(?m)^\s*Name\.+:\s*(.+)$`)
	hashcatHashPattern   = regexp.MustCompile(`^[A-Za-z0-9$./+=:_*!,-]{8,512}$`)
)

// hashcatSpeed 解析基准输出中的速度并换算为 H/s，同时取第一个设备名
func hashcatSpeed(output string) (float64, string) {
	speed := 0.0
	if match := hashcatSpeedPattern.FindStringSubmatch(output); len(match) > 2 {
		value, _ := strconv.ParseFloat(match[1], 64)
		multiplier := 1.0
		switch strings.ToUpper(match[2]) {
		case "K":
			multiplier = 1e3
		case "M":
			multiplier = 1e6
		case "G":
			multiplier = 1e9
		case "T":
			multiplier = 1e12
		}
		speed = value * multiplier
	}
	device := ""
	if match := hashcatDevicePattern.FindStringSubmatch(output); len(match) > 1 {
		device = strings.TrimSpace(match[1])
	}
	return speed, device
}

// hashcatBenchmark hashcat CPU 与 GPU 基准对比结果
type hashcatBenchmark struct {
	Available  bool    `json:"available"`
	Version    string  `json:"version"`
	Mode       string  `json:"mode"`
	GPUDevice  string  `json:"gpuDevice"`
	CPUDevice  string  `json:"cpuDevice"`
	GPUSpeedHs float64 `json:"gpuSpeedHs"`
	CPUSpeedHs float64 `json:"cpuSpeedHs"`
	Speedup    float64 `json:"speedup"`
	ElapsedMs  int64   `json:"elapsedMs"`
	Error      string  `json:"error,omitempty"`
}

// handleSSHHostHashcatBenchmark 运行 hashcat CPU/GPU 基准（operator+）
func (a *App) handleSSHHostHashcatBenchmark(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	host, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	client, _, release, err := a.acquireSSHHost(ctx, host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	defer release()

	started := time.Now()
	versionOutput, _, _ := runSSHCommand(ctx, client, `hashcat --version 2>/dev/null | head -n 1`, 10*time.Second)
	version := strings.TrimSpace(versionOutput)
	if version == "" || strings.Contains(strings.ToLower(version), "not found") {
		writeErr(w, http.StatusBadRequest, "hashcat_unavailable", "目标主机未安装 hashcat，无法进行 GPU 口令审计")
		return
	}

	benchmark := hashcatBenchmark{Available: true, Version: version, Mode: "MD5"}
	gpuOutput, _, _ := runSSHCommand(ctx, client, hashcatBenchmarkCommand(2), 150*time.Second)
	benchmark.GPUSpeedHs, benchmark.GPUDevice = hashcatSpeed(gpuOutput)
	cpuOutput, _, _ := runSSHCommand(ctx, client, hashcatBenchmarkCommand(1), 150*time.Second)
	benchmark.CPUSpeedHs, benchmark.CPUDevice = hashcatSpeed(cpuOutput)
	benchmark.ElapsedMs = time.Since(started).Milliseconds()

	if benchmark.GPUSpeedHs <= 0 && benchmark.CPUSpeedHs <= 0 {
		benchmark.Error = "hashcat 基准未返回有效速度，请检查后端设备是否可用"
		writeJSON(w, http.StatusOK, benchmark)
		return
	}
	if benchmark.CPUSpeedHs > 0 {
		benchmark.Speedup = round1((benchmark.GPUSpeedHs - benchmark.CPUSpeedHs) / benchmark.CPUSpeedHs * 100)
	}
	a.audit(r, "ssh.hashcat.benchmark", host.Name,
		fmt.Sprintf("MD5 基准：GPU %.0f H/s / CPU %.0f H/s", benchmark.GPUSpeedHs, benchmark.CPUSpeedHs))
	writeJSON(w, http.StatusOK, benchmark)
}

// ---------- 批量口令审计 ----------

type hashcatAuditRequest struct {
	Hashes       []string `json:"hashes"`
	HashMode     int      `json:"hashMode"`
	WordlistPath string   `json:"wordlistPath"`
}

type hashcatCrack struct {
	Hash  string `json:"hash"`
	Plain string `json:"plain"`
}

type hashcatAuditResult struct {
	Total        int            `json:"total"`
	CrackedCount int            `json:"crackedCount"`
	NotFound     int            `json:"notFound"`
	HashMode     int            `json:"hashMode"`
	Wordlist     string         `json:"wordlist"`
	ElapsedMs    int64          `json:"elapsedMs"`
	Cracked      []hashcatCrack `json:"cracked"`
	Message      string         `json:"message,omitempty"`
}

// shellQuote 以单引号包裹参数，避免命令注入
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// parseHashcatAuditOutput 解析 HASH:PLAIN 行，只保留请求中的哈希
func parseHashcatAuditOutput(output string, requested map[string]bool) ([]hashcatCrack, string) {
	cracked := make([]hashcatCrack, 0, 8)
	message := ""
	lines := strings.Split(output, "\n")
	for index, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "WORDLIST_MISSING" {
			return cracked, "wordlist_missing"
		}
		if line == "HASHCAT_ERROR" {
			tail := lines[index+1:]
			if len(tail) > 3 {
				tail = tail[:3]
			}
			message = strings.TrimSpace(strings.Join(tail, " "))
			continue
		}
		if strings.HasPrefix(line, "HASHCAT_EXIT|") || strings.HasPrefix(line, "WORDLIST_MISSING") {
			continue
		}
		hash, plain, ok := strings.Cut(line, ":")
		if !ok || plain == "" {
			continue
		}
		if !requested[strings.ToLower(hash)] {
			continue
		}
		cracked = append(cracked, hashcatCrack{Hash: hash, Plain: truncateRunes(plain, 512)})
	}
	return cracked, message
}

// handleSSHHostHashcatAudit 上传哈希到目标机，用 hashcat 做字典审计并回收结果（operator+）
func (a *App) handleSSHHostHashcatAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "主机 ID 无效")
		return
	}
	var req hashcatAuditRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	wordlist := strings.TrimSpace(req.WordlistPath)
	if !strings.HasPrefix(wordlist, "/") || len(wordlist) > 1000 || strings.ContainsAny(wordlist, "\r\n\x00") {
		writeErr(w, http.StatusBadRequest, "bad_request", "字典路径必须是绝对路径")
		return
	}
	if req.HashMode < 0 || req.HashMode > 99999 {
		writeErr(w, http.StatusBadRequest, "bad_request", "hashcat 模式必须在 0-99999 之间")
		return
	}
	hashes := make([]string, 0, len(req.Hashes))
	requested := make(map[string]bool, len(req.Hashes))
	for _, raw := range req.Hashes {
		hash := strings.TrimSpace(raw)
		if hash == "" {
			continue
		}
		if !hashcatHashPattern.MatchString(hash) {
			writeErr(w, http.StatusBadRequest, "bad_request", "哈希格式不合法："+truncateRunes(hash, 32))
			return
		}
		if requested[strings.ToLower(hash)] {
			continue
		}
		requested[strings.ToLower(hash)] = true
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "至少提供一条合法哈希")
		return
	}
	if len(hashes) > 100 {
		writeErr(w, http.StatusBadRequest, "bad_request", "单次最多审计 100 条哈希")
		return
	}
	host, err := a.getSSHHost(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "主机不存在")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()
	client, _, release, err := a.acquireSSHHost(ctx, host)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ssh_failed", err.Error())
		return
	}
	defer release()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp_failed", "SFTP 子系统不可用："+err.Error())
		return
	}
	defer sftpClient.Close()

	base := "/tmp/vulnagent-hashcat-" + newSSHRunID()
	hashPath, outPath, logPath := base+".txt", base+".out", base+".log"
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _, _ = runSSHCommand(cleanupCtx, client, fmt.Sprintf("rm -f %s %s %s", shellQuote(hashPath), shellQuote(outPath), shellQuote(logPath)), 8*time.Second)
	}
	defer cleanup()

	file, err := sftpClient.Create(hashPath)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upload_failed", "写入临时哈希文件失败："+err.Error())
		return
	}
	if _, err := file.Write([]byte(strings.Join(hashes, "\n") + "\n")); err != nil {
		_ = file.Close()
		writeErr(w, http.StatusBadGateway, "upload_failed", "写入临时哈希文件失败："+err.Error())
		return
	}
	_ = file.Close()
	_ = sftpClient.Chmod(hashPath, 0o600)

	started := time.Now()
	script := fmt.Sprintf(`if [ ! -f %s ]; then echo "WORDLIST_MISSING"; exit 3; fi
hashcat -m %d -a 0 --potfile-disable --runtime 300 --outfile-format 2 -o %s %s %s > %s 2>&1
rc=$?
echo "HASHCAT_EXIT|$rc"
cat %s 2>/dev/null || true
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then echo "HASHCAT_ERROR"; tail -n 3 %s; fi`,
		shellQuote(wordlist), req.HashMode, shellQuote(outPath), shellQuote(hashPath), shellQuote(wordlist), shellQuote(logPath),
		shellQuote(outPath), shellQuote(logPath))
	output, _, _ := runSSHCommand(ctx, client, script, 6*time.Minute)
	cracked, message := parseHashcatAuditOutput(output, requested)
	if message == "wordlist_missing" {
		writeErr(w, http.StatusBadRequest, "wordlist_missing", "目标主机上不存在该字典文件")
		return
	}
	result := hashcatAuditResult{
		Total: len(hashes), CrackedCount: len(cracked), NotFound: len(hashes) - len(cracked),
		HashMode: req.HashMode, Wordlist: wordlist,
		ElapsedMs: time.Since(started).Milliseconds(), Cracked: cracked, Message: message,
	}
	a.audit(r, "ssh.hashcat.audit", host.Name,
		fmt.Sprintf("模式 %d，共 %d 条，命中 %d 条", req.HashMode, result.Total, result.CrackedCount))
	writeJSON(w, http.StatusOK, result)
}
