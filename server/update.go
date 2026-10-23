package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// updateManifest 自更新清单，签名为 canonicalPayload 的 Ed25519 签名（base64）
type updateManifest struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	URL       string `json:"url"`
	Signature string `json:"signature"`
}

func canonicalPayload(m updateManifest) []byte {
	return []byte(strings.Join([]string{m.Version, m.OS, m.Arch, m.SHA256, m.URL}, "\n"))
}

func verifyManifest(pub ed25519.PublicKey, m updateManifest) error {
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("签名不是合法 base64: %w", err)
	}
	if !ed25519.Verify(pub, canonicalPayload(m), sig) {
		return fmt.Errorf("清单签名校验失败")
	}
	if m.OS != "" && m.OS != runtime.GOOS {
		return fmt.Errorf("清单目标系统 %s 与当前 %s 不一致", m.OS, runtime.GOOS)
	}
	if m.Arch != "" && m.Arch != runtime.GOARCH {
		return fmt.Errorf("清单目标架构 %s 与当前 %s 不一致", m.Arch, runtime.GOARCH)
	}
	return nil
}

func parsePublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if data, err := os.ReadFile(raw); err == nil {
		raw = strings.TrimSpace(string(data))
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("公钥不是合法 base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("公钥长度应为 %d 字节，实际 %d", ed25519.PublicKeySize, len(key))
	}
	return ed25519.PublicKey(key), nil
}

func readManifest(source string) (updateManifest, error) {
	var m updateManifest
	var data []byte
	var err error
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return m, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return m, fmt.Errorf("下载清单失败：HTTP %d", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("解析清单失败: %w", err)
	}
	return m, nil
}

// runUpdateKeygen 生成 Ed25519 签名密钥对（私钥 0600，仅用于发布机）
func runUpdateKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out", ".", "密钥输出目录")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成密钥失败：%v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "创建目录失败：%v\n", err)
		os.Exit(1)
	}
	keyPath := filepath.Join(*outDir, "update.key")
	pubPath := filepath.Join(*outDir, "update.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "写入私钥失败：%v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入公钥失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "已生成密钥：%s（0600）、%s\n", keyPath, pubPath)
	fmt.Fprintf(os.Stderr, "Agent 侧设置 VA_UPDATE_PUBKEY 为公钥内容或路径，或使用 --pubkey 指定\n")
}

// runUpdateSign 为二进制生成签名清单
func runUpdateSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "update.key", "Ed25519 私钥文件")
	binary := fs.String("binary", "", "待发布二进制路径（用于计算 sha256）")
	version := fs.String("version", appVersion, "版本号")
	url := fs.String("url", "", "二进制下载地址")
	osName := fs.String("os", runtime.GOOS, "目标系统（linux/windows/darwin）")
	arch := fs.String("arch", runtime.GOARCH, "目标架构（amd64/arm64）")
	_ = fs.Parse(args)
	if *binary == "" || *url == "" {
		fmt.Fprintln(os.Stderr, "需要 --binary 与 --url")
		os.Exit(2)
	}
	data, err := os.ReadFile(*binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取二进制失败：%v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(data)

	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取私钥失败：%v\n", err)
		os.Exit(1)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "私钥格式错误\n")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	m := updateManifest{
		Version: *version,
		OS:      *osName,
		Arch:    *arch,
		SHA256:  hex.EncodeToString(sum[:]),
		URL:     *url,
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalPayload(m)))
	out, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(out))
}

// runSelfUpdateCommand 校验签名与哈希后替换当前可执行文件
func runSelfUpdateCommand(args []string) {
	fs := flag.NewFlagSet("self-update", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "清单文件或 URL")
	pubkey := fs.String("pubkey", "", "Ed25519 公钥（base64 或文件路径），默认读 VA_UPDATE_PUBKEY")
	checkOnly := fs.Bool("check", false, "只校验清单与签名，不下载替换")
	_ = fs.Parse(args)
	if *manifestPath == "" {
		fmt.Fprintln(os.Stderr, "请使用 --manifest 指定清单文件或 URL")
		os.Exit(2)
	}
	keyRaw := *pubkey
	if keyRaw == "" {
		keyRaw = os.Getenv("VA_UPDATE_PUBKEY")
	}
	if keyRaw == "" {
		fmt.Fprintln(os.Stderr, "缺少公钥：--pubkey 或 VA_UPDATE_PUBKEY")
		os.Exit(2)
	}
	pub, err := parsePublicKey(keyRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	m, err := readManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取清单失败：%v\n", err)
		os.Exit(1)
	}
	if err := verifyManifest(pub, m); err != nil {
		fmt.Fprintf(os.Stderr, "清单校验失败：%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "清单校验通过：version=%s os=%s arch=%s\n", m.Version, m.OS, m.Arch)
	if *checkOnly {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "定位当前可执行文件失败：%v\n", err)
		os.Exit(1)
	}
	tmp := exe + ".new"
	if err := downloadBinary(m, tmp); err != nil {
		fmt.Fprintf(os.Stderr, "下载新版本失败：%v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取新版本失败：%v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m.SHA256) {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "哈希校验失败，已丢弃下载文件\n")
		os.Exit(1)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "设置执行权限失败：%v\n", err)
		os.Exit(1)
	}

	backup := exe + ".old"
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "替换失败（可先停止服务再执行）：%v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(backup, exe)
		fmt.Fprintf(os.Stderr, "替换失败，已回滚：%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "更新完成：%s → %s（旧版本保留为 %s）\n", appVersion, m.Version, backup)
}

func downloadBinary(m updateManifest, target string) error {
	var reader io.Reader
	if strings.HasPrefix(m.URL, "http://") || strings.HasPrefix(m.URL, "https://") {
		client := &http.Client{Timeout: 5 * time.Minute}
		resp, err := client.Get(m.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		reader = io.LimitReader(resp.Body, 512<<20)
	} else {
		f, err := os.Open(m.URL)
		if err != nil {
			return err
		}
		defer f.Close()
		reader = f
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, reader)
	return err
}
