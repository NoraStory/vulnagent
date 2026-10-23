// Package sshscan 实现无 Agent 兜底采集：控制面通过 SSH 执行只读脚本，
// 解析系统包清单。不写入目标主机，不执行升级或配置变更。
package sshscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"vulnagent/server/internal/collect"
)

// Config SSH 连接参数
type Config struct {
	Host               string
	Port               int
	User               string
	Password           string
	PrivateKeyPEM      string
	Passphrase         string
	HostKeyFingerprint string // 形如 SHA256:xxxx，留空表示首次连接接受并回报指纹
	Timeout            time.Duration
}

// Result 一次 SSH 采集结果
type Result struct {
	OS                 string
	OSVersion          string
	Components         []collect.Component
	HostKeyFingerprint string
	Elapsed            time.Duration
}

// scanScript 只读采集脚本：优先 dpkg，其次 rpm，最后 apk
const scanScript = `osid=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -n1)
osver=$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -n1)
printf '#os\t%s\t%s\n' "$osid" "$osver"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='deb\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf 'rpm\t%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null
elif [ -r /lib/apk/db/installed ]; then
  awk '/^P:/{n=substr($0,3)} /^V:/{v=substr($0,3)} /^A:/{a=substr($0,3); printf "apk\t%s\t%s\t%s\n", n, v, a}' /lib/apk/db/installed
fi
`

// Scan 连接目标主机并采集软件清单
func Scan(ctx context.Context, cfg Config) (Result, error) {
	start := time.Now()
	if cfg.Host == "" || cfg.User == "" {
		return Result{}, fmt.Errorf("缺少主机或用户名")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}

	var auth []ssh.AuthMethod
	if cfg.Password != "" {
		auth = append(auth, ssh.Password(cfg.Password))
	}
	if cfg.PrivateKeyPEM != "" {
		var (
			signer ssh.Signer
			err    error
		)
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKeyPEM), []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKeyPEM))
		}
		if err != nil {
			return Result{}, fmt.Errorf("解析私钥失败: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return Result{}, fmt.Errorf("需要口令或私钥")
	}

	observed := ""
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = ssh.FingerprintSHA256(key)
		if cfg.HostKeyFingerprint != "" && !strings.EqualFold(cfg.HostKeyFingerprint, observed) {
			return fmt.Errorf("主机指纹不匹配：期望 %s，实际 %s", cfg.HostKeyFingerprint, observed)
		}
		return nil
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("连接失败: %w", err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	})
	if err != nil {
		_ = conn.Close()
		return Result{}, fmt.Errorf("SSH 握手失败: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("建立会话失败: %w", err)
	}
	defer session.Close()

	type execResult struct {
		out []byte
		err error
	}
	done := make(chan execResult, 1)
	go func() {
		out, err := session.Output(scanScript)
		done <- execResult{out: out, err: err}
	}()

	select {
	case <-ctx.Done():
		return Result{}, fmt.Errorf("采集超时或被取消")
	case r := <-done:
		if r.err != nil {
			return Result{}, fmt.Errorf("执行采集脚本失败: %w", r.err)
		}
		components, osName, osVersion, err := parseOutput(string(r.out))
		if err != nil {
			return Result{}, err
		}
		return Result{
			OS:                 osName,
			OSVersion:          osVersion,
			Components:         components,
			HostKeyFingerprint: observed,
			Elapsed:            time.Since(start),
		}, nil
	}
}

// parseOutput 解析采集脚本输出（#os 行 + 包清单行）
func parseOutput(out string) ([]collect.Component, string, string, error) {
	var components []collect.Component
	osName, osVersion := "linux", ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "#os":
			if len(fields) >= 3 {
				if fields[1] != "" {
					osName = fields[1]
				}
				osVersion = fields[2]
			}
		case "deb", "rpm", "apk":
			if len(fields) < 3 || fields[1] == "" || fields[2] == "" {
				continue
			}
			name, version := fields[1], fields[2]
			arch := ""
			if len(fields) >= 4 {
				arch = fields[3]
			}
			var purl, vendor string
			switch fields[0] {
			case "deb":
				purl = fmt.Sprintf("pkg:deb/debian/%s@%s?arch=%s", name, version, arch)
				vendor = "debian"
			case "rpm":
				purl = fmt.Sprintf("pkg:rpm/rhel/%s@%s?arch=%s", name, version, arch)
				vendor = "rhel"
			case "apk":
				purl = fmt.Sprintf("pkg:apk/alpine/%s@%s?arch=%s", name, version, arch)
				vendor = "alpine"
			}
			components = append(components, collect.Component{
				PURL:    purl,
				Name:    name,
				Version: version,
				Eco:     fields[0],
				Vendor:  vendor,
				Product: name,
				Source:  "ssh",
			})
		}
	}
	return components, osName, osVersion, nil
}
