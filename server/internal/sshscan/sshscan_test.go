package sshscan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const fixtureOutput = `#os	debian	12
deb	openssl	3.0.11	amd64
deb	sudo	1.9.9	amd64
rpm	nginx	1.20.1	x86_64
`

func TestScanAgainstTestServer(t *testing.T) {
	addr, stop := startTestServer(t, fixtureOutput)
	defer stop()

	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("解析测试地址失败：%v", err)
	}
	port, _ := strconv.Atoi(portText)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Scan(ctx, Config{
		Host:     host,
		Port:     port,
		User:     "root",
		Password: "secret",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH 采集失败：%v", err)
	}
	if len(res.Components) != 3 {
		t.Fatalf("应解析出 3 个组件，实际 %d", len(res.Components))
	}
	if res.OS != "debian" || res.OSVersion != "12" {
		t.Fatalf("系统信息解析错误：%s %s", res.OS, res.OSVersion)
	}
	if !strings.HasPrefix(res.HostKeyFingerprint, "SHA256:") {
		t.Fatalf("应返回主机指纹，实际 %q", res.HostKeyFingerprint)
	}
	if res.Components[0].PURL != "pkg:deb/debian/openssl@3.0.11?arch=amd64" {
		t.Fatalf("PURL 生成错误：%s", res.Components[0].PURL)
	}
	if res.Components[2].Eco != "rpm" {
		t.Fatalf("rpm 生态识别错误：%+v", res.Components[2])
	}

	// 指纹不匹配必须拒绝连接
	if _, err := Scan(ctx, Config{
		Host:               host,
		Port:               port,
		User:               "root",
		Password:           "secret",
		HostKeyFingerprint: "SHA256:not-the-real-fingerprint",
		Timeout:            5 * time.Second,
	}); err == nil {
		t.Fatal("指纹不匹配时应返回错误")
	}
}

func TestParseOutputIgnoresBrokenLines(t *testing.T) {
	components, osName, osVersion, err := parseOutput("#os\tubuntu\t22.04\ndeb\tonlyname\n\nrpm\tnginx\t1.20.1\n")
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if osName != "ubuntu" || osVersion != "22.04" {
		t.Fatalf("系统信息错误：%s %s", osName, osVersion)
	}
	if len(components) != 1 || components[0].Name != "nginx" {
		t.Fatalf("应只保留 1 条合法组件，实际 %+v", components)
	}
}

// startTestServer 启动一个内存 SSH 服务端，模拟 exec 返回固定清单
func startTestServer(t *testing.T, output string) (string, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败：%v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("构造 signer 失败：%v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "仅支持 session")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range requests {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							_, _ = channel.Write([]byte(output))
							_, _ = channel.SendRequest("exit-status", false,
								ssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}
