package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/sftp"
)

func TestSSHSecretRoundTrip(t *testing.T) {
	app := &App{dataDir: t.TempDir()}
	sealed, err := app.sealSSHSecret("s3cret-pass")
	if err != nil {
		t.Fatalf("加密失败：%v", err)
	}
	if sealed == "" || sealed == "s3cret-pass" {
		t.Fatal("密文不应为空或与明文相同")
	}
	plain, err := app.openSSHSecret(sealed)
	if err != nil || plain != "s3cret-pass" {
		t.Fatalf("解密失败：%q err=%v", plain, err)
	}
	if _, err := app.openSSHSecret(sealed[:len(sealed)-4]); err == nil {
		t.Fatal("篡改后的密文应解密失败")
	}
	// 空值保持为空，便于 PATCH 时表示不修改凭据
	empty, err := app.sealSSHSecret("")
	if err != nil || empty != "" {
		t.Fatalf("空凭据应保持空：%q err=%v", empty, err)
	}
}

func TestNormalizeSSHHostInput(t *testing.T) {
	name, host, user, auth := "web-01", "10.0.0.1", "root", "password"
	port := 2222
	h, err := normalizeSSHHostInput(sshHostInput{Name: &name, Host: &host, Username: &user, AuthType: &auth, Port: &port})
	if err != nil || h.Port != 2222 || h.AuthType != "password" {
		t.Fatalf("合法输入解析失败：%+v err=%v", h, err)
	}
	badAuth := "token"
	if _, err := normalizeSSHHostInput(sshHostInput{AuthType: &badAuth}); err == nil {
		t.Fatal("非法认证方式应被拒绝")
	}
	scheme := "ssh://10.0.0.1"
	if _, err := normalizeSSHHostInput(sshHostInput{Host: &scheme}); err == nil {
		t.Fatal("包含协议前缀的主机应被拒绝")
	}
	badPort := 70000
	if _, err := normalizeSSHHostInput(sshHostInput{Port: &badPort}); err == nil {
		t.Fatal("非法端口应被拒绝")
	}
}

func TestExtractTypedLines(t *testing.T) {
	var buf strings.Builder
	lines := extractTypedLines(&buf, "ls -al\r")
	if len(lines) != 1 || lines[0] != "ls -al" {
		t.Fatalf("回车提交的命令解析异常：%+v", lines)
	}
	lines = extractTypedLines(&buf, "echoo\x7f hi\r")
	if len(lines) != 1 || lines[0] != "echo hi" {
		t.Fatalf("退格处理异常：%+v", lines)
	}
	if lines := extractTypedLines(&buf, "\x1b[A"); len(lines) != 0 {
		t.Fatalf("方向键不应产生命令：%+v", lines)
	}
}

func TestExtractShellCommands(t *testing.T) {
	answer := "先看磁盘：\n```sh\ndf -h\n```\n再看 inode：\n```bash\n# 注释\ndf -i\ndf -h\n```\n"
	commands := extractShellCommands(answer)
	if len(commands) != 2 || commands[0] != "df -h" || commands[1] != "df -i" {
		t.Fatalf("命令提取异常：%+v", commands)
	}
	long := "```sh\n"
	for i := 0; i < 12; i++ {
		long += fmt.Sprintf("echo %d\n", i)
	}
	long += "```"
	if got := extractShellCommands(long); len(got) != 8 {
		t.Fatalf("命令数量应截断为 8，实际 %d", len(got))
	}
}

// startTestSSHServer 启动一个仅用于测试的 SSH 服务，支持口令认证与回显 shell
func startTestSSHServer(t *testing.T) (addr, fingerprint string) {
	addr, fingerprint, _ = startTestSSHServerEx(t)
	return addr, fingerprint
}

// startTestSSHServerEx 额外返回 SFTP 子系统的根目录
func startTestSSHServerEx(t *testing.T) (addr, fingerprint, root string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() == "tester" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
	}
	config.AddHostKey(signer)

	root = t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSSHConn(conn, config, root)
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), root
}

func serveTestSSHConn(conn net.Conn, config *ssh.ServerConfig, root string) {
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer serverConn.Close()
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
			defer channel.Close()
			for req := range requests {
				switch req.Type {
				case "shell":
					_ = req.Reply(true, nil)
					_, _ = channel.Write([]byte("ready\n"))
					buf := make([]byte, 512)
					for {
						n, err := channel.Read(buf)
						if n > 0 {
							_, _ = channel.Write(buf[:n])
						}
						if err != nil {
							return
						}
					}
				case "exec":
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					_ = req.Reply(true, nil)
					output := "ok\n"
					exit := uint32(0)
					switch {
					case strings.Contains(payload.Command, "dpkg-query"):
						output = "#os\tubuntu\t22.04\ndeb\topenssl\t3.0.2-0ubuntu1.10\tamd64\ndeb\tbash\t5.1-6ubuntu1\tamd64\n"
					case strings.HasPrefix(payload.Command, "echo "):
						output = strings.TrimPrefix(payload.Command, "echo ") + "\n"
					case payload.Command == "false":
						output = ""
						exit = 1
					}
					if output != "" {
						_, _ = channel.Write([]byte(output))
					}
					status := struct{ Status uint32 }{exit}
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&status))
					return
				case "subsystem":
					var payload struct{ Name string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					if payload.Name != "sftp" {
						_ = req.Reply(false, nil)
						continue
					}
					_ = req.Reply(true, nil)
					server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
					if err != nil {
						return
					}
					_ = server.Serve()
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

func TestDialSSHHostTOFUAndShell(t *testing.T) {
	addr, fingerprint := startTestSSHServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)

	app := &App{dataDir: t.TempDir()}
	sealed, err := app.sealSSHSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	h := sshHost{Name: "test", Host: host, Port: port, Username: "tester", AuthType: "password", Secret: sealed}
	client, observed, err := app.dialSSHHost(context.Background(), h)
	if err != nil {
		t.Fatalf("连接测试 SSH 服务失败：%v", err)
	}
	defer client.Close()
	if observed != fingerprint {
		t.Fatalf("指纹不一致：%s != %s", observed, fingerprint)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdin, "ping\n"); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan string, 1)
	go func() {
		buf := make([]byte, 128)
		total := ""
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				total += string(buf[:n])
				if strings.Contains(total, "ready") && strings.Contains(total, "ping") {
					break
				}
			}
			if err != nil {
				break
			}
		}
		readDone <- total
	}()
	select {
	case got := <-readDone:
		if !strings.Contains(got, "ready") || !strings.Contains(got, "ping") {
			t.Fatalf("shell 回显异常：%q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 shell 输出超时")
	}

	h.HostKey = "SHA256:not-the-real-fingerprint"
	if _, _, err := app.dialSSHHost(context.Background(), h); err == nil {
		t.Fatal("指纹不匹配时应拒绝连接")
	}
}
