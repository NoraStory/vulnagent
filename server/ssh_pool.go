package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshPoolIdleTTL 空闲连接保留时长；超时后在下一次获取连接时关闭
const sshPoolIdleTTL = 3 * time.Minute

// sshPoolEntry 一台主机共享的 SSH 连接。
// ssh.Client 支持并发 NewSession，因此同一连接可被多个只读请求复用。
type sshPoolEntry struct {
	client        *ssh.Client
	fingerprint   string
	configVersion string
	lastUsed      time.Time
	inflight      int
}

func sshHostConfigVersion(host sshHost) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s",
		host.Host, host.Port, host.Username, host.AuthType, host.Secret, host.Passphrase, host.HostKey)))
	return hex.EncodeToString(sum[:])
}

// acquireSSHHost 获取可复用的 SSH 连接；返回的 release 必须在请求结束时调用。
// 复用前会打开一个空会话探测连接是否仍然可用，失效时自动重连。
func (a *App) acquireSSHHost(ctx context.Context, host sshHost) (*ssh.Client, string, func(), error) {
	now := time.Now()
	version := sshHostConfigVersion(host)
	a.sshPoolMu.Lock()
	a.cleanupSSHPoolLocked(now)
	if entry, ok := a.sshPool[host.ID]; ok && entry.client != nil {
		if entry.configVersion == version {
			if err := probeSSHClient(entry.client); err == nil {
				entry.inflight++
				entry.lastUsed = now
				a.sshPoolMu.Unlock()
				return entry.client, entry.fingerprint, func() { a.releaseSSHHost(host.ID) }, nil
			}
		}
		_ = entry.client.Close()
		delete(a.sshPool, host.ID)
	}
	a.sshPoolMu.Unlock()

	client, fingerprint, err := a.dialSSHHost(ctx, host)
	if err != nil {
		return nil, "", nil, err
	}

	a.sshPoolMu.Lock()
	if entry, ok := a.sshPool[host.ID]; ok && entry.client != nil && entry.client != client {
		// 并发重连时只复用配置一致的连接，避免更新前发起的旧拨号覆盖新配置。
		if entry.configVersion == version {
			if err := probeSSHClient(entry.client); err == nil {
				_ = client.Close()
				entry.inflight++
				entry.lastUsed = now
				cachedFingerprint := entry.fingerprint
				a.sshPoolMu.Unlock()
				return entry.client, cachedFingerprint, func() { a.releaseSSHHost(host.ID) }, nil
			}
		}
		_ = entry.client.Close()
	}
	if a.sshPool == nil {
		a.sshPool = make(map[int64]*sshPoolEntry)
	}
	a.sshPool[host.ID] = &sshPoolEntry{
		client: client, fingerprint: fingerprint, configVersion: version, lastUsed: now, inflight: 1,
	}
	a.sshPoolMu.Unlock()
	return client, fingerprint, func() { a.releaseSSHHost(host.ID) }, nil
}

// probeSSHClient 通过打开并关闭一个空会话判断连接是否仍可用
func probeSSHClient(client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	return session.Close()
}

func (a *App) releaseSSHHost(hostID int64) {
	a.sshPoolMu.Lock()
	defer a.sshPoolMu.Unlock()
	if entry, ok := a.sshPool[hostID]; ok {
		if entry.inflight > 0 {
			entry.inflight--
		}
		entry.lastUsed = time.Now()
	}
}

func (a *App) cleanupSSHPoolLocked(now time.Time) {
	for id, entry := range a.sshPool {
		if entry.inflight == 0 && now.Sub(entry.lastUsed) > sshPoolIdleTTL {
			_ = entry.client.Close()
			delete(a.sshPool, id)
		}
	}
}

// invalidateSSHHost 在地址或凭据变化后立即关闭旧连接，进行中的请求也会随连接关闭而终止。
func (a *App) invalidateSSHHost(hostID int64) {
	a.sshPoolMu.Lock()
	defer a.sshPoolMu.Unlock()
	if entry, ok := a.sshPool[hostID]; ok {
		_ = entry.client.Close()
		delete(a.sshPool, hostID)
	}
}

// closeSSHPool 关闭全部缓存连接（测试与退出时使用）
func (a *App) closeSSHPool() {
	a.sshPoolMu.Lock()
	defer a.sshPoolMu.Unlock()
	for id, entry := range a.sshPool {
		_ = entry.client.Close()
		delete(a.sshPool, id)
	}
}
