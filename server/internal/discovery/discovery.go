// Package discovery 提供受限的网段资产发现能力：CIDR 白名单校验、TCP 探活与反向解析。
// 该包不做任何写库操作，任务调度与候选落库由控制面负责。
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Policy 发现策略：授权网段、默认端口与资源上限
type Policy struct {
	AllowedCIDRs   []string `json:"allowedCidrs"`
	DefaultPorts   []int    `json:"defaultPorts"`
	MaxHosts       int      `json:"maxHosts"`
	MaxConcurrency int      `json:"maxConcurrency"`
	TimeoutMS      int      `json:"timeoutMs"`
	MaxPorts       int      `json:"maxPorts"`
	MaxJobsPerHour int      `json:"maxJobsPerHour"`
	ReverseDNS     bool     `json:"reverseDns"`
}

// DefaultPolicy 返回默认策略：仅内网与回环地址，TCP 常见端口
func DefaultPolicy() Policy {
	return Policy{
		AllowedCIDRs:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
		DefaultPorts:   []int{22, 80, 443, 3389, 3306, 5432, 6379, 9200},
		MaxHosts:       1024,
		MaxConcurrency: 64,
		TimeoutMS:      600,
		MaxPorts:       32,
		MaxJobsPerHour: 10,
		ReverseDNS:     true,
	}
}

// NormalizePolicy 补齐默认值并收敛到安全区间
func NormalizePolicy(p Policy) Policy {
	def := DefaultPolicy()
	if len(p.AllowedCIDRs) == 0 {
		p.AllowedCIDRs = def.AllowedCIDRs
	}
	if len(p.DefaultPorts) == 0 {
		p.DefaultPorts = def.DefaultPorts
	}
	if p.MaxHosts <= 0 {
		p.MaxHosts = def.MaxHosts
	}
	if p.MaxHosts > 8192 {
		p.MaxHosts = 8192
	}
	if p.MaxConcurrency <= 0 {
		p.MaxConcurrency = def.MaxConcurrency
	}
	if p.MaxConcurrency > 256 {
		p.MaxConcurrency = 256
	}
	if p.TimeoutMS <= 0 {
		p.TimeoutMS = def.TimeoutMS
	}
	if p.TimeoutMS < 100 {
		p.TimeoutMS = 100
	}
	if p.TimeoutMS > 5000 {
		p.TimeoutMS = 5000
	}
	if p.MaxPorts <= 0 {
		p.MaxPorts = def.MaxPorts
	}
	if p.MaxPorts > 128 {
		p.MaxPorts = 128
	}
	if p.MaxJobsPerHour <= 0 {
		p.MaxJobsPerHour = def.MaxJobsPerHour
	}
	if p.MaxJobsPerHour > 200 {
		p.MaxJobsPerHour = 200
	}
	return p
}

// ParsePolicy 从 JSON 解析策略，失败时回落到默认值
func ParsePolicy(raw string) Policy {
	policy := DefaultPolicy()
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &policy)
	}
	return NormalizePolicy(policy)
}

// ValidatePolicyCIDRs 校验策略白名单本身可用
func ValidatePolicyCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		return errors.New("授权网段不能为空")
	}
	for _, item := range cidrs {
		prefix, err := parsePrefix(item)
		if err != nil {
			return err
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("不允许使用 %s：授权网段不能覆盖整个互联网", item)
		}
	}
	return nil
}

// ValidateCIDRs 校验任务网段是否在白名单内并计算主机数
func ValidateCIDRs(raw []string, policy Policy) ([]netip.Prefix, int, error) {
	if len(raw) == 0 {
		return nil, 0, errors.New("请至少填写一个网段")
	}
	allowed := make([]netip.Prefix, 0, len(policy.AllowedCIDRs))
	for _, item := range policy.AllowedCIDRs {
		prefix, err := parsePrefix(item)
		if err != nil {
			return nil, 0, fmt.Errorf("策略中的授权网段无效：%s", item)
		}
		allowed = append(allowed, prefix)
	}

	seen := map[string]bool{}
	prefixes := make([]netip.Prefix, 0, len(raw))
	total := 0
	for _, item := range raw {
		prefix, err := parsePrefix(item)
		if err != nil {
			return nil, 0, err
		}
		if prefix.Bits() == 0 {
			return nil, 0, fmt.Errorf("不允许扫描 %s：网段范围过大", item)
		}
		if !containedIn(prefix, allowed) {
			return nil, 0, fmt.Errorf("网段 %s 不在授权范围内，请先由管理员在发现策略中添加", prefix)
		}
		if seen[prefix.String()] {
			continue
		}
		seen[prefix.String()] = true
		prefixes = append(prefixes, prefix)
		total += hostCount(prefix)
		if total > policy.MaxHosts {
			return nil, 0, fmt.Errorf("本次扫描主机数超过上限 %d，请拆分为更小的网段", policy.MaxHosts)
		}
	}
	if len(prefixes) == 0 {
		return nil, 0, errors.New("没有可扫描的网段")
	}
	return prefixes, total, nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Prefix{}, errors.New("网段不能为空")
	}
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("网段格式错误：%s", raw)
		}
		if addr.Is6() && !addr.Is4In6() {
			return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6 网段：%s", raw)
		}
		return netip.PrefixFrom(addr, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("网段格式错误：%s", raw)
	}
	if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6 网段：%s", raw)
	}
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

func containedIn(prefix netip.Prefix, allowed []netip.Prefix) bool {
	for _, item := range allowed {
		if item.Bits() <= prefix.Bits() && item.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func hostCount(prefix netip.Prefix) int {
	bits := 32 - prefix.Bits()
	if bits >= 31 {
		return 1 << 31
	}
	return 1 << bits
}

// NormalizePorts 去重、排序并校验端口
func NormalizePorts(raw []int, maxPorts int) ([]int, error) {
	if maxPorts <= 0 {
		maxPorts = 32
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(raw))
	for _, port := range raw {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("端口 %d 超出 1-65535 范围", port)
		}
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	if len(out) == 0 {
		return nil, errors.New("请至少填写一个端口")
	}
	if len(out) > maxPorts {
		return nil, fmt.Errorf("端口数量超过上限 %d", maxPorts)
	}
	sort.Ints(out)
	return out, nil
}

// Addrs 展开网段为 IP 列表
func Addrs(prefixes []netip.Prefix, limit int) []netip.Addr {
	out := make([]netip.Addr, 0, limit)
	for _, prefix := range prefixes {
		addr := prefix.Addr()
		for addr.IsValid() && prefix.Contains(addr) {
			out = append(out, addr)
			if limit > 0 && len(out) >= limit {
				return out
			}
			addr = addr.Next()
		}
	}
	return out
}

// PortResult 单个端口的探测结果
type PortResult struct {
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
}

// HostResult 一台存活主机的探测结果
type HostResult struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname"`
	Ports    []PortResult `json:"ports"`
}

// OpenPorts 返回逗号分隔的开放端口
func (h HostResult) OpenPorts() string {
	ports := make([]string, 0, len(h.Ports))
	for _, item := range h.Ports {
		ports = append(ports, fmt.Sprintf("%d", item.Port))
	}
	return strings.Join(ports, ",")
}

// Evidence 返回可读的探测证据
func (h HostResult) Evidence() string {
	parts := make([]string, 0, len(h.Ports))
	for _, item := range h.Ports {
		if item.Banner != "" {
			parts = append(parts, fmt.Sprintf("tcp/%d %s", item.Port, item.Banner))
		} else {
			parts = append(parts, fmt.Sprintf("tcp/%d open", item.Port))
		}
	}
	return strings.Join(parts, "; ")
}

// ScanOptions 扫描参数
type ScanOptions struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	ReverseDNS  bool
}

// ScanStats 扫描统计
type ScanStats struct {
	Scanned int
	Found   int
}

// Scan 并发探测主机，命中时回调 onHost；onProgress 每处理若干地址回调一次。
func Scan(ctx context.Context, addrs []netip.Addr, opts ScanOptions, onHost func(HostResult), onProgress func(done, found int)) ScanStats {
	stats := ScanStats{}
	if len(addrs) == 0 {
		return stats
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > 256 {
		concurrency = 256
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}

	var mu sync.Mutex
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup

	report := func() {
		if onProgress != nil {
			onProgress(stats.Scanned, stats.Found)
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := probeHost(ctx, addr.String(), opts.Ports, timeout, opts.ReverseDNS)
				mu.Lock()
				stats.Scanned++
				if len(result.Ports) > 0 {
					stats.Found++
					if onHost != nil {
						onHost(result)
					}
				}
				if stats.Scanned%16 == 0 {
					report()
				}
				mu.Unlock()
			}
		}()
	}

loop:
	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			break loop
		case jobs <- addr:
		}
	}
	close(jobs)
	wg.Wait()

	mu.Lock()
	report()
	mu.Unlock()
	return stats
}

func probeHost(ctx context.Context, ip string, ports []int, timeout time.Duration, reverseDNS bool) HostResult {
	result := HostResult{IP: ip}
	dialer := net.Dialer{Timeout: timeout}
	for _, port := range ports {
		if ctx.Err() != nil {
			return result
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
		if err != nil {
			continue
		}
		banner := readBanner(conn)
		_ = conn.Close()
		result.Ports = append(result.Ports, PortResult{Port: port, Banner: banner})
	}
	if len(result.Ports) > 0 && reverseDNS {
		result.Hostname = lookupHostname(ctx, ip)
	}
	return result
}

func readBanner(conn net.Conn) string {
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return ""
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

func sanitizeBanner(raw []byte) string {
	builder := strings.Builder{}
	for _, b := range raw {
		if b >= 32 && b < 127 {
			builder.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			builder.WriteByte(' ')
		}
	}
	text := strings.TrimSpace(builder.String())
	if len(text) > 120 {
		text = text[:120]
	}
	return text
}

func lookupHostname(ctx context.Context, ip string) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}
