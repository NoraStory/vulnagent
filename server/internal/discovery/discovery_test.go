package discovery

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateCIDRs(t *testing.T) {
	policy := DefaultPolicy()

	prefixes, total, err := ValidateCIDRs([]string{"10.0.0.0/30", "127.0.0.1"}, policy)
	if err != nil {
		t.Fatalf("合法网段应通过：%v", err)
	}
	if len(prefixes) != 2 || total != 5 {
		t.Fatalf("网段展开异常：prefixes=%v total=%d", prefixes, total)
	}

	cases := []struct {
		name  string
		cidrs []string
		want  string
	}{
		{"公网未授权", []string{"8.8.8.0/24"}, "不在授权范围"},
		{"全网段", []string{"0.0.0.0/0"}, "网段范围过大"},
		{"超出主机上限", []string{"10.0.0.0/8"}, "超过上限"},
		{"IPv6", []string{"2001:db8::/64"}, "暂不支持 IPv6"},
		{"格式错误", []string{"10.0.0.0/33"}, "网段格式错误"},
	}
	for _, item := range cases {
		if _, _, err := ValidateCIDRs(item.cidrs, policy); err == nil || !strings.Contains(err.Error(), item.want) {
			t.Fatalf("%s：期望错误包含 %q，实际 %v", item.name, item.want, err)
		}
	}
}

func TestValidateCIDRsCustomPolicy(t *testing.T) {
	policy := NormalizePolicy(Policy{AllowedCIDRs: []string{"192.168.10.0/24"}})
	if _, _, err := ValidateCIDRs([]string{"192.168.10.0/28"}, policy); err != nil {
		t.Fatalf("白名单内网段应通过：%v", err)
	}
	if _, _, err := ValidateCIDRs([]string{"192.168.11.0/28"}, policy); err == nil {
		t.Fatal("白名单外网段应被拒绝")
	}
}

func TestNormalizePorts(t *testing.T) {
	ports, err := NormalizePorts([]int{443, 22, 443, 80}, 8)
	if err != nil {
		t.Fatalf("端口校验失败：%v", err)
	}
	if len(ports) != 3 || ports[0] != 22 || ports[2] != 443 {
		t.Fatalf("端口去重排序异常：%v", ports)
	}
	if _, err := NormalizePorts([]int{0}, 8); err == nil {
		t.Fatal("端口 0 应被拒绝")
	}
	if _, err := NormalizePorts([]int{22, 80, 443, 8080, 8443}, 2); err == nil {
		t.Fatal("超过端口上限应被拒绝")
	}
}

func TestAddrs(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/30")}
	addrs := Addrs(prefixes, 10)
	if len(addrs) != 4 || addrs[0].String() != "127.0.0.0" || addrs[3].String() != "127.0.0.3" {
		t.Fatalf("地址展开异常：%v", addrs)
	}
	if got := Addrs(prefixes, 2); len(got) != 2 {
		t.Fatalf("地址上限未生效：%v", got)
	}
}

func TestScanFindsLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地端口失败：%v", err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port

	var hosts []HostResult
	stats := Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ScanOptions{
		Ports:       []int{openPort},
		Concurrency: 2,
		Timeout:     500 * time.Millisecond,
		ReverseDNS:  false,
	}, func(host HostResult) { hosts = append(hosts, host) }, nil)

	if stats.Scanned != 1 || stats.Found != 1 || len(hosts) != 1 {
		t.Fatalf("扫描结果异常：%+v hosts=%v", stats, hosts)
	}
	if hosts[0].OpenPorts() != strconv.Itoa(openPort) {
		t.Fatalf("开放端口记录异常：%s", hosts[0].OpenPorts())
	}
	if !strings.Contains(hosts[0].Evidence(), "open") {
		t.Fatalf("证据缺少端口信息：%s", hosts[0].Evidence())
	}
}

func TestScanClosedPortNotFound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地端口失败：%v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	found := 0
	stats := Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ScanOptions{
		Ports:       []int{port},
		Concurrency: 1,
		Timeout:     300 * time.Millisecond,
	}, func(HostResult) { found++ }, nil)
	if stats.Scanned != 1 || stats.Found != 0 || found != 0 {
		t.Fatalf("关闭端口不应命中：%+v found=%d", stats, found)
	}
}

func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stats := Scan(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ScanOptions{
		Ports:       []int{22},
		Concurrency: 1,
		Timeout:     100 * time.Millisecond,
	}, nil, nil)
	if stats.Scanned != 0 {
		t.Fatalf("取消后不应继续扫描：%+v", stats)
	}
}
