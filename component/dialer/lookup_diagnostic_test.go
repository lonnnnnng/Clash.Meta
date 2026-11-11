package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
)

// 作者 long：显式指定端口才随调用context采集；普通拨号与其他会话不能进入诊断缓存，也不申请真实网络。
func TestLookupDiagnosticOnlyFollowsEnabledSourceContext(t *testing.T) {
	prior := activeLookupObserver.Load()
	defer activeLookupObserver.Store(prior)
	var records []LookupDiagnostic
	SetLookupDiagnosticObserver(func(port int) bool { return port == 43210 }, func(record LookupDiagnostic) { records = append(records, record) })
	for _, port := range []int{0, 43211, 43210} {
		ctx := WithLookupDiagnosticSource(context.Background(), port)
		ips, _, err := parseAddr(ctx, "tcp4", "127.0.0.1:443", nil)
		if err != nil || len(ips) != 1 {
			t.Fatal("literal lookup changed")
		}
	}
	if len(records) != 1 || records[0].SourcePort != 43210 || records[0].Network != "tcp4" || records[0].IPv4Addresses != 1 || records[0].Err != nil {
		t.Fatal("lookup capture not scoped")
	}
	ctx := WithLookupDiagnosticSource(context.Background(), 43210)
	_, _, err := parseAddr(ctx, "tcp4", "[::1]:443", nil)
	if err == nil || len(records) != 2 || records[1].Err == nil {
		t.Fatal("IP version mismatch not observed")
	}
	if records[1].ResolverRole != "proxy" || records[1].IPv6Disabled != resolver.DisableIPv6 {
		t.Fatal("effective lookup options missing")
	}
}

// 作者 long：拨号观察不包装成功连接、不改变错误；无需真实端口即可证明原始端点与耗时回执沿本次context返回。
func TestNodeDialObservationPreservesOriginalConnectionAndError(t *testing.T) {
	prior := activeLookupObserver.Load()
	defer activeLookupObserver.Store(prior)
	var records []LookupDiagnostic
	SetLookupDiagnosticObserver(func(port int) bool { return port == 43210 }, func(record LookupDiagnostic) { records = append(records, record) })
	ctx := WithLookupDiagnosticSource(context.Background(), 43210)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	option := option{netDialer: NetDialerFunc(func(context.Context, string, string) (net.Conn, error) { return left, nil })}
	got, err := dialContext(ctx, "tcp", netip.MustParseAddr("192.0.2.1"), "443", option)
	if err != nil || got != left || len(records) != 1 || records[0].Kind != "node-dial" || records[0].DialEndpoint != "192.0.2.1:443" || records[0].DialFamily != "ipv4" {
		t.Fatal("successful dial altered")
	}
	want := errors.New("fixture refused")
	option.netDialer = NetDialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, want })
	got, err = dialContext(ctx, "tcp", netip.MustParseAddr("192.0.2.1"), "443", option)
	if got != nil || err != want || len(records) != 2 || records[1].Err != want {
		t.Fatal("failed dial altered")
	}
}

type diagnosticAddressConn struct {
	net.Conn
	remote net.Addr
}

func (c *diagnosticAddressConn) RemoteAddr() net.Addr { return c.remote }

// 作者 long：公共入口回执必须来自最终返回连接，而不是候选地址；自定义连接没有地址时诊断也不能让原拨号崩溃。
func TestPublicDialReportsSelectedOriginalConnectionWithoutRequiringRemoteAddress(t *testing.T) {
	prior := activeLookupObserver.Load()
	defer activeLookupObserver.Store(prior)
	for _, remote := range []net.Addr{&net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 8443}, nil} {
		var records []LookupDiagnostic
		SetLookupDiagnosticObserver(func(port int) bool { return port == 43210 }, func(record LookupDiagnostic) { records = append(records, record) })
		ctx := WithLookupDiagnosticSource(context.Background(), 43210)
		left, right := net.Pipe()
		connection := &diagnosticAddressConn{left, remote}
		got, err := DialContext(ctx, "tcp4", "192.0.2.1:443", WithNetDialer(NetDialerFunc(func(context.Context, string, string) (net.Conn, error) { return connection, nil })))
		left.Close()
		right.Close()
		if err != nil || got != connection || len(records) != 3 {
			t.Fatalf("public dial altered: %v, records=%d", err, len(records))
		}
		winner := records[2]
		if winner.Kind != "node-selected" || winner.Err != nil {
			t.Fatal("selected connection missing")
		}
		if remote == nil {
			if winner.DialEndpoint != "" || winner.DialFamily != "unknown" {
				t.Fatal("invented absent remote")
			}
		} else if winner.DialEndpoint != remote.String() || winner.DialFamily != "ipv4" {
			t.Fatal("candidate address substituted for winner")
		}
	}
}
