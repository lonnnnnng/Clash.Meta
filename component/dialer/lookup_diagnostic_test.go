package dialer

import (
	"context"
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
