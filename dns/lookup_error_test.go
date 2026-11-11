package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

type lookupGateClient struct {
	aaaaStarted chan struct{}
	releaseAAAA chan struct{}
}

func (c *lookupGateClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	reply := new(D.Msg)
	reply.SetReply(m)
	if m.Question[0].Qtype == D.TypeAAAA {
		close(c.aaaaStarted)
		select {
		case <-c.releaseAAAA:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		reply.Answer = []D.RR{&D.AAAA{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET}, AAAA: net.ParseIP("2001:db8::1")}}
	} else {
		<-c.aaaaStarted
	}
	return reply, nil
}
func (*lookupGateClient) Address() string  { return "test://lookup-gate" }
func (*lookupGateClient) ResetConnection() {}

// 作者 long：A合法空答复由lookupIP转为ErrIPNotFound；AAAA尚未返回时，调用者必须收到失败而非空地址成功。
func TestLookupIPPreservesFailureWhenIPv6WindowExpires(t *testing.T) {
	client := &lookupGateClient{make(chan struct{}), make(chan struct{})}
	defer close(client.releaseAAAA)
	r := NewResolverFromClient(client)
	r.ipv6Timeout = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "lookup-gate.test")
	if len(ips) != 0 || !errors.Is(err, resolver.ErrIPNotFound) {
		t.Fatalf("empty lookup must preserve failure: count=%d errorPresent=%v", len(ips), err != nil)
	}
}

// 作者 long：IPv6已返回有效地址时仍允许成功，不能把A的失败误传播到正常的双栈回退。
func TestLookupIPKeepsCompletedIPv6AfterIPv4Failure(t *testing.T) {
	client := &lookupGateClient{make(chan struct{}), make(chan struct{})}
	close(client.releaseAAAA)
	r := NewResolverFromClient(client)
	r.ipv6Timeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "lookup-gate.test")
	if err != nil || len(ips) != 1 || !ips[0].Is6() {
		t.Fatalf("completed IPv6 must remain usable: count=%d errorPresent=%v", len(ips), err != nil)
	}
}
