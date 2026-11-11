package dialer

import (
	"context"
	"sync/atomic"
	"time"
)

type lookupDiagnosticSource struct{}

// LookupDiagnostic只在显式源端口采集期间交给宿主；地址和错误原值必须由宿主立即分类/摘要，不得直接持久化。作者 long。
type LookupDiagnostic struct {
	Kind                                     string
	SourcePort                               int
	Host, Network, ResolverRole              string
	IPv6Disabled                             bool
	Addresses, IPv4Addresses, IPv6Addresses  int
	Duration                                 time.Duration
	Err, ContextErr                          error
	DialEndpoint, DialFamily                 string
	ProtocolStage, ProtocolState             string
	PayloadBytes, StreamBytes, ExpectedBytes int
}

type lookupObserver struct {
	enabled func(int) bool
	observe func(LookupDiagnostic)
}

var activeLookupObserver atomic.Pointer[lookupObserver]

func SetLookupDiagnosticObserver(enabled func(int) bool, observe func(LookupDiagnostic)) {
	if enabled == nil || observe == nil {
		activeLookupObserver.Store(nil)
		return
	}
	activeLookupObserver.Store(&lookupObserver{enabled, observe})
}

// WithLookupDiagnosticSource沿原拨号context传递源端口，不延长预算、不新增请求；后台共享DNS任务不会冒充本次调用。作者 long。
func WithLookupDiagnosticSource(ctx context.Context, port int) context.Context {
	observer := activeLookupObserver.Load()
	if observer == nil || port <= 0 || port > 65535 || !observer.enabled(port) {
		return ctx
	}
	return context.WithValue(ctx, lookupDiagnosticSource{}, port)
}

func lookupDiagnosticFor(ctx context.Context) (int, *lookupObserver) {
	port, _ := ctx.Value(lookupDiagnosticSource{}).(int)
	observer := activeLookupObserver.Load()
	if observer == nil || !observer.enabled(port) {
		return 0, nil
	}
	return port, observer
}

// NewProtocolDiagnosticObserver只复用拨号时绑定的身份；IO阶段不借用已结束拨号context的取消状态推断读写超时。作者 long。
func NewProtocolDiagnosticObserver(ctx context.Context) func(string, string, time.Duration, int, int, int, error) {
	port, observer := lookupDiagnosticFor(ctx)
	if observer == nil {
		return nil
	}
	return func(stage, state string, duration time.Duration, payloadBytes, streamBytes, expectedBytes int, err error) {
		if activeLookupObserver.Load() != observer || !observer.enabled(port) {
			return
		}
		observer.observe(LookupDiagnostic{Kind: "protocol", SourcePort: port, ProtocolStage: stage, ProtocolState: state,
			Duration: duration, PayloadBytes: payloadBytes, StreamBytes: streamBytes, ExpectedBytes: expectedBytes, Err: err})
	}
}
