package vless

import "time"

// HandshakeDiagnostic只报告原读写的阶段/字节数，不携带UUID、地址、正文或协议头内容。作者 long。
type HandshakeDiagnostic struct {
	Stage, State                             string
	Duration                                 time.Duration
	PayloadBytes, StreamBytes, ExpectedBytes int
	Err                                      error
}

// SetHandshakeObserver必须在连接交给读写者之前调用；不新增包装层或改变可替换读写接口。作者 long。
func (vc *Conn) SetHandshakeObserver(observer func(HandshakeDiagnostic)) { vc.observer = observer }
