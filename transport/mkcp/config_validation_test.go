package mkcp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// 作者 long：无真实端口/数据包的输入边界回归，坏TTI必须在读循环或会话创建之前返回错误。
func TestExcessiveTTIRejectedBeforeListenerAndDial(t *testing.T) {
	t.Run("listener", func(t *testing.T) {
		pc := &validationPacketConn{done: make(chan struct{})}
		defer pc.Close()
		listener, err := Listen(context.Background(), pc, Config{TTI: 1001})
		if listener != nil {
			defer listener.Close()
		}
		if err == nil {
			t.Fatal("unsafe TTI was accepted before listener creation")
		}
	})
	t.Run("dial", func(t *testing.T) {
		defer func() {
			if recover() != nil {
				t.Error("unsafe TTI reached session creation")
			}
		}()
		_, err := Dial(context.Background(), nil, Config{TTI: 1001})
		if err == nil {
			t.Fatal("unsafe TTI accepted before raw connection access")
		}
	})
}

func TestDefaultAndBoundaryTTIAreAccepted(t *testing.T) {
	for _, tti := range []uint32{0, 50, 1000} {
		pc := &validationPacketConn{done: make(chan struct{})}
		listener, err := Listen(context.Background(), pc, Config{TTI: tti})
		if err != nil {
			t.Fatal(err)
		}
		listener.Close()
	}
}

type validationPacketConn struct {
	done chan struct{}
	once sync.Once
}

func (p *validationPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-p.done
	return 0, nil, net.ErrClosed
}
func (*validationPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, net.ErrClosed }
func (p *validationPacketConn) Close() error                        { p.once.Do(func() { close(p.done) }); return nil }
func (*validationPacketConn) LocalAddr() net.Addr                   { return &net.UDPAddr{} }
func (*validationPacketConn) SetDeadline(time.Time) error           { return nil }
func (*validationPacketConn) SetReadDeadline(time.Time) error       { return nil }
func (*validationPacketConn) SetWriteDeadline(time.Time) error      { return nil }
