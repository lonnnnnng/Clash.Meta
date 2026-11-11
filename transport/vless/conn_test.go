package vless

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
)

type responseFixtureConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c responseFixtureConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c responseFixtureConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

// 作者 long：附加头声明长度还未收齐时不能把连接切为可替换读者，否则截断响应被当成已完成握手。
func TestResponseRejectsTruncatedAddonAndPreservesReadFailure(t *testing.T) {
	for _, data := range [][]byte{{Version, 4}, {Version, 4, 1, 2}} {
		conn := &Conn{ExtendedConn: N.NewExtendedConn(responseFixtureConn{reader: bytes.NewReader(data)})}
		if err := conn.recvResponse(); !errors.Is(err, io.EOF) {
			t.Fatalf("truncated addon accepted: %v", err)
		}
		conn = &Conn{ExtendedConn: N.NewExtendedConn(responseFixtureConn{reader: bytes.NewReader(data)})}
		var payload [1]byte
		if n, err := conn.Read(payload[:]); n != 0 || !errors.Is(err, io.EOF) || conn.ReaderReplaceable() {
			t.Fatal("truncated handshake released reader", n, err)
		}
	}
	conn := &Conn{ExtendedConn: N.NewExtendedConn(responseFixtureConn{reader: bytes.NewReader([]byte{Version, 2, 1, 2, 9})})}
	if err := conn.recvResponse(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn.ExtendedConn)
	if err != nil || !bytes.Equal(data, []byte{9}) {
		t.Fatalf("payload consumed: %v, %v", data, err)
	}
}

// 作者 long：普通/缓冲入口必须落到同一首写和响应头观察点；零载荷首包只证明VLESS头写入，不能声称业务TLS已发送。
func TestHandshakeDiagnosticsPreserveOrdinaryAndBufferIO(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, payload := range [][]byte{nil, {7, 8, 9}} {
			client, _ := NewClient("00000000-0000-0000-0000-000000000000", nil)
			var wire bytes.Buffer
			raw, _ := client.StreamConn(responseFixtureConn{reader: bytes.NewReader([]byte{Version, 0, 42}), writer: &wire}, &DstAddr{AddrType: AtypIPv4, Addr: []byte{192, 0, 2, 1}, Port: 443})
			conn := raw.(*Conn)
			var events []HandshakeDiagnostic
			conn.SetHandshakeObserver(func(event HandshakeDiagnostic) { events = append(events, event) })
			if buffered {
				buffer := buf.As(payload)
				if err := conn.WriteBuffer(buffer); err != nil {
					t.Fatal(err)
				}
			} else if n, err := conn.Write(payload); n != len(payload) || err != nil {
				t.Fatal("write changed", n, err)
			}
			if len(events) != 2 || events[0].State != "begin" || events[1].State != "end" || events[1].PayloadBytes != len(payload) || events[1].StreamBytes != wire.Len() || !conn.WriterReplaceable() {
				t.Fatalf("request diagnostic mismatch: %+v", events)
			}
			if buffered {
				buffer := buf.NewSize(8)
				defer buffer.Release()
				if err := conn.ReadBuffer(buffer); err != nil || !bytes.Equal(buffer.Bytes(), []byte{42}) {
					t.Fatal("buffer response changed", err)
				}
			} else {
				var payload [1]byte
				n, err := conn.Read(payload[:])
				if n != 1 || err != nil || payload[0] != 42 {
					t.Fatal("response changed", n, err)
				}
			}
			if len(events) != 4 || events[2].Stage != "vless-response" || events[2].State != "begin" || events[3].StreamBytes != 2 || events[3].Err != nil || !conn.ReaderReplaceable() {
				t.Fatalf("response diagnostic mismatch: %+v", events)
			}
		}
	}
}
