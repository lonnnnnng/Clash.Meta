package vless

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	N.ExtendedConn
	dst      *DstAddr
	id       uuid.UUID
	addons   *Addons
	received bool
	sent     bool
	observer func(HandshakeDiagnostic)
}

func (vc *Conn) Read(b []byte) (int, error) {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return 0, err
		}
		vc.received = true
	}
	return vc.ExtendedConn.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return err
		}
		vc.received = true
	}
	return vc.ExtendedConn.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	if !vc.sent {
		if err := vc.sendRequest(p); err != nil {
			return 0, err
		}
		vc.sent = true
		return len(p), nil
	}

	return vc.ExtendedConn.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !vc.sent {
		if err := vc.sendRequest(buffer.Bytes()); err != nil {
			return err
		}
		vc.sent = true
		return nil
	}

	return vc.ExtendedConn.WriteBuffer(buffer)
}

func (vc *Conn) sendRequest(p []byte) (err error) {
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, err = proto.Marshal(vc.addons)
		if err != nil {
			return
		}
	}

	requestLen := 1  // protocol version
	requestLen += 16 // UUID
	requestLen += 1  // addons length
	requestLen += len(addonsBytes)
	requestLen += 1 // command
	if !vc.dst.Mux {
		requestLen += 2 // port
		requestLen += 1 // addr type
		requestLen += len(vc.dst.Addr)
	}
	requestLen += len(p)

	buffer := buf.NewSize(requestLen)
	defer buffer.Release()

	buf.Must(
		buffer.WriteByte(Version),              // protocol version
		buf.Error(buffer.Write(vc.id.Bytes())), // 16 bytes of uuid
		buffer.WriteByte(byte(len(addonsBytes))),
		buf.Error(buffer.Write(addonsBytes)),
	)

	if vc.dst.Mux {
		buf.Must(buffer.WriteByte(CommandMux))
	} else {
		if vc.dst.UDP {
			buf.Must(buffer.WriteByte(CommandUDP))
		} else {
			buf.Must(buffer.WriteByte(CommandTCP))
		}

		binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		buf.Must(
			buffer.WriteByte(vc.dst.AddrType),
			buf.Error(buffer.Write(vc.dst.Addr)),
		)
	}

	buf.Must(buf.Error(buffer.Write(p)))

	var written int
	if vc.observer != nil {
		started := time.Now()
		vc.observer(HandshakeDiagnostic{Stage: "vless-request", State: "begin", PayloadBytes: len(p), ExpectedBytes: requestLen})
		defer func() {
			vc.observer(HandshakeDiagnostic{Stage: "vless-request", State: "end", Duration: time.Since(started),
				PayloadBytes: len(p), StreamBytes: written, ExpectedBytes: requestLen, Err: err})
		}()
	}
	written, err = vc.ExtendedConn.Write(buffer.Bytes())
	return
}

func (vc *Conn) recvResponse() (err error) {
	read, expected := 0, 2
	if vc.observer != nil {
		started := time.Now()
		vc.observer(HandshakeDiagnostic{Stage: "vless-response", State: "begin", ExpectedBytes: expected})
		defer func() {
			vc.observer(HandshakeDiagnostic{Stage: "vless-response", State: "end", Duration: time.Since(started),
				StreamBytes: read, ExpectedBytes: expected, Err: err})
		}()
	}
	var buffer [2]byte
	read, err = io.ReadFull(vc.ExtendedConn, buffer[:])
	if err != nil {
		return err
	}

	if buffer[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buffer[1])
	expected += int(length)
	if length != 0 { // addon data length > 0
		if vc.observer != nil {
			vc.observer(HandshakeDiagnostic{Stage: "vless-response-addon", State: "begin", StreamBytes: read, ExpectedBytes: expected})
		}
		// 作者 long：声明的附加头未收齐时保留原读取错误，不能把截断头当作完整响应而释放读取握手状态。
		var count int64
		count, err = io.CopyN(io.Discard, vc.ExtendedConn, length)
		read += int(count)
	}

	return
}

func (vc *Conn) Upstream() any {
	return vc.ExtendedConn
}

func (vc *Conn) ReaderReplaceable() bool {
	return vc.received
}

func (vc *Conn) WriterReplaceable() bool {
	return vc.sent
}

func (vc *Conn) NeedHandshake() bool {
	return !vc.sent
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (net.Conn, error) {
	c := &Conn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		addons:       client.Addons,
		dst:          dst,
	}

	if client.Addons != nil {
		switch client.Addons.Flow {
		case XRV:
			visionConn, err := vision.NewConn(c, conn, c.id)
			if err != nil {
				return nil, err
			}
			return visionConn, nil
		}
	}

	return c, nil
}
