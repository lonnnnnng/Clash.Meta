package tuic

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type resetTestClient struct {
	closeCalls int
}

func (*resetTestClient) DialContext(context.Context, *C.Metadata) (net.Conn, error) {
	return nil, errors.New("unused")
}

func (*resetTestClient) ListenPacket(context.Context, *C.Metadata) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func (*resetTestClient) OpenStreams() int64       { return 0 }
func (*resetTestClient) LastVisited() time.Time   { return time.Time{} }
func (*resetTestClient) SetLastVisited(time.Time) {}
func (c *resetTestClient) Close()                 { c.closeCalls++ }

func TestResetNetworkClosesAndClearsTcpAndUdpPools(t *testing.T) {
	pool := &PoolClient{}
	tcpClient := &resetTestClient{}
	udpClient := &resetTestClient{}
	pool.tcpClients.PushFront(tcpClient)
	pool.udpClients.PushFront(udpClient)

	pool.ResetNetwork()

	if tcpClient.closeCalls != 1 || udpClient.closeCalls != 1 {
		t.Fatalf("close calls: tcp=%d udp=%d, want 1 each", tcpClient.closeCalls, udpClient.closeCalls)
	}
	if pool.tcpClients.Front() != nil || pool.udpClients.Front() != nil {
		t.Fatal("network-bound clients remain in a pool after reset")
	}
}
