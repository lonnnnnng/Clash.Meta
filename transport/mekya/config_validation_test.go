package mekya

import (
	"context"
	"testing"
)

// 作者 long：监听器与客户端都不能把负队列容量留到首个网络请求的make(chan)才发现。
func TestNegativeQueueRejectedBeforeListenerAndClient(t *testing.T) {
	t.Run("listener", func(t *testing.T) {
		defer func() {
			if recover() != nil {
				t.Error("negative queue reached listener access")
			}
		}()
		_, err := Listen(context.Background(), nil, Config{PacketWritingBuffer: -1})
		if err == nil {
			t.Fatal("negative queue accepted by listener")
		}
	})
	t.Run("client", func(t *testing.T) {
		client, err := NewClient(context.Background(), nil, Config{URL: "https://example.test/", PacketWritingBuffer: -1})
		if client != nil {
			defer client.Close()
		}
		if err == nil {
			t.Fatal("negative queue accepted by client")
		}
	})
}

func TestDefaultQueueClientConstructionDoesNotDial(t *testing.T) {
	client, err := NewClient(context.Background(), nil, Config{URL: "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
}
