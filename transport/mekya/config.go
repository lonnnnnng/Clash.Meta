package mekya

import (
	"errors"
	"github.com/metacubex/mihomo/transport/mkcp"
)

type Config struct {
	KCP                            mkcp.Config
	URL                            string
	H2PoolSize                     int
	MaxWriteDelay                  int
	MaxRequestSize                 int
	PollingIntervalInitial         int
	MaxWriteSize                   int
	MaxWriteDurationMs             int
	MaxSimultaneousWriteConnection int
	PacketWritingBuffer            int
}

// 作者 long：请求到达后才分配写队列，负容量会直接panic；离线检查和真正监听使用同一约束。
func (c Config) Validate() error {
	if c.PacketWritingBuffer < 0 {
		return errors.New("mekya: negative packet writing buffer")
	}
	return c.KCP.Validate()
}
