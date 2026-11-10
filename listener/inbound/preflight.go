package inbound

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/preflight"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/anytls"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/listener/sing_vless"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	"github.com/metacubex/mihomo/listener/trojan"
	"github.com/metacubex/mihomo/listener/tuic"
)

var errPreflightBind = errors.New("preflight reached bind boundary")

// 作者 long：复用真实协议构造器的语义分支，在绑定前返回专用结果；不会创建监听套接字或触发握手。
type preflightListenConfig struct{}

func (preflightListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errPreflightBind
}
func (preflightListenConfig) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errPreflightBind
}

func preflightBindResult(err error) error {
	if errors.Is(err, errPreflightBind) {
		return nil
	}
	return err
}

// ValidateReadOnly只允许一次性校验进程使用；构造器的定时器和加密任务随该进程退出，不复用主核心全局。作者 long。
func ValidateReadOnly(listener C.InboundListener) error {
	if !preflight.Enabled() {
		return errors.New("not a validation process")
	}
	lc := preflightListenConfig{}
	var err error
	switch v := listener.(type) {
	case *Tun:
		return sing_tun.ValidateOptions(v.tun)
	case *AnyTLS:
		_, err = anytls.New(v.vs, lc, nil, v.Additions()...)
		// 作者 long：上游把安全模式的最后检查放在Bind之后；拒绝绑定时仍须保留这条语义约束。
		if errors.Is(err, errPreflightBind) && !v.vs.AllowInsecure && v.vs.Certificate == "" && !v.vs.ShadowTLS.Enable && !v.vs.ResTLS.Enable && !v.vs.JLSConfig.Enable {
			return errors.New("AnyTLS requires security mode")
		}
	case *Vless:
		_, err = sing_vless.New(v.vs, lc, nil, v.Additions()...)
		if errors.Is(err, errPreflightBind) && !v.vs.AllowInsecure && v.vs.Certificate == "" && v.vs.RealityConfig.PrivateKey == "" && !v.vs.ShadowTLS.Enable && !v.vs.ResTLS.Enable && !v.vs.JLSConfig.Enable && (v.vs.Decryption == "" || v.vs.Decryption == "none") {
			return errors.New("VLESS requires security mode")
		}
	case *Vmess:
		_, err = sing_vmess.New(v.vs, lc, nil, v.Additions()...)
	case *Trojan:
		_, err = trojan.New(v.vs, lc, nil, v.Additions()...)
		if errors.Is(err, errPreflightBind) && !v.vs.AllowInsecure && !v.vs.TrojanSSOption.Enabled && v.vs.Certificate == "" && v.vs.RealityConfig.PrivateKey == "" && !v.vs.ShadowTLS.Enable && !v.vs.ResTLS.Enable && !v.vs.JLSConfig.Enable {
			return errors.New("Trojan requires security mode")
		}
	case *ShadowSocks:
		_, err = sing_shadowsocks.New(v.ss, lc, nil, v.Additions()...)
	case *Tuic:
		_, err = tuic.New(v.ts, lc, nil, v.Additions()...)
	case *Hysteria2:
		_, err = sing_hysteria2.New(v.ts, lc, nil, v.Additions()...)
	}
	return preflightBindResult(err)
}

func ValidateTuicReadOnly(config LC.TuicServer) error {
	if !preflight.Enabled() {
		return errors.New("not a validation process")
	}
	_, err := tuic.New(config, preflightListenConfig{}, nil)
	return preflightBindResult(err)
}
