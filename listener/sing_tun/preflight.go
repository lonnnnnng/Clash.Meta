package sing_tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	LC "github.com/metacubex/mihomo/listener/config"
	tun "github.com/metacubex/sing-tun"
)

// ValidateOptions在网卡探测/FD查询/网络监视之前复用原始范围解析器；不要求校验进程拥有TUN权限。作者 long。
func ValidateOptions(options LC.Tun) error {
	for _, values := range [][]string{options.IncludeUIDRange, options.ExcludeUIDRange, options.ExcludeSrcPortRange, options.ExcludeDstPortRange} {
		if _, err := parseRange[uint32](nil, values); err != nil {
			return err
		}
	}
	for _, values := range [][]string{options.IncludeMACAddress, options.ExcludeMACAddress} {
		for _, value := range values {
			if _, err := net.ParseMAC(value); err != nil {
				return err
			}
		}
	}
	switch options.DNSMode {
	case "", tun.DNSModeDisabled, tun.DNSModeNative, tun.DNSModeHijack:
	default:
		return fmt.Errorf("invalid DNS mode")
	}
	for _, value := range options.DNSHijack {
		if _, after, ok := strings.Cut(value, "://"); ok {
			value = after
		}
		if _, err := netip.ParseAddrPort(strings.Replace(value, "any", "0.0.0.0", 1)); err != nil {
			return err
		}
	}
	return nil
}
