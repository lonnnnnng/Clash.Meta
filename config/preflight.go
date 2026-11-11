package config

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/preflight"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	IN "github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
)

// PreflightResult只包含静态分类与候选内位置，不导出解析器可能含密码/地址/正文的异常消息。作者 long。
type PreflightResult struct {
	Passed            bool   `json:"passed"`
	Code              string `json:"code"`
	Section           string `json:"section"`
	Index             int    `json:"index"`
	DeferredResources int    `json:"deferredResources"`
}

// ParseReadOnly必须位于一次性独立进程；复用完整解析，资源获取和fakeIP存储才使用只读后端。作者 long。
func ParseReadOnly(buf []byte, resourceLoader func(string) ([]byte, error)) (result PreflightResult) {
	result = PreflightResult{Code: "invalid_config", Section: "config", Index: -1}
	if err := preflight.Enable(resourceLoader); err != nil {
		result.Code = "validation_process_reused"
		return
	}
	defer func() {
		section, index, code, deferred := preflight.Status()
		result.Section = section
		result.Index = index
		result.DeferredResources = deferred
		if code != "" {
			result.Passed = false
			result.Code = code
		}
		if recover() != nil {
			result.Passed = false
			result.Code = "validation_internal_error"
		}
	}()
	log.SetLevel(log.SILENT)
	C.SetHomeDir("/kclash-validation")
	if len(buf) == 0 || len(buf) > 8*1024*1024 {
		result.Code = "invalid_size"
		return
	}
	raw, err := UnmarshalRawConfig(buf)
	if err != nil {
		return
	}
	if err = validatePreflightPorts(raw); err != nil {
		return
	}
	// 作者 long：候选的自定义信任链和TLS字段在普通Parse只复制；预检提前验证，不能等Listen才发现坏证书。
	preflight.Location("tls", -1)
	if err = validatePreflightTLS(raw.TLS.Certificate, raw.TLS.PrivateKey, raw.TLS.ClientAuthCert, raw.TLS.EchKey); err != nil {
		return
	}
	for _, cert := range raw.TLS.CustomTrustCert {
		if _, err = ca.LoadCertificates(cert); err != nil {
			return
		}
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		return
	}
	preflight.Location("dns", -1)
	if err = validatePreflightDNS(cfg); err != nil {
		return
	}
	for index, mapping := range raw.Listeners {
		preflight.Location("listeners", index)
		value := func(key string) string { v, _ := mapping[key].(string); return v }
		if err = validatePreflightTLS(value("certificate"), value("private-key"), value("client-auth-cert"), value("ech-key")); err != nil {
			return
		}
	}
	if raw.Tun.Enable {
		preflight.Location("tun", -1)
		if err = sing_tun.ValidateOptions(cfg.General.Tun); err != nil {
			return
		}
	}
	if raw.TuicServer.Enable {
		preflight.Location("tuic-server", -1)
		if err = validatePreflightTLS(raw.TuicServer.Certificate, raw.TuicServer.PrivateKey, "", ""); err != nil {
			return
		}
		if err = IN.ValidateTuicReadOnly(cfg.General.TuicServer); err != nil {
			return
		}
	}
	preflight.Location("config", -1)
	result.Passed = true
	result.Code = "valid"
	return
}
func validatePreflightPorts(raw *RawConfig) error {
	preflight.Location("general", -1)
	for _, port := range []int{raw.Port, raw.SocksPort, raw.RedirPort, raw.TProxyPort, raw.MixedPort} {
		if port < 0 || port > 65535 {
			return errors.New("invalid port")
		}
	}
	if raw.TuicServer.Enable {
		preflight.Location("tuic-server", -1)
		for _, address := range strings.Split(raw.TuicServer.Listen, ",") {
			_, port, err := net.SplitHostPort(strings.TrimSpace(address))
			if err != nil {
				return errors.New("invalid TUIC listen address")
			}
			number, err := strconv.Atoi(port)
			if err != nil || number < 0 || number > 65535 {
				return errors.New("invalid TUIC port")
			}
		}
	}
	for section, address := range map[string]string{"external-controller": raw.ExternalController, "external-controller-tls": raw.ExternalControllerTLS, "dns": raw.DNS.Listen} {
		if address == "" {
			continue
		}
		preflight.Location(section, -1)
		if _, port, err := net.SplitHostPort(address); err != nil {
			return errors.New("invalid listen address")
		} else if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			return errors.New("invalid listen port")
		}
	}
	return nil
}
func validatePreflightTLS(certificate, key, clientCert, echKey string) error {
	if certificate != "" || key != "" {
		if _, err := ca.NewTLSKeyPairLoader(certificate, key); err != nil {
			return err
		}
	}
	if clientCert != "" {
		if _, err := ca.LoadCertificates(clientCert); err != nil {
			return err
		}
	}
	return ech.LoadECHKey(echKey, &tls.Config{})
}
func validatePreflightDNS(cfg *Config) error {
	groups := [][]dns.NameServer{cfg.DNS.NameServer, cfg.DNS.Fallback, cfg.DNS.DefaultNameserver, cfg.DNS.ProxyServerNameserver, cfg.DNS.DirectNameServer}
	for _, p := range cfg.DNS.NameServerPolicy {
		groups = append(groups, p.NameServers)
	}
	for _, p := range cfg.DNS.ProxyServerPolicy {
		groups = append(groups, p.NameServers)
	}
	for _, group := range groups {
		for _, ns := range group {
			// 作者 long：核心把未知#名称作为网卡名处理，离线预检不能把当前没有连接的网卡误报为不存在代理。
			if ns.ProxyName != "" && ns.ProxyName != dns.RespectRules {
				if _, ok := cfg.Proxies[ns.ProxyName]; !ok {
					preflight.DeferExternal()
				}
			}

			if ns.Net == "tailscale" || ns.Net == "easytier" {
				proxy, ok := cfg.Proxies[ns.Addr]
				if !ok {
					return errors.New("missing overlay DNS proxy")
				}
				if ns.Net == "tailscale" && proxy.Type() != C.Tailscale || ns.Net == "easytier" && proxy.Type() != C.EasyTier {
					return errors.New("wrong overlay DNS proxy type")
				}
			}
		}
	}
	return nil
}
