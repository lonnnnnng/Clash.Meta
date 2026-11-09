package http

import (
	"context"
	"io"
	"net"
	URL "net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"

	"github.com/metacubex/http"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, options ...Option) (*http.Response, error) {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UA())
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(opt.caOption)
	if err != nil {
		return nil, err
	}
	applyTLSConfigHook(opt.caOption, tlsConfig)

	transport := &http.Transport{
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if opt.dialer != nil {
				return opt.dialer.DialContext(ctx, network, address)
			}
			if conn, err := inner.HandleTcp(inner.GetTunnel(), address, opt.specialProxy); err == nil {
				return conn, nil
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport}
	response, err := client.Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		return response, err
	}
	// 作者 long：Android强制Connection:close会触发部分代理传输链在响应尾段提前断开。
	// 本次请求与重定向共用独立Transport，正文关闭后再回收全部空闲连接，既让内容收完整也不遗留后台连接。
	response.Body = &requestBody{ReadCloser: response.Body, closeIdle: transport.CloseIdleConnections}
	return response, nil
}

type requestBody struct {
	io.ReadCloser
	closeIdle func()
	once      sync.Once
}

func (b *requestBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.closeIdle)
	return err
}

type Option func(opt *option)

type option struct {
	specialProxy string
	dialer       C.Dialer
	caOption     ca.Option
}

func WithSpecialProxy(name string) Option {
	return func(opt *option) {
		opt.specialProxy = name
	}
}

func WithDialer(dialer C.Dialer) Option {
	return func(opt *option) {
		opt.dialer = dialer
	}
}

func WithCAOption(caOption ca.Option) Option {
	return func(opt *option) {
		opt.caOption = caOption
	}
}
