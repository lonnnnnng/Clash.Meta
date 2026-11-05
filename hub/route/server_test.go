package route

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"net"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/ca"
)

func resetTestControllers(t *testing.T) {
	t.Helper()
	ReCreateServer(&Config{})
	controllerMu.Lock()
	originalEmbed, originalPath := embedMode, uiPath
	controllerMu.Unlock()
	t.Cleanup(func() {
		ReCreateServer(&Config{})
		controllerMu.Lock()
		embedMode, uiPath = originalEmbed, originalPath
		controllerMu.Unlock()
	})
}

func controllerTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func controllerTestStatus(t *testing.T, client *stdhttp.Client, url, secret, origin string) (int, string) {
	t.Helper()
	req, err := stdhttp.NewRequest(stdhttp.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode, response.Header.Get("Access-Control-Allow-Origin")
}

func controllerTestClient(t *testing.T) *stdhttp.Client {
	t.Helper()
	transport := &stdhttp.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &stdhttp.Client{Transport: transport, Timeout: 3 * time.Second}
}

func assertControllerPortFree(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("controller still owns port after close/failure: %v", err)
	}
	_ = listener.Close()
}

func TestControllerRecreateBindsBeforeReturnAndReplacesSecret(t *testing.T) {
	resetTestControllers(t)
	address := controllerTestAddress(t)
	client := controllerTestClient(t)
	for i := 0; i < 40; i++ {
		secret := fmt.Sprintf("controller-test-%d", i)
		ReCreateServer(&Config{Addr: address, Secret: secret})
		if code, _ := controllerTestStatus(t, client, "http://"+address, secret, ""); code != 200 {
			t.Fatalf("new secret rejected at round %d: %d", i, code)
		}
		if code, _ := controllerTestStatus(t, client, "http://"+address, "previous-secret", ""); code != 401 {
			t.Fatalf("stale secret accepted at round %d: %d", i, code)
		}
	}
	ReCreateServer(&Config{})
	assertControllerPortFree(t, address)
}

func TestControllerConcurrentRecreatesCannotSurviveFinalClose(t *testing.T) {
	resetTestControllers(t)
	var pending sync.WaitGroup
	for i := 0; i < 64; i++ {
		pending.Add(1)
		go func(i int) {
			defer pending.Done()
			cfg := &Config{}
			if i%2 == 0 {
				cfg.Addr = "127.0.0.1:0"
			}
			ReCreateServer(cfg)
		}(i)
	}
	pending.Wait()
	address := controllerTestAddress(t)
	ReCreateServer(&Config{Addr: address, Secret: "last-request"})
	if code, _ := controllerTestStatus(t, controllerTestClient(t), "http://"+address, "last-request", ""); code != 200 {
		t.Fatalf("final request did not win: %d", code)
	}
	ReCreateServer(&Config{})
	if httpServer != nil || tlsServer != nil || unixServer != nil || pipeServer != nil {
		t.Fatal("final close left a published controller")
	}
	assertControllerPortFree(t, address)
}

func TestControllerCloseReleasesListenerBeforeServeRegisters(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	server := &http.Server{}
	// 作者 long：故意不启动Serve，稳定覆盖刚发布服务就重建的窗口；不能靠goroutine碰巧先执行来释放旧端口。
	managed := &controllerServer{server: server, listener: listener}
	managed.close()
	assertControllerPortFree(t, address)
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("late Serve did not stay closed: %v", err)
	}
}

func controllerTestTLS(t *testing.T) (string, string, *stdhttp.Client) {
	t.Helper()
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	// 作者 long：证书只在本次测试内随机生成并仅用于回环；跳过自签信任校验不改变产品TLS配置或网络验收标准。
	transport := &stdhttp.Transport{DisableKeepAlives: true, TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}}
	t.Cleanup(transport.CloseIdleConnections)
	return certificate, privateKey, &stdhttp.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestControllerTLSRecreatesOnTheSamePort(t *testing.T) {
	resetTestControllers(t)
	certificate, privateKey, client := controllerTestTLS(t)
	address := controllerTestAddress(t)
	for i := 0; i < 12; i++ {
		secret := fmt.Sprintf("tls-test-%d", i)
		ReCreateServer(&Config{TLSAddr: address, Certificate: certificate, PrivateKey: privateKey, Secret: secret})
		if code, _ := controllerTestStatus(t, client, "https://"+address, secret, ""); code != 200 {
			t.Fatalf("TLS controller failed at round %d: %d", i, code)
		}
		if code, _ := controllerTestStatus(t, client, "https://"+address, "previous-secret", ""); code != 401 {
			t.Fatalf("TLS controller accepted stale secret: %d", code)
		}
	}
	ReCreateServer(&Config{})
	assertControllerPortFree(t, address)
}

func TestControllerInvalidTLSDoesNotHoldThePortOrRestoreOldService(t *testing.T) {
	resetTestControllers(t)
	certificate, privateKey, client := controllerTestTLS(t)
	for _, kind := range []string{"client-ca", "ech"} {
		t.Run(kind, func(t *testing.T) {
			address := controllerTestAddress(t)
			valid := Config{TLSAddr: address, Certificate: certificate, PrivateKey: privateKey, Secret: "valid"}
			ReCreateServer(&valid)
			if code, _ := controllerTestStatus(t, client, "https://"+address, "valid", ""); code != 200 {
				t.Fatalf("initial TLS controller failed: %d", code)
			}
			invalid := valid
			if kind == "client-ca" {
				invalid.ClientAuthCert = filepath.Join(t.TempDir(), "missing-ca.pem")
			} else {
				invalid.EchKey = "invalid-ech-test-key"
			}
			ReCreateServer(&invalid)
			if tlsServer != nil {
				t.Fatal("invalid configuration left the old TLS service running")
			}
			assertControllerPortFree(t, address)
			ReCreateServer(&valid)
			if code, _ := controllerTestStatus(t, client, "https://"+address, "valid", ""); code != 200 {
				t.Fatalf("corrected TLS configuration could not reuse port: %d", code)
			}
			ReCreateServer(&Config{})
		})
	}
}

func TestControllerUnixRecreatesAndKeepsLocalAuthenticationSemantics(t *testing.T) {
	resetTestControllers(t)
	// 作者 long：macOS Unix socket路径长度有限，短的专属临时目录避免测试名称把路径扩到系统上限之外。
	directory, err := os.MkdirTemp("", "kcr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "c.sock")
	transport := &stdhttp.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &stdhttp.Client{Transport: transport, Timeout: 3 * time.Second}
	for i := 0; i < 12; i++ {
		ReCreateServer(&Config{UnixAddr: path, Secret: "tcp-only-secret"})
		if code, _ := controllerTestStatus(t, client, "http://unix", "", ""); code != 200 {
			t.Fatalf("Unix controller unexpectedly required TCP secret: %d", code)
		}
	}
	ReCreateServer(&Config{})
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("Unix listener not released: %v", err)
	}
	_ = listener.Close()
}

func TestControllerRecreateFreezesSubmittedConfig(t *testing.T) {
	resetTestControllers(t)
	address := controllerTestAddress(t)
	cfg := &Config{Addr: address, Secret: "submitted-secret", Cors: Cors{AllowOrigins: []string{"https://submitted.example"}}}
	ReCreateServer(cfg)
	cfg.Secret = "later-secret"
	cfg.Cors.AllowOrigins[0] = "https://later.example"
	client := controllerTestClient(t)
	if code, origin := controllerTestStatus(t, client, "http://"+address, "submitted-secret", "https://submitted.example"); code != 200 || origin != "https://submitted.example" {
		t.Fatalf("caller mutation changed submitted controller: code=%d origin=%q", code, origin)
	}
}

func TestControllerSettingsSerializeRouterConstruction(t *testing.T) {
	resetTestControllers(t)
	path := t.TempDir()
	var pending sync.WaitGroup
	for i := 0; i < 32; i++ {
		pending.Add(1)
		go func(i int) {
			defer pending.Done()
			SetEmbedMode(i%2 == 0)
			SetUIPath(path)
			ReCreateServer(&Config{Addr: "127.0.0.1:0"})
		}(i)
	}
	pending.Wait()
	SetEmbedMode(true)
	address := controllerTestAddress(t)
	ReCreateServer(&Config{Addr: address})
	req, err := stdhttp.NewRequest(stdhttp.MethodPut, "http://"+address+"/configs/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := controllerTestClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatalf("embedded controller exposed config mutation: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	SetEmbedMode(false)
	ReCreateServer(&Config{Addr: address})
	// 作者 long：非嵌入模式仍注册原配置接口；只发送坏JSON验证路由，不加载或修改任何实际配置。
	req, err = stdhttp.NewRequest(stdhttp.MethodPut, "http://"+address+"/configs/", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	response, err = controllerTestClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("non-embedded controller lost config mutation route: %d", response.StatusCode)
	}
}
