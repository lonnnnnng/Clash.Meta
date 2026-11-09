package updater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"google.golang.org/protobuf/proto"
)

type geoTimeoutError struct{}

func (geoTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }
func (geoTimeoutError) Timeout() bool   { return true }
func (geoTimeoutError) Temporary() bool { return true }

type delayedFirstAcceptListener struct {
	net.Listener
	accepts atomic.Int32
	delay   time.Duration
}

func (l *delayedFirstAcceptListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.accepts.Add(1) == 1 {
		time.Sleep(l.delay)
	}
	return conn, nil
}

func TestGeoRetryErrorPolicy(t *testing.T) {
	for _, item := range []struct {
		name   string
		err    error
		status int
		retry  bool
	}{
		{"tls", &url.Error{Op: "Get", URL: "https://user:secret@example.test/private?sig=secret", Err: geoTimeoutError{}}, 0, true},
		{"partial", fmt.Errorf("body: %w", io.ErrUnexpectedEOF), 200, true},
		{"eof", io.EOF, 0, true},
		{"reset", syscall.ECONNRESET, 0, true},
		{"refused", syscall.ECONNREFUSED, 0, true},
		{"canceled", context.Canceled, 0, false},
		{"certificate", errors.New("x509: private diagnostic"), 0, false},
		{"403", errors.New("secret"), 403, false},
		{"404", errors.New("secret"), 404, false},
		{"501", errors.New("secret"), 501, false},
		{"408", errors.New("secret"), 408, true},
		{"429", errors.New("secret"), 429, true},
		{"500", errors.New("secret"), 500, true},
		{"502", errors.New("secret"), 502, true},
		{"503", errors.New("secret"), 503, true},
		{"504", errors.New("secret"), 504, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			reason, retry := geoDownloadFailure(item.err, item.status)
			if retry != item.retry || strings.Contains(reason, "secret") || strings.Contains(reason, "private") {
				t.Fatalf("reason=%q retry=%v want=%v", reason, retry, item.retry)
			}
		})
	}
}

// 作者 long：走真实HTTP响应和截断TCP，验证每次从原URL重下且残缺正文不会混入最终数据库。
func TestGeoRetryRestartsOriginalRedirectAfterGatewayAndTruncation(t *testing.T) {
	var starts, attempts atomic.Int32
	body := bytes.Repeat([]byte("database"), 32*1024)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			w.WriteHeader(504)
		case 2:
			conn, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			fmt.Fprintf(buffer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\npartial", len(body))
			buffer.Flush()
		default:
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Write(body)
		}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		starts.Add(1)
		http.Redirect(w, r, target.URL+"/signed?sig=private-value", 302)
	}))
	defer source.Close()
	vehicle := resource.NewHTTPVehicle(source.URL, "", "", nil, time.Second, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, hash, err := readGeoResourceWithin(ctx, "GEOSITE", vehicle, utils.HashType{}, 0)
	if err != nil || !bytes.Equal(data, body) || !hash.Equal(utils.MakeHash(body)) || starts.Load() != 3 || attempts.Load() != 3 {
		t.Fatalf("bytes=%d attempts=%d starts=%d err=%v", len(data), attempts.Load(), starts.Load(), err)
	}
}

// 作者 long：延迟HTTP/TLS服务端握手制造真实TLSHandshakeTimeout，确认下载恢复会重新走完整TLS与正文读取。
func TestGeoRetryRecoversAfterRealTLSHandshakeTimeout(t *testing.T) {
	var responses atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		responses.Add(1)
		_, _ = w.Write([]byte("complete after handshake retry"))
	}))
	listener := &delayedFirstAcceptListener{Listener: server.Listener, delay: 11 * time.Second}
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	certificate := server.TLS.Certificates[0].Certificate[0]
	if err := ca.AddCertificate(string(certificate)); err != nil {
		t.Fatal(err)
	}
	defer ca.ResetCertificate()
	vehicle := resource.NewHTTPVehicle(server.URL, "", "", nil, 25*time.Second, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	data, _, err := readGeoResourceWithin(ctx, "MMDB", vehicle, utils.HashType{}, 0)
	if err != nil || string(data) != "complete after handshake retry" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if listener.accepts.Load() != 2 || responses.Load() != 1 {
		t.Fatalf("tcp connections=%d successful responses=%d", listener.accepts.Load(), responses.Load())
	}
	if elapsed := time.Since(started); elapsed < 10*time.Second || elapsed > 20*time.Second {
		t.Fatalf("elapsed=%s, want one real TLS timeout followed by one successful retry", elapsed)
	}
}

func TestGeoRetryPersistentFailureIsBoundedAndReturnsNoPartialData(t *testing.T) {
	for _, status := range []int{403, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.WriteHeader(status)
				io.WriteString(w, "secret-response")
			}))
			defer server.Close()
			vehicle := resource.NewHTTPVehicle(server.URL+"/private?sig=secret", "", "", nil, time.Second, 0)
			data, hash, err := readGeoResourceWithin(context.Background(), "ASN", vehicle, utils.HashType{}, 0)
			want := int32(3)
			if status == 403 {
				want = 1
			}
			if err == nil || len(data) != 0 || hash.IsValid() || attempts.Load() != want || strings.Contains(err.Error(), "secret") {
				t.Fatalf("attempts=%d want=%d data=%q hash=%v err=%v", attempts.Load(), want, data, hash, err)
			}
		})
	}
}

func TestGeoRetryHonorsRetryAfterAndTotalDeadline(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	vehicle := resource.NewHTTPVehicle(server.URL, "", "", nil, time.Second, 0)
	_, _, err := readGeoResourceWithin(ctx, "MMDB", vehicle, utils.HashType{}, 0)
	if !errors.Is(err, context.DeadlineExceeded) || attempts.Load() != 1 {
		t.Fatalf("attempts=%d err=%v", attempts.Load(), err)
	}
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if geoRetryAfter(now.Add(5*time.Second).Format(http.TimeFormat), now) != 5*time.Second {
		t.Fatal("HTTP-date not respected")
	}
	if geoRetryAfter("-1", now) != 0 || geoRetryAfter("invalid", now) != 0 {
		t.Fatal("invalid Retry-After")
	}
}

func TestGeoRetryCancellationStopsBodyAndFurtherAttempts(t *testing.T) {
	var attempts atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Length", "99999")
		io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	vehicle := resource.NewHTTPVehicle(server.URL, "", "", nil, time.Second, 0)
	data, _, err := readGeoResourceWithin(ctx, "GEOIP", vehicle, utils.HashType{}, 0)
	if err == nil || data != nil || attempts.Load() != 1 {
		t.Fatalf("attempts=%d bytes=%d err=%v", attempts.Load(), len(data), err)
	}
}

// 作者 long：从公开更新入口验证失败旧文件保护、单次终态、手动再试和有效新正文落盘。
func TestGeoUpdateRetryEmitsOneCompletionAndPreservesOldFile(t *testing.T) {
	oldHome, oldURL, oldHook := C.Path.HomeDir(), geodata.GeoSiteUrl(), GeoUpdateHook
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome); geodata.SetGeoSiteUrl(oldURL); GeoUpdateHook = oldHook })
	body, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "cn", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "example.test"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("old-file")
	path := C.Path.GeoSite()
	os.MkdirAll(filepath.Dir(path), 0700)
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	originalTime := time.Unix(100000, 0)
	os.Chtimes(path, originalTime, originalTime)
	var attempts atomic.Int32
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		switch mode.Load() {
		case 0:
			w.WriteHeader(504)
		case 1:
			if attempt == 1 {
				w.WriteHeader(503)
				return
			}
			w.Write(body)
		case 2:
			io.WriteString(w, "invalid-database")
		}
	}))
	defer server.Close()
	geodata.SetGeoSiteUrl(server.URL)
	var begins, ends int
	var terminal error
	GeoUpdateHook = func(kind string, updating, skipped bool, err error) {
		if kind != "GEOSITE" {
			t.Errorf("kind=%s", kind)
		}
		if updating {
			begins++
		} else {
			ends++
			terminal = err
		}
	}
	if err = UpdateGeoSite(); err == nil || terminal == nil || attempts.Load() != 3 || begins != 1 || ends != 1 {
		t.Fatalf("attempts=%d events=%d/%d err=%v", attempts.Load(), begins, ends, err)
	}
	got, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if !bytes.Equal(got, old) || !info.ModTime().Equal(originalTime) {
		t.Fatal("failed download changed old database")
	}
	mode.Store(1)
	attempts.Store(0)
	begins, ends = 0, 0
	if err = UpdateGeoSite(); err != nil || terminal != nil || attempts.Load() != 2 || begins != 1 || ends != 1 {
		t.Fatalf("attempts=%d events=%d/%d err=%v", attempts.Load(), begins, ends, err)
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatal("complete validated database not saved")
	}
	mode.Store(2)
	attempts.Store(0)
	if err = UpdateGeoSite(); err == nil || attempts.Load() != 1 {
		t.Fatalf("validation must not retry: attempts=%d err=%v", attempts.Load(), err)
	}
	got, _ = os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatal("invalid database replaced valid file")
	}
}
