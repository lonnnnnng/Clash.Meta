package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 作者 long：分别观察重定向源和正文源的真实TCP关闭，避免只检查头字段却漏掉请求私有连接池泄漏。
func lifecycleServer(t *testing.T, handler stdhttp.HandlerFunc) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	closed := make(chan struct{}, 8)
	s := httptest.NewUnstartedServer(handler)
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateClosed {
			closed <- struct{}{}
		}
	}
	s.Start()
	t.Cleanup(s.Close)
	return s, closed
}
func awaitLifecycleClose(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("本次请求的TCP连接未及时回收")
	}
}
func TestDownloadKeepsBodyAliveAndClosesRedirectConnections(t *testing.T) {
	prefix := make(chan struct{})
	finish := make(chan struct{})
	target, targetClosed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Close {
			t.Error("下载器不应强制Connection:close")
		}
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "first")
		w.(stdhttp.Flusher).Flush()
		close(prefix)
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "last!")
	})
	redirect, redirectClosed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Close {
			t.Error("重定向请求不应强制Connection:close")
		}
		stdhttp.Redirect(w, r, target.URL, stdhttp.StatusFound)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, redirect.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-prefix
	first := make([]byte, 5)
	if _, err = io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-targetClosed:
		t.Fatal("正文未完成前连接已关闭")
	default:
	}
	close(finish)
	tail, err := io.ReadAll(response.Body)
	if err != nil || string(first)+string(tail) != "firstlast!" {
		t.Fatalf("正文=%q+%q，错误=%v", first, tail, err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	awaitLifecycleClose(t, redirectClosed)
	awaitLifecycleClose(t, targetClosed)
}
func TestDownloadEarlyBodyCloseReclaimsRedirectAndActiveConnection(t *testing.T) {
	target, targetClosed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Length", "1000000")
		_, _ = io.WriteString(w, "prefix")
		w.(stdhttp.Flusher).Flush()
		<-r.Context().Done()
	})
	redirect, redirectClosed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.Redirect(w, r, target.URL, stdhttp.StatusFound)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, redirect.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	awaitLifecycleClose(t, redirectClosed)
	awaitLifecycleClose(t, targetClosed)
}
func TestDownloadTruncatedBodyStaysFailureAndReclaimsRedirect(t *testing.T) {
	target, _ := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		c, b, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		fmt.Fprint(b, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
		b.Flush()
	})
	redirect, redirectClosed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.Redirect(w, r, target.URL, stdhttp.StatusFound)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, redirect.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if !errors.Is(err, io.ErrUnexpectedEOF) || string(data) != "partial" {
		t.Fatalf("截断正文=%q err=%v", data, err)
	}
	response.Body.Close()
	awaitLifecycleClose(t, redirectClosed)
}
func TestDownloadRedirectFailureClosesExistingIdleConnection(t *testing.T) {
	redirect, closed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.Redirect(w, r, "file:///unsupported", stdhttp.StatusFound)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := HttpRequest(ctx, redirect.URL, "GET", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol scheme") {
		t.Fatalf("err=%v", err)
	}
	awaitLifecycleClose(t, closed)
}
func TestDownloadExplicitCloseHeaderRemainsCallerControlled(t *testing.T) {
	target, closed := lifecycleServer(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if !r.Close {
			t.Error("显式Connection:close被覆盖")
		}
		io.WriteString(w, "ok")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, target.URL, "GET", map[string][]string{"Connection": {"close"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != "ok" {
		t.Fatalf("正文=%q err=%v", data, err)
	}
	awaitLifecycleClose(t, closed)
}
