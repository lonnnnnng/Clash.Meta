package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/log"
)

const geoDownloadAttempts = 3
const geoDownloadBudget = 165 * time.Second

// 作者 long：只在下载层恢复瞬断，所有尝试共用预算且不发中间完成事件；校验和写入仍只执行一次。
func readGeoResource(geoType string, vehicle *resource.HTTPVehicle, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	ctx, cancel := context.WithTimeout(context.Background(), geoDownloadBudget)
	defer cancel()
	return readGeoResourceWithin(ctx, geoType, vehicle, oldHash, time.Second)
}

func readGeoResourceWithin(ctx context.Context, geoType string, vehicle *resource.HTTPVehicle, oldHash utils.HashType, backoff time.Duration) ([]byte, utils.HashType, error) {
	started := time.Now()
	initial, _ := url.Parse(vehicle.Url())
	for attempt := 1; attempt <= geoDownloadAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, utils.HashType{}, err
		}
		host := ""
		if initial != nil {
			host = initial.Hostname()
		}
		status, length, retryAfter := 0, int64(-1), ""
		vehicle.SetInRead(func(response *http.Response) {
			status, length = response.StatusCode, response.ContentLength
			retryAfter = response.Header.Get("Retry-After")
			if response.Request != nil && response.Request.URL != nil {
				host = response.Request.URL.Hostname()
			}
		})
		data, hash, err := vehicle.Read(ctx, oldHash)
		if err == nil {
			log.Infoln("[GEO] resource=%s attempt=%d/%d host=%q status=%d bytes=%d length=%d elapsed_ms=%d outcome=downloaded",
				geoType, attempt, geoDownloadAttempts, host, status, len(data), length, time.Since(started).Milliseconds())
			return data, hash, nil
		}
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			if target, parseErr := url.Parse(requestErr.URL); parseErr == nil {
				host = target.Hostname()
			}
		}
		reason, retryable := geoDownloadFailure(err, status)
		willRetry := retryable && attempt < geoDownloadAttempts && ctx.Err() == nil
		// 作者 long：签名重定向URL可能含凭据，只记录主机、白名单错误与字节数，逐次失败不被最终成功覆盖。
		// 作者 long：默认日志等级为error，失败尝试也保留证据；retry字段明确它是否仍会恢复，避免成功后丢掉失败现场。
		log.Errorln("[GEO] resource=%s attempt=%d/%d host=%q status=%d bytes=%d length=%d elapsed_ms=%d reason=%q retry=%t",
			geoType, attempt, geoDownloadAttempts, host, status, len(data), length, time.Since(started).Milliseconds(), reason, willRetry)
		if !willRetry {
			return nil, utils.HashType{}, fmt.Errorf("%s (attempts=%d)", reason, attempt)
		}
		delay := time.Duration(attempt) * backoff
		if wait := geoRetryAfter(retryAfter, time.Now()); wait > delay {
			delay = wait
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, utils.HashType{}, ctx.Err()
		case <-timer.C:
		}
	}
	panic("unreachable geo download attempt")
}

func geoDownloadFailure(err error, status int) (string, bool) {
	if status >= 400 {
		retry := status == 408 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504
		return fmt.Sprintf("%d %s", status, http.StatusText(status)), retry
	}
	if errors.Is(err, context.Canceled) {
		return "request canceled", false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return "unexpected EOF", true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return "connection interrupted", true
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "network timeout", true
	}
	return "request failed", false
}

func geoRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32); err == nil {
		// 作者 long：服务器要求的等待可耗尽总预算，但不能溢出为负数并提前重试。
		return time.Duration(seconds) * time.Second
	}
	if target, err := http.ParseTime(value); err == nil && target.After(now) {
		return target.Sub(now)
	}
	return 0
}
