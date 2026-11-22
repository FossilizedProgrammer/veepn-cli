package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/proxy"

	"veepn/internal/engine"
	"veepn/internal/sub"
	"veepn/internal/upstream"
)

// Real checks run actual traffic through a server (a TLS request plus
// an optional download), which is the only reliable way to tell a
// working server from one that accepts TCP but drops the tunnel.

const (
	checkURL = "https://www.gstatic.com/generate_204"
	altURL   = "https://api.ipify.org?format=json"
	speedURL = "https://speed.cloudflare.com/__down?bytes=524288"
)

// RealResult is the outcome of one server check.
type RealResult struct {
	Server     sub.Server `json:"-"`
	Index      int        `json:"index"`
	OK         bool       `json:"ok"`
	LatencyMS  int64      `json:"latency_ms"`
	StatusCode int        `json:"status_code,omitempty"`
	SpeedKBps  float64    `json:"speed_kbps,omitempty"`
	Err        string     `json:"error,omitempty"`
}

// RealCheck verifies one server end-to-end, dialing through up when
// it is set.
func RealCheck(ctx context.Context, srv sub.Server, up *upstream.Upstream, timeout time.Duration, measureSpeed bool) RealResult {
	res := RealResult{Server: srv}
	client, cleanup, err := clientFor(ctx, srv, up, timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer cleanup()

	start := time.Now()
	code, err := httpGet(client, checkURL)
	if err != nil {
		code, err = httpGet(client, altURL)
	}
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.OK = true
	res.StatusCode = code
	if measureSpeed {
		// A 512 KB download needs more than the probe timeout.
		if client.Timeout < 25*time.Second {
			client.Timeout = 25 * time.Second
		}
		res.SpeedKBps = measureSpeedKBps(client, timeout)
	}
	return res
}

// RealSweep checks every server with bounded parallelism.
func RealSweep(ctx context.Context, list []sub.Server, up *upstream.Upstream, timeout time.Duration, parallel int, measureSpeed bool, progress func(done, total int)) []RealResult {
	if parallel < 1 {
		parallel = 1
	}
	results := make([]RealResult, len(list))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i := range list {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := RealCheck(ctx, list[i], up, timeout, measureSpeed)
			res.Index = i + 1
			results[i] = res
			mu.Lock()
			done++
			if progress != nil {
				progress(done, len(list))
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func clientFor(ctx context.Context, srv sub.Server, up *upstream.Upstream, timeout time.Duration) (*http.Client, func(), error) {
	if srv.Proto == "vmess" {
		return vmessClient(ctx, srv, up, timeout)
	}
	method, err := shadowaead.New(srv.Method, nil, srv.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported ss method %q: %w", srv.Method, err)
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		if up != nil {
			conn, err = up.DialContext(ctx, "tcp", srv.Endpoint())
		} else {
			d := net.Dialer{Timeout: timeout}
			conn, err = d.DialContext(ctx, "tcp", srv.Endpoint())
		}
		if err != nil {
			return nil, err
		}
		ssConn, err := method.DialConn(conn, M.ParseSocksaddrHostPort(host, uint16(port)))
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return ssConn, nil
	}
	return newClient(dial, timeout), func() {}, nil
}

// vmessClient uses a throw-away sing-box instance with a SOCKS
// inbound, since VMess is only implemented by the full engine.
func vmessClient(ctx context.Context, srv sub.Server, up *upstream.Upstream, timeout time.Duration) (*http.Client, func(), error) {
	port, err := freePort()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := engine.BuildConfig(engine.Options{
		Server:    srv,
		SocksPort: port,
		LogLevel:  "error",
		Upstream:  up,
	})
	if err != nil {
		return nil, nil, err
	}
	instance, err := engine.Start(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		_ = instance.Close()
		return nil, nil, err
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		_ = instance.Close()
		return nil, nil, fmt.Errorf("socks dialer does not support contexts")
	}
	client := newClient(ctxDialer.DialContext, timeout)
	return client, func() { _ = instance.Close() }, nil
}

func newClient(dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         dial,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   false,
		},
	}
}

func httpGet(client *http.Client, url string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func measureSpeedKBps(client *http.Client, timeout time.Duration) float64 {
	start := time.Now()
	resp, err := client.Get(speedURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 || n == 0 {
		return 0
	}
	return float64(n) / 1024 / elapsed
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
