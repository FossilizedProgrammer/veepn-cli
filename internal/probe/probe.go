// Package probe holds the reachability checks: the parallel TCP
// latency sweep (like MainActivity.tcpProbeServer) and the
// "through the proxy" checks used after connecting and by the
// watchdog (exit IP, generate_204 latency).
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"veepn/internal/sub"
	"veepn/internal/upstream"
)

// Result is one measured server.
type Result struct {
	Server sub.Server
	MS     int64 // -1 = no answer (TIMEOUT)
}

// Sweep measures every server with N parallel TCP connects and
// returns the results in the input order.
func Sweep(servers []sub.Server, timeout time.Duration, parallel int) []Result {
	return SweepVia(servers, timeout, parallel, nil)
}

// SweepVia is Sweep, but with every probe dialed through up when it
// is set — the same path connect will use.
func SweepVia(servers []sub.Server, timeout time.Duration, parallel int, up *upstream.Upstream) []Result {
	if parallel <= 0 {
		parallel = 20
	}
	if parallel > len(servers) {
		parallel = len(servers)
	}
	results := make([]Result, len(servers))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s sub.Server) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = Result{Server: s, MS: dialLatency(s.Endpoint(), timeout, up)}
		}(i, s)
	}
	wg.Wait()
	return results
}

// dialLatency measures the connect time through up (direct when nil).
func dialLatency(endpoint string, timeout time.Duration, up *upstream.Upstream) int64 {
	if up == nil {
		return TCP(endpoint, timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := up.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds()
}

// TCP returns the time to establish a TCP connection, or -1.
func TCP(endpoint string, timeout time.Duration) int64 {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds()
}

// SocksClient builds an HTTP client whose traffic goes through the
// local mixed (SOCKS5) inbound.
func SocksClient(socksPort int, timeout time.Duration) *http.Client {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	transport := &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, target)
			}
			return d.Dial(network, target)
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// ExitIP asks api.ipify.org (through the proxy) for the public IP.
func ExitIP(socksPort int, timeout time.Duration) (string, error) {
	client := SocksClient(socksPort, timeout)
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ipify HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	var v struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &v) != nil || v.IP == "" {
		return "", fmt.Errorf("unexpected ipify response")
	}
	return v.IP, nil
}

// Health fetches generate_204 through the proxy and returns the
// round-trip time; an error means the tunnel is not passing traffic.
func Health(socksPort int, timeout time.Duration) (time.Duration, error) {
	client := SocksClient(socksPort, timeout)
	start := time.Now()
	resp, err := client.Get("http://www.gstatic.com/generate_204")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("generate_204 HTTP %d", resp.StatusCode)
	}
	return time.Since(start), nil
}
