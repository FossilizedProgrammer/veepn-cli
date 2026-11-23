package engine_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"veepn/internal/engine"
	"veepn/internal/probe"
	"veepn/internal/sub"
)

// TestBuildConfigVariants checks that every outbound shape the
// parser can produce is accepted by the sing-box 1.14 decoder
// (transports, TLS, DNS/route sections).
func TestBuildConfigVariants(t *testing.T) {
	base := sub.Server{
		Proto: "vmess", IP: "203.0.113.7", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", AlterID: 0,
	}
	cases := []sub.Server{
		{Proto: "ss", IP: "203.0.113.7", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
		base,
		func() sub.Server {
			s := base
			s.Network, s.Path, s.Host, s.TLS = "ws", "/ws", "cdn.example", "tls"
			return s
		}(),
		func() sub.Server {
			s := base
			s.Network, s.Path, s.Host, s.TLS = "http", "/h2", "cdn.example", "tls"
			return s
		}(),
		func() sub.Server { s := base; s.Network, s.Path, s.TLS = "grpc", "svc", "tls"; return s }(),
		func() sub.Server { s := base; s.Network, s.TLS = "quic", "tls"; return s }(),
		func() sub.Server {
			s := base
			s.Network, s.Path, s.Host, s.TLS = "httpupgrade", "/hu", "cdn.example", "tls"
			return s
		}(),
		func() sub.Server {
			s := base
			s.Proto, s.TLS, s.ServerName, s.Flow = "vless", "tls", "cdn.example", "xtls-rprx-vision"
			s.Fingerprint, s.PublicKey, s.ShortID = "firefox", "PUBKEY", "ab12"
			return s
		}(),
		func() sub.Server {
			s := base
			s.Proto, s.Network, s.Path, s.Host = "vless", "ws", "/ws", "cdn.example"
			s.TLS, s.ServerName, s.ALPN = "tls", "cdn.example", "h2,http/1.1"
			return s
		}(),
		func() sub.Server {
			s := base
			s.Proto, s.UUID, s.Password, s.Network = "trojan", "", "pw", "tcp"
			s.TLS, s.ServerName = "tls", "t.example"
			return s
		}(),
	}
	ctx := include.Context(context.Background())
	for i, srv := range cases {
		cfg, err := engine.BuildConfig(engine.Options{Server: srv, SocksPort: 11200, HTTPPort: 11201})
		if err != nil {
			t.Fatalf("case %d (%s/%s): %v", i, srv.Proto, srv.Network, err)
		}
		var opts option.Options
		if err := sjson.UnmarshalContext(ctx, cfg, &opts); err != nil {
			t.Fatalf("case %d (%s/%s) rejected by sing-box: %v\n%s", i, srv.Proto, srv.Network, err, cfg)
		}
		if len(opts.Outbounds) != 2 || opts.Outbounds[1].Tag != "proxy-out" {
			t.Fatalf("case %d: unexpected outbounds %+v", i, opts.Outbounds)
		}
	}
}

// TestProxyPath starts a local Shadowsocks server with sing-box,
// points the CLI config at it, and fetches a local HTTP page through
// the SOCKS inbound. This exercises the whole path the CLI uses for
// real servers (engine config -> box instance -> mixed inbound ->
// SS outbound) without needing an external subscription.
func TestProxyPath(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok-through-proxy")
	}))
	defer target.Close()

	ssPort, socksPort, httpPort := freePort(t), freePort(t), freePort(t)
	serverCfg := []byte(fmt.Sprintf(`{
	  "log": {"level": "error"},
	  "inbounds": [{
	    "type": "shadowsocks", "tag": "ss-in",
	    "listen": "127.0.0.1", "listen_port": %d,
	    "method": "aes-128-gcm", "password": "testpass"
	  }],
	  "outbounds": [{"type": "direct", "tag": "direct"}]
	}`, ssPort))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := engine.Start(ctx, serverCfg)
	if err != nil {
		t.Fatalf("start test shadowsocks server: %v", err)
	}
	defer server.Close()

	waitPort(t, fmt.Sprintf("127.0.0.1:%d", ssPort))

	cfg, err := engine.BuildConfig(engine.Options{
		Server: sub.Server{
			Proto: "ss", IP: "127.0.0.1", Port: ssPort,
			Method: "aes-128-gcm", Password: "testpass",
		},
		SocksPort: socksPort,
		HTTPPort:  httpPort,
		LogLevel:  "error",
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	client, err := engine.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer client.Close()

	waitPort(t, fmt.Sprintf("127.0.0.1:%d", socksPort))
	waitPort(t, fmt.Sprintf("127.0.0.1:%d", httpPort))

	hc := probe.SocksClient(socksPort, 10*time.Second)
	resp, err := hc.Get(target.URL)
	if err != nil {
		t.Fatalf("GET through SOCKS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok-through-proxy" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, body)
	}

	// The HTTP inbound serves the same proxy.
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
	if err != nil {
		t.Fatal(err)
	}
	pc := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	r2, err := pc.Get(target.URL)
	if err != nil {
		t.Fatalf("GET through HTTP proxy: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("HTTP inbound returned %d", r2.StatusCode)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s never opened", addr)
}
