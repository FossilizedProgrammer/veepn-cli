package upstream_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"veepn/internal/engine"
	"veepn/internal/sub"
	"veepn/internal/upstream"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		kind    upstream.Kind
		addr    string
		user    string
		wantErr bool
	}{
		{in: "socks5://127.0.0.1:1080", kind: upstream.Socks5, addr: "127.0.0.1:1080"},
		{in: "socks5h://u:p@10.0.0.2:9050", kind: upstream.Socks5, addr: "10.0.0.2:9050", user: "u"},
		{in: "http://192.168.1.5:8080", kind: upstream.HTTP, addr: "192.168.1.5:8080"},
		{in: "127.0.0.1:7890", kind: upstream.Socks5, addr: "127.0.0.1:7890"},
		{in: "https://127.0.0.1:443", wantErr: true},
		{in: "socks5://127.0.0.1", wantErr: true},
		{in: "ftp://127.0.0.1:21", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		up, err := upstream.Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %v, want error", c.in, up)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if up.Kind != c.kind || up.Addr() != c.addr || up.Username != c.user {
			t.Errorf("Parse(%q) = kind %v addr %s user %q, want %v %s %q",
				c.in, up.Kind, up.Addr(), up.Username, c.kind, c.addr, c.user)
		}
	}
}

// TestDialThroughProxies sends a payload through a fake proxy of each
// kind to a local echo listener, which is what a real connect does.
func TestDialThroughProxies(t *testing.T) {
	echo := startEcho(t)
	for _, tc := range []struct {
		name  string
		kind  upstream.Kind
		serve func(net.Conn, string)
	}{
		{"socks5", upstream.Socks5, serveSocks5},
		{"http", upstream.HTTP, serveHTTP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go tc.serve(c, echo)
				}
			}()
			port := ln.Addr().(*net.TCPAddr).Port
			up := &upstream.Upstream{Kind: tc.kind, Host: "127.0.0.1", Port: port}

			conn, err := up.DialContext(context.Background(), "tcp", echo)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 5)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != "hello" {
				t.Fatalf("echoed %q, want %q", buf, "hello")
			}
		})
	}
}

// TestEngineConfigChainsUpstream checks the JSON the engine hands to
// sing-box: the server outbound must dial through upstream-out.
func TestEngineConfigChainsUpstream(t *testing.T) {
	up, err := upstream.Parse("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := engine.BuildConfig(engine.Options{
		Server:    sub.Server{Proto: "vmess", IP: "203.0.113.5", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Network: "ws"},
		SocksPort: 18080,
		Upstream:  up,
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var serverOut, upOut map[string]any
	for _, o := range cfg.Outbounds {
		switch o["tag"] {
		case "proxy-out":
			serverOut = o
		case "upstream-out":
			upOut = o
		}
	}
	if upOut == nil {
		t.Fatal("no upstream-out outbound in the config")
	}
	if upOut["type"] != "socks" || upOut["server_port"] != float64(1080) || upOut["username"] != "user" {
		t.Fatalf("unexpected upstream outbound: %v", upOut)
	}
	if serverOut == nil || serverOut["detour"] != "upstream-out" {
		t.Fatalf("proxy-out does not dial through the upstream: %v", serverOut)
	}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// serveSocks5 is a no-auth SOCKS5 CONNECT proxy for the test.
func serveSocks5(c net.Conn, target string) {
	defer c.Close()
	br := bufio.NewReader(c)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, int(n))
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(br, port); err != nil {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
	upstream, err := net.Dial("tcp", addr)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	pipe(c, br, upstream)
}

// serveHTTP is a CONNECT proxy for the test.
func serveHTTP(c net.Conn, target string) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	pipe(c, br, upstream)
}

func pipe(c net.Conn, buffered *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, buffered); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func TestProxyURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "socks5://127.0.0.1:1080", want: "socks5://127.0.0.1:1080"},
		{in: "socks5h://u:p@10.0.0.2:9050", want: "socks5://u:p@10.0.0.2:9050"},
		{in: "http://u:p%40ss@192.168.1.5:8080", want: "http://u:p%40ss@192.168.1.5:8080"},
		{in: "127.0.0.1:7890", want: "socks5://127.0.0.1:7890"},
	}
	for _, c := range cases {
		up, err := upstream.Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if got := up.ProxyURL(); got != c.want {
			t.Errorf("ProxyURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	var nilUp *upstream.Upstream
	if got := nilUp.ProxyURL(); got != "" {
		t.Errorf("nil ProxyURL() = %q, want empty", got)
	}
}

func TestProxyURLKeepsPasswordOutOfString(t *testing.T) {
	up, err := upstream.Parse("socks5://user:secret@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(up.String(), "secret") {
		t.Errorf("String() leaked the password: %q", up.String())
	}
	if !strings.Contains(up.ProxyURL(), "secret") {
		t.Errorf("ProxyURL() dropped the password: %q", up.ProxyURL())
	}
}
