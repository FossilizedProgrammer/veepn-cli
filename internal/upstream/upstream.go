// Package upstream lets the CLI reach the VeePN servers through
// another local proxy (SOCKS5 or HTTP CONNECT) instead of dialing
// them directly — the desktop counterpart of the app's "connect
// through" option. sing-box chains the server outbound behind the
// upstream via its detour field; the probes dial through the same
// proxy so ping/test measure the path that connect will use.
package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Kind is the upstream proxy protocol.
type Kind int

const (
	// Socks5 is a SOCKS5 proxy (socks5://, socks5h://, socks://).
	Socks5 Kind = iota
	// HTTP is an HTTP proxy used through CONNECT (http://).
	HTTP
)

// Upstream is a parsed upstream proxy URL.
type Upstream struct {
	Kind     Kind
	Host     string
	Port     int
	Username string
	Password string
}

// Parse reads "socks5://[user:pass@]host:port" or
// "http://[user:pass@]host:port". A bare "host:port" means SOCKS5,
// which is what a locally running client usually exposes.
func Parse(raw string) (*Upstream, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("empty upstream")
	}
	if !strings.Contains(s, "://") {
		s = "socks5://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", raw, err)
	}
	up := &Upstream{}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
		up.Kind = Socks5
	case "http":
		up.Kind = HTTP
	case "https":
		return nil, fmt.Errorf("https:// upstream proxies are not supported; use http:// or socks5://")
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q (use socks5:// or http://)", u.Scheme)
	}
	up.Host = u.Hostname()
	if up.Host == "" {
		return nil, fmt.Errorf("upstream %q has no host", raw)
	}
	portStr := u.Port()
	if portStr == "" {
		return nil, fmt.Errorf("upstream %q has no port (want host:port)", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid upstream port %q", portStr)
	}
	up.Port = port
	if u.User != nil {
		up.Username = u.User.Username()
		up.Password, _ = u.User.Password()
	}
	return up, nil
}

// Addr is the upstream endpoint.
func (u *Upstream) Addr() string {
	return net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
}

// String hides the credentials so it is safe for logs and status.
func (u *Upstream) String() string {
	if u == nil {
		return ""
	}
	if u.Username != "" {
		return fmt.Sprintf("%s://%s@%s", u.scheme(), u.Username, u.Addr())
	}
	return fmt.Sprintf("%s://%s", u.scheme(), u.Addr())
}

func (u *Upstream) scheme() string {
	if u.Kind == HTTP {
		return "http"
	}
	return "socks5"
}

// Outbound returns the sing-box outbound that dials the upstream.
// The server outbound points at it with "detour": "upstream-out".
func (u *Upstream) Outbound() map[string]any {
	out := map[string]any{
		"tag":         "upstream-out",
		"server":      u.Host,
		"server_port": u.Port,
	}
	if u.Kind == HTTP {
		out["type"] = "http"
	} else {
		out["type"] = "socks"
		out["version"] = "5"
	}
	if u.Username != "" {
		out["username"] = u.Username
		out["password"] = u.Password
	}
	return out
}

// DialContext connects to addr through the upstream.
func (u *Upstream) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("upstream: unsupported network %q", network)
	}
	if u.Kind == HTTP {
		return u.dialHTTP(ctx, addr)
	}
	return u.dialSocks5(ctx, network, addr)
}

func (u *Upstream) dialSocks5(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if u.Username != "" {
		auth = &proxy.Auth{User: u.Username, Password: u.Password}
	}
	d, err := proxy.SOCKS5(network, u.Addr(), auth, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}

// dialHTTP opens a CONNECT tunnel through an HTTP proxy, including
// the basic-auth header when the URL carries credentials.
func (u *Upstream) dialHTTP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", u.Addr())
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.String(), err)
	}
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if u.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(u.Username + ":" + u.Password))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", token)
	}
	req.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream %s: %w", u.String(), err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream %s: %w", u.String(), err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("upstream %s refused CONNECT %s: %s", u.String(), addr, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn keeps the bytes the proxy sent right after the CONNECT
// response, which are part of the tunneled stream.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
