// Package engine turns one subscription server into a running
// sing-box instance whose only inbound is a local mixed proxy
// (SOCKS5 + HTTP CONNECT) plus an optional HTTP proxy — the same
// "proxy mode" config the Android app builds in
// SingBoxConfig.buildServer/buildVmess, without the TUN inbound.
package engine

import (
	"context"
	"encoding/json"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"veepn/internal/sub"
	"veepn/internal/upstream"
)

// Options for one proxy instance.
type Options struct {
	Server    sub.Server
	SocksPort int
	HTTPPort  int // 0 or equal to SocksPort: no separate HTTP inbound
	LogLevel  string
	Bind      string // default 127.0.0.1
	// Upstream, when set, makes the server outbound dial through
	// that SOCKS5/HTTP proxy instead of the local network.
	Upstream *upstream.Upstream
}

// BuildConfig returns the sing-box JSON config for one server.
func BuildConfig(o Options) ([]byte, error) {
	bind := o.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	if o.SocksPort <= 0 || o.SocksPort > 65535 {
		return nil, fmt.Errorf("invalid socks port %d", o.SocksPort)
	}
	level := o.LogLevel
	if level == "" {
		level = "warn"
	}

	inbounds := []any{
		map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      bind,
			"listen_port": o.SocksPort,
		},
	}
	if o.HTTPPort > 0 && o.HTTPPort != o.SocksPort {
		inbounds = append(inbounds, map[string]any{
			"type":        "http",
			"tag":         "http-in",
			"listen":      bind,
			"listen_port": o.HTTPPort,
		})
	}

	outbound, err := buildOutbound(o.Server)
	if err != nil {
		return nil, err
	}

	outbounds := []any{
		map[string]any{"type": "direct", "tag": "direct-out"},
		outbound,
	}
	if o.Upstream != nil {
		// detour is sing-box's dial-through-outbound: traffic to the
		// server leaves through the upstream proxy, while DNS and
		// everything else still follow proxy-out.
		outbound["detour"] = "upstream-out"
		outbounds = []any{
			map[string]any{"type": "direct", "tag": "direct-out"},
			o.Upstream.Outbound(),
			outbound,
		}
	}

	config := map[string]any{
		"log": map[string]any{
			"level":     level,
			"timestamp": true,
		},
		// Same DNS shape as the app: a local resolver for server
		// names and DoH through the proxy for everything else.
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "local-dns", "type": "local"},
				map[string]any{
					"tag":         "remote-dns",
					"type":        "https",
					"server":      "1.1.1.1",
					"server_port": 443,
					"detour":      "proxy-out",
				},
			},
			"final":         "remote-dns",
			"disable_cache": false,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"outbound": "proxy-out"},
			},
			"final": "proxy-out",
			"default_domain_resolver": map[string]any{
				"server": "local-dns",
			},
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{"enabled": false},
		},
	}
	return json.MarshalIndent(config, "", "  ")
}

func buildOutbound(s sub.Server) (map[string]any, error) {
	switch s.Proto {
	case "ss", "":
		if s.Method == "" || s.Password == "" {
			return nil, fmt.Errorf("server %s has no Shadowsocks credentials", s.Endpoint())
		}
		return map[string]any{
			"type":        "shadowsocks",
			"tag":         "proxy-out",
			"server":      s.IP,
			"server_port": s.Port,
			"method":      s.Method,
			"password":    s.Password,
		}, nil
	case "vmess":
		if s.UUID == "" {
			return nil, fmt.Errorf("server %s has no VMess uuid", s.Endpoint())
		}
		out := map[string]any{
			"type":        "vmess",
			"tag":         "proxy-out",
			"server":      s.IP,
			"server_port": s.Port,
			"uuid":        s.UUID,
			"alter_id":    s.AlterID,
			"security":    "auto",
		}
		// sing-box accepts only http/ws/quic/grpc/httpupgrade as a
		// transport; plain TCP must have no transport object at all.
		switch s.Network {
		case "ws":
			tr := map[string]any{"type": "ws"}
			if s.Path != "" {
				tr["path"] = s.Path
			}
			if s.Host != "" {
				tr["headers"] = map[string]any{"Host": s.Host}
			}
			out["transport"] = tr
		case "http", "h2":
			tr := map[string]any{"type": "http"}
			if s.Host != "" {
				tr["host"] = []any{s.Host}
			}
			if s.Path != "" {
				tr["path"] = s.Path
			}
			out["transport"] = tr
		case "grpc":
			tr := map[string]any{"type": "grpc"}
			if s.Path != "" {
				tr["service_name"] = s.Path
			}
			out["transport"] = tr
		case "quic":
			out["transport"] = map[string]any{"type": "quic"}
		case "httpupgrade":
			tr := map[string]any{"type": "httpupgrade"}
			if s.Host != "" {
				tr["host"] = s.Host
			}
			if s.Path != "" {
				tr["path"] = s.Path
			}
			out["transport"] = tr
		}
		if s.TLS == "tls" {
			sni := s.ServerName
			if sni == "" {
				sni = s.IP
			}
			out["tls"] = map[string]any{"enabled": true, "server_name": sni}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", s.Proto)
	}
}

// Start creates and starts a sing-box instance. Close it to stop.
func Start(ctx context.Context, cfg []byte) (*box.Box, error) {
	// The JSON decoder needs the same registries as the instance:
	// option.Options parses inbounds/outbounds/dns by type name.
	ctx = include.Context(ctx)
	var options option.Options
	if err := sjson.UnmarshalContext(ctx, cfg, &options); err != nil {
		return nil, fmt.Errorf("invalid sing-box config: %w", err)
	}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}
