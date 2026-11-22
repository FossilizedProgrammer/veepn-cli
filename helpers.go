package main

import (
	"flag"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"veepn/internal/config"
)

// singboxVersion reports the sing-box module version linked into the
// binary (the library's own constant is only set by its own build).
func singboxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
			return strings.TrimPrefix(dep.Version, "v")
		}
	}
	return "unknown"
}

type flagSet = flag.FlagSet

func newFlagSet(name string) *flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	return fs
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// newDirectClient is the plain client used by `ip --direct`; it
// honours the configured http_proxy when set.
func newDirectClient(cfg config.Config) *http.Client {
	tr := &http.Transport{DisableKeepAlives: true}
	if cfg.HTTPProxy != "" {
		if u, err := url.Parse(cfg.HTTPProxy); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}
