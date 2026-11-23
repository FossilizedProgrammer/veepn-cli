package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"veepn/internal/config"
	"veepn/internal/upstream"
)

func TestFetchProxy(t *testing.T) {
	up, err := upstream.Parse("socks5://user:secret@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}

	if got := fetchProxy(config.Config{}, nil); got != "" {
		t.Errorf("no upstream and no http_proxy = %q, want empty", got)
	}
	if got := fetchProxy(config.Config{}, up); got != "socks5://user:secret@127.0.0.1:1080" {
		t.Errorf("upstream fallback = %q", got)
	}
	if got := fetchProxy(config.Config{HTTPProxy: "http://10.0.0.2:8080"}, up); got != "http://10.0.0.2:8080" {
		t.Errorf("explicit http_proxy should win, got %q", got)
	}
	if got := fetchProxy(config.Config{HTTPProxy: "  "}, nil); got != "" {
		t.Errorf("blank http_proxy = %q, want empty", got)
	}
}

// The subscription endpoint is usually blocked in a filtered network, so
// `servers --upstream` must download it through that proxy, not directly.
func TestServersFetchesSubscriptionThroughUpstream(t *testing.T) {
	const body = "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#DE"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("subscription was fetched directly from %s", targetURL(r))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()

	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Store(true)
		if got, want := strings.TrimSuffix(targetURL(r), "/"), strings.TrimSuffix(target.URL, "/"); got != want {
			t.Errorf("proxy target = %q, want %q", got, want)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer proxy.Close()

	dir := t.TempDir()
	cfg := fmt.Sprintf(`{"subscription_url":%q,"backup_url":"","cache_ttl_minutes":30}`, target.URL)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEEPN_HOME", dir)
	t.Setenv("VEEPN_SUB", "")
	t.Setenv("VEEPN_HTTP_PROXY", "")
	t.Setenv("VEEPN_UPSTREAM", "")

	if code := cmdServers([]string{"--json", "--refresh", "--upstream", proxy.URL}); code != 0 {
		t.Fatalf("cmdServers exit code = %d, want 0", code)
	}
	if !proxied.Load() {
		t.Fatal("subscription was not downloaded through the upstream proxy")
	}
}

func targetURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	return "http://" + r.Host + r.URL.Path
}
