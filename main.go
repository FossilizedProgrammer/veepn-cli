// Command veepn is the desktop (proxy-only) counterpart of the
// VeePN Android app: it fetches the same subscriptions, parses
// the same ss:// / vmess:// servers, pings them, and runs the
// selected one behind a local SOCKS5 + HTTP proxy. No VPN/TUN is
// used — only a local proxy, as requested.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"

	"veepn/internal/config"
	"veepn/internal/engine"
	"veepn/internal/probe"
	"veepn/internal/sub"
	"veepn/internal/upstream"
)

const version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "servers":
		return cmdServers(args[1:])
	case "ping":
		return cmdPing(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "connect":
		return cmdConnect(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "stop":
		return cmdStop()
	case "ip":
		return cmdIP(args[1:])
	case "log":
		return cmdLog(args[1:])
	case "ports":
		return cmdPorts(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("VeePN CLI %s (sing-box %s)\n", version, singboxVersion())
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Print(`VeePN CLI — subscription proxy for the desktop (local proxy only, no VPN)

Usage:
  veepn servers [--refresh] [--json]
        List the servers. Out of the box this is the app's own free
        subscription (primary ss:// list, then the vmess backup;
        cached for 30 min and kept for offline use). Set your own
        with 'config set subscription_url' to use it instead.

  veepn ping [--json] [--timeout MS] [--parallel N] [--upstream URL]
        TCP latency sweep over all servers (20 at a time).

  veepn test [--json] [--timeout MS] [--parallel N] [--speed] [--top N] [--configured] [--upstream URL]
        Real usability test: opens a TLS request through every server
        (and, with --speed, downloads 512 KB) and ranks the working
        ones by latency/speed. This always tests the built-in free
        servers; add --configured to test your own subscription.

  veepn connect [SELECTOR] [--fastest] [--socks PORT] [--http PORT] [--no-watchdog] [--upstream URL]
        Start the local proxy on 127.0.0.1 (SOCKS5+HTTP on --socks,
        HTTP on --http). SELECTOR is a list index, ip:port, or part
        of a server name/flag. Without one, the fastest server is
        picked and the next ones are tried if it fails. With
        --upstream the servers are reached through another proxy
        (socks5://host:port or http://host:port, credentials allowed
        as socks5://user:pass@host:port); ping/test accept it too.

  veepn status [--json] [--check]
  veepn stop
  veepn ports [SOCKS] [HTTP]  Show or set the local ports (HTTP 0 = off)
  veepn ip [--direct]        Exit IP through the proxy (or real IP)
  veepn log [-n N]           Recent connect log
  veepn config [show|path] | config set KEY VALUE
  veepn version

Settings (~/.config/veepn/config.json):	  subscription_url, backup_url (empty = built-in free servers),
  socks_port, http_port, ping_timeout_ms, cache_ttl_minutes,
  log_level, watchdog, http_proxy, upstream (default chain proxy)
Env overrides: VEEPN_SUB, VEEPN_SUB_BACKUP, VEEPN_HTTP_PROXY,
  VEEPN_UPSTREAM, VEEPN_HOME
`)
}

// ---------- helpers ----------

func fetchOptions(cfg config.Config, force bool) sub.Options {
	ttl := time.Duration(cfg.CacheTTLMinutes) * time.Minute
	if force {
		ttl = 0
	}
	return sub.Options{
		URL:      cfg.SubscriptionURL,
		Backup:   cfg.BackupURL,
		Proxy:    cfg.HTTPProxy,
		CacheDir: config.Dir(),
		TTL:      ttl,
	}
}

func loadServers(cfg config.Config, force bool) ([]sub.Server, bool, error) {
	list, cached, err := sub.Fetch(fetchOptions(cfg, force))
	if len(list) == 0 {
		if err == nil {
			err = fmt.Errorf("no servers")
		}
		return nil, cached, err
	}
	return list, cached, err
}

// resolveUpstream picks the upstream for this run: the flag wins,
// then the saved setting (VEEPN_UPSTREAM overrides the config file).
func resolveUpstream(cfg config.Config, flagValue string) (*upstream.Upstream, error) {
	raw := strings.TrimSpace(flagValue)
	if raw == "" {
		raw = strings.TrimSpace(cfg.Upstream)
	}
	if raw == "" {
		return nil, nil
	}
	return upstream.Parse(raw)
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	return 1
}

// ---------- servers ----------

func cmdServers(args []string) int {
	fs := newFlagSet("servers")
	refresh := fs.Bool("refresh", false, "ignore the cache and fetch now")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := config.Load()
	list, cached, err := loadServers(cfg, *refresh)
	if err != nil {
		return fail("%v", err)
	}
	if cached && err != nil {
		fmt.Fprintf(os.Stderr, "note: showing the cached subscription (%v)\n", err)
	}
	if *asJSON {
		printJSON(list)
		return 0
	}
	fmt.Printf("%-3s %-3s %-4s %-26s %-26s %s\n", "#", "P", "FLAG", "NAME", "ENDPOINT", "DETAIL")
	for i, s := range list {
		name := serverLabel(s)
		detail := s.Method
		if s.Proto == "vmess" {
			detail = s.Network
			if s.TLS == "tls" {
				detail += "+tls"
			}
		}
		fmt.Printf("%-3d %-3s %-4s %-26s %-26s %s\n",
			i+1, strings.ToUpper(s.Proto[:1]), serverFlag(s), truncate(name, 24), s.Endpoint(), detail)
	}
	fmt.Printf("\n%d servers\n", len(list))
	return 0
}

// ---------- ping ----------

func cmdPing(args []string) int {
	fs := newFlagSet("ping")
	asJSON := fs.Bool("json", false, "print JSON")
	timeout := fs.Int("timeout", 0, "per-server timeout in ms (0 = setting)")
	parallel := fs.Int("parallel", 20, "parallel probes")
	upstreamFlag := fs.String("upstream", "", "reach the servers through this proxy (socks5:// or http://)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := config.Load()
	up, err := resolveUpstream(cfg, *upstreamFlag)
	if err != nil {
		return fail("%v", err)
	}
	list, _, err := loadServers(cfg, false)
	if err != nil {
		return fail("%v", err)
	}
	if *timeout <= 0 {
		*timeout = cfg.PingTimeoutMS
	}
	if up != nil {
		fmt.Fprintf(os.Stderr, "probing through %s\n", up)
	}
	results := probe.SweepVia(list, time.Duration(*timeout)*time.Millisecond, *parallel, up)
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i].MS, results[j].MS
		if a < 0 {
			return false
		}
		if b < 0 {
			return true
		}
		return a < b
	})
	if *asJSON {
		type row struct {
			Index int    `json:"index"`
			IP    string `json:"ip"`
			Port  int    `json:"port"`
			Proto string `json:"proto"`
			Flag  string `json:"flag"`
			Name  string `json:"name"`
			Ping  int64  `json:"ping_ms"`
		}
		rows := make([]row, 0, len(results))
		for i, r := range results {
			rows = append(rows, row{i + 1, r.Server.IP, r.Server.Port, r.Server.Proto, r.Server.Flag, r.Server.Name, r.MS})
		}
		printJSON(rows)
		return 0
	}
	alive := 0
	for i, r := range results {
		pingText := "TIMEOUT"
		if r.MS >= 0 {
			pingText = fmt.Sprintf("%d ms", r.MS)
			alive++
		}
		fmt.Printf("%-3d %-4s %-20s %-18s %s\n", i+1, serverFlag(r.Server), truncate(serverLabel(r.Server), 18), r.Server.Endpoint(), pingText)
	}
	fmt.Printf("\n%d/%d answered\n", alive, len(results))
	if alive == 0 {
		return 1
	}
	return 0
}

// ---------- real usability test ----------

func cmdTest(args []string) int {
	fs := newFlagSet("test")
	asJSON := fs.Bool("json", false, "print JSON")
	timeoutMS := fs.Int("timeout", 6000, "per-server timeout in ms")
	parallel := fs.Int("parallel", 24, "parallel checks")
	measureSpeed := fs.Bool("speed", false, "also download 512 KB per server and report KB/s")
	useConfigured := fs.Bool("configured", false, "test your configured subscription instead of the built-in free list")
	top := fs.Int("top", 0, "show only the N best servers (0 = all)")
	upstreamFlag := fs.String("upstream", "", "reach the servers through this proxy (socks5:// or http://)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := config.Load()
	up, err := resolveUpstream(cfg, *upstreamFlag)
	if err != nil {
		return fail("%v", err)
	}
	// Free servers only, unless the user explicitly asks for the
	// configured subscription.
	if !*useConfigured {
		cfg.SubscriptionURL = config.DefaultSubscriptionURL
		cfg.BackupURL = config.DefaultBackupURL
	}
	list, cached, err := loadServers(cfg, false)
	if err != nil {
		return fail("%v", err)
	}
	if cached && err != nil {
		fmt.Fprintf(os.Stderr, "note: using the cached list (%v)\n", err)
	}
	if up != nil {
		fmt.Fprintf(os.Stderr, "testing through %s\n", up)
	}
	timeout := time.Duration(*timeoutMS) * time.Millisecond
	source := "built-in free list"
	if *useConfigured {
		source = "configured subscription"
	}
	fmt.Fprintf(os.Stderr, "testing %d servers from the %s (real traffic through each one)…\n", len(list), source)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lastLine int
	results := probe.RealSweep(ctx, list, up, timeout, *parallel, *measureSpeed, func(done, total int) {
		if *asJSON {
			return
		}
		fmt.Fprintf(os.Stderr, "\r  checked %d/%d", done, total)
		lastLine = 1
	})
	if lastLine == 1 {
		fmt.Fprintln(os.Stderr)
	}

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.OK != b.OK {
			return a.OK
		}
		if *measureSpeed {
			if (a.SpeedKBps > 0) != (b.SpeedKBps > 0) {
				return a.SpeedKBps > 0
			}
			if a.SpeedKBps != b.SpeedKBps {
				return a.SpeedKBps > b.SpeedKBps
			}
		}
		return a.LatencyMS < b.LatencyMS
	})

	usable, fast, slow := 0, 0, 0
	for _, r := range results {
		if !r.OK {
			continue
		}
		usable++
		if r.LatencyMS <= 800 {
			fast++
		} else {
			slow++
		}
	}

	if *asJSON {
		type row struct {
			Rank      int     `json:"rank"`
			Index     int     `json:"index"`
			OK        bool    `json:"ok"`
			IP        string  `json:"ip"`
			Port      int     `json:"port"`
			Proto     string  `json:"proto"`
			Flag      string  `json:"flag"`
			Name      string  `json:"name"`
			LatencyMS int64   `json:"latency_ms"`
			SpeedKBps float64 `json:"speed_kbps,omitempty"`
			Status    int     `json:"status_code,omitempty"`
			Error     string  `json:"error,omitempty"`
		}
		rows := make([]row, 0, len(results))
		for i, r := range results {
			rows = append(rows, row{
				Rank: i + 1, Index: r.Index, OK: r.OK,
				IP: r.Server.IP, Port: r.Server.Port, Proto: r.Server.Proto,
				Flag: r.Server.Flag, Name: r.Server.Name,
				LatencyMS: r.LatencyMS, SpeedKBps: r.SpeedKBps,
				Status: r.StatusCode, Error: r.Err,
			})
		}
		printJSON(map[string]any{
			"total": len(list), "usable": usable, "fast": fast, "slow": slow,
			"results": rows,
		})
		if usable == 0 {
			return 1
		}
		return 0
	}

	shown := 0
	fmt.Printf("%-4s %-4s %-4s %-22s %-8s %-9s %s\n", "RANK", "IDX", "FLAG", "NAME", "LAT", "SPEED", "STATUS / ENDPOINT")
	for i, r := range results {
		if *top > 0 && shown >= *top {
			break
		}
		shown++
		lat := "-"
		if r.LatencyMS > 0 {
			lat = fmt.Sprintf("%d ms", r.LatencyMS)
		}
		speed := "-"
		if *measureSpeed {
			if r.SpeedKBps > 0 {
				speed = fmt.Sprintf("%.0f KB/s", r.SpeedKBps)
			} else {
				speed = "n/a"
			}
		}
		status := "✅ usable"
		switch {
		case !r.OK:
			status = "❌ " + shortErr(r.Err)
		case r.LatencyMS > 800:
			status = "🟡 slow"
		}
		fmt.Printf("%-4d %-4d %-4s %-22s %-8s %-9s %s  %s\n",
			i+1, r.Index, serverFlag(r.Server), truncate(serverLabel(r.Server), 20),
			lat, speed, status, r.Server.Endpoint())
	}
	fmt.Printf("\nusable: %d/%d (fast %d, slow %d)", usable, len(results), fast, slow)
	if *measureSpeed {
		fmt.Print(" — ranked by download speed, then latency")
	} else {
		fmt.Print(" — ranked by real latency (add --speed for KB/s)")
	}
	fmt.Println()
	if usable > 0 {
		best := -1
		for _, r := range results {
			if r.OK {
				best = r.Index
				break
			}
		}
		fmt.Printf("connect to the best one: veepn connect %d\n", best)
	}
	if usable == 0 {
		fmt.Fprintln(os.Stderr, "no server passed the real test")
		return 1
	}
	return 0
}

func shortErr(msg string) string {
	if msg == "" {
		return "unusable"
	}
	if len(msg) > 48 {
		msg = msg[:45] + "…"
	}
	return strings.NewReplacer("\n", " ").Replace(msg)
}

// ---------- connect ----------

func cmdConnect(args []string) int {
	fs := newFlagSet("connect")
	fastest := fs.Bool("fastest", false, "pick the fastest server (default when no selector)")
	socksPort := fs.Int("socks", 0, "local SOCKS5+HTTP port (0 = setting)")
	httpPort := fs.Int("http", -1, "local HTTP proxy port (-1 = setting, 0 = off)")
	noWatchdog := fs.Bool("no-watchdog", false, "disable the health watchdog")
	upstreamFlag := fs.String("upstream", "", "reach the server through this proxy (socks5:// or http://)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "usage: veepn connect [SELECTOR] [flags]") }
	// The flag package stops at the first positional argument;
	// loop so `connect 1 --socks 11080` works too.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	cfg := config.Load()
	up, err := resolveUpstream(cfg, *upstreamFlag)
	if err != nil {
		return fail("%v", err)
	}
	if *socksPort == 0 {
		*socksPort = cfg.SocksPort
	}
	if *httpPort == -1 {
		*httpPort = cfg.HTTPPort
	}
	if err := validatePorts(*socksPort, *httpPort); err != nil {
		return fail("%v", err)
	}
	if st := config.LoadState(); st.Alive() {
		return fail("already running (pid %d) on SOCKS 127.0.0.1:%d — run `veepn stop` first", st.PID, st.SocksPort)
	}

	list, _, err := loadServers(cfg, false)
	if err != nil {
		config.Log("connect: subscription failed: %v", err)
		return fail("%v", err)
	}

	selector := strings.TrimSpace(strings.Join(positional, " "))
	var candidates []sub.Server
	mode := "server"
	switch {
	case *fastest || selector == "":
		mode = "fastest"
		results := probe.SweepVia(list, time.Duration(cfg.PingTimeoutMS)*time.Millisecond, 20, up)
		sort.SliceStable(results, func(i, j int) bool {
			a, b := results[i].MS, results[j].MS
			if a < 0 {
				return false
			}
			if b < 0 {
				return true
			}
			return a < b
		})
		for _, r := range results {
			if r.MS >= 0 {
				candidates = append(candidates, r.Server)
			}
		}
		if len(candidates) == 0 {
			config.Log("connect: no server answered the ping sweep")
			if up != nil {
				return fail("no server answered through %s (try `veepn ping --upstream %s`)", up, up)
			}
			return fail("no server answered (try `veepn ping`)")
		}
		fmt.Fprintf(os.Stderr, "fastest: %d server(s) answered, starting with %s\n",
			len(candidates), candidates[0].Endpoint())
	default:
		s, err := selectServer(list, selector)
		if err != nil {
			return fail("%v", err)
		}
		candidates = []sub.Server{s}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess := &session{
		cfg:        cfg,
		socksPort:  *socksPort,
		httpPort:   *httpPort,
		watchdog:   cfg.Watchdog && !*noWatchdog,
		mode:       mode,
		candidates: candidates,
		upstream:   up,
	}
	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stopSignals
		fmt.Fprintln(os.Stderr, "\nstopping…")
		cancel()
	}()

	if err := sess.start(ctx); err != nil {
		config.Log("connect: %v", err)
		return fail("%v", err)
	}
	defer sess.shutdown()
	fmt.Printf("connected to %s\n", candidates[sess.current].Display())
	if up != nil {
		fmt.Printf("  via:    %s\n", up)
	}
	fmt.Printf("  SOCKS5: 127.0.0.1:%d\n", *socksPort)
	if *httpPort > 0 && *httpPort != *socksPort {
		fmt.Printf("  HTTP:   127.0.0.1:%d\n", *httpPort)
	}
	fmt.Printf("  exit IP: %s (%d ms)\n", sess.exitIP, sess.latencyMS)
	fmt.Println("  press Ctrl-C to disconnect")

	if sess.watchdog {
		go sess.runWatchdog(ctx)
	}
	<-ctx.Done()
	return 0
}

func selectServer(list []sub.Server, selector string) (sub.Server, error) {
	if n, err := strconv.Atoi(selector); err == nil {
		if n < 1 || n > len(list) {
			return sub.Server{}, fmt.Errorf("index %d out of range (1-%d)", n, len(list))
		}
		return list[n-1], nil
	}
	sel := strings.ToLower(selector)
	var exact []sub.Server
	var matches []sub.Server
	for _, s := range list {
		if s.Endpoint() == selector {
			exact = append(exact, s)
			continue
		}
		if strings.Contains(strings.ToLower(s.Name), sel) ||
			strings.Contains(strings.ToLower(s.Flag), sel) ||
			strings.Contains(strings.ToLower(s.IP), sel) {
			matches = append(matches, s)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return sub.Server{}, fmt.Errorf("no server matches %q", selector)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%q matches %d servers:\n", selector, len(matches)))
	for i, s := range matches {
		if i == 10 {
			b.WriteString("  …")
			break
		}
		b.WriteString("  " + s.Display() + "\n")
	}
	return sub.Server{}, fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
}

type session struct {
	cfg        config.Config
	socksPort  int
	httpPort   int
	watchdog   bool
	mode       string
	candidates []sub.Server
	upstream   *upstream.Upstream
	current    int
	instance   *box.Box
	exitIP     string
	latencyMS  int64
	mu         sync.Mutex
}

// start walks the candidate list until one server passes a real
// traffic check through the local proxy (exit IP), like the app's
// Fastest failover.
func (s *session) start(ctx context.Context) error {
	timeout := time.Duration(s.cfg.PingTimeoutMS) * time.Millisecond
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	for i := 0; i < len(s.candidates); i++ {
		srv := s.candidates[i]
		cfgJSON, err := engine.BuildConfig(engine.Options{
			Server:    srv,
			SocksPort: s.socksPort,
			HTTPPort:  s.httpPort,
			LogLevel:  s.cfg.LogLevel,
			Upstream:  s.upstream,
		})
		if err != nil {
			config.Log("connect %s: %v", srv.Endpoint(), err)
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", srv.Endpoint(), err)
			continue
		}
		instance, err := engine.Start(ctx, cfgJSON)
		if err != nil {
			config.Log("connect %s: %v", srv.Endpoint(), err)
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", srv.Endpoint(), err)
			continue
		}
		exitIP, err := probe.ExitIP(s.socksPort, timeout)
		if err != nil {
			config.Log("verify %s failed: %v", srv.Endpoint(), err)
			fmt.Fprintf(os.Stderr, "skip %s: tunnel check failed (%v)\n", srv.Endpoint(), err)
			_ = instance.Close()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		latency, _ := probe.Health(s.socksPort, timeout)
		s.mu.Lock()
		s.instance = instance
		s.current = i
		s.exitIP = exitIP
		s.latencyMS = latency.Milliseconds()
		s.mu.Unlock()

		via := "direct"
		if s.upstream != nil {
			via = s.upstream.String()
		}
		config.Log("connected %s via %s exit=%s latency=%dms mode=%s upstream=%s",
			srv.Proto, srv.Endpoint(), exitIP, latency.Milliseconds(), s.mode, via)
		_ = config.SaveState(config.State{
			PID:       os.Getpid(),
			StartedAt: time.Now().UnixMilli(),
			Server:    srv.Display(),
			Proto:     srv.Proto,
			IP:        srv.IP,
			Port:      srv.Port,
			SocksPort: s.socksPort,
			HTTPPort:  s.httpPort,
			ExitIP:    exitIP,
			LatencyMS: latency.Milliseconds(),
			Mode:      s.mode,
			Upstream:  upstreamDesc(s.upstream),
		})
		return nil
	}
	if s.mode == "fastest" {
		return fmt.Errorf("could not connect to any server (%d tried)", len(s.candidates))
	}
	return fmt.Errorf("could not connect to %s", s.candidates[0].Endpoint())
}

// runWatchdog checks real traffic every 30 s and reconnects after a
// 90 s stall (three failed checks) — the CLI counterpart of the
// app's watchdog + optimize.
func (s *session) runWatchdog(ctx context.Context) {
	const interval = 30 * time.Second
	const maxFails = 3
	fails := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_, err := probe.Health(s.socksPort, 12*time.Second)
		if err == nil {
			fails = 0
			continue
		}
		fails++
		config.Log("watchdog: check failed (%d/%d): %v", fails, maxFails, err)
		if fails < maxFails {
			continue
		}
		fails = 0
		s.reconnect(ctx)
	}
}

func (s *session) reconnect(ctx context.Context) {
	s.mu.Lock()
	old := s.instance
	from := s.current
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	fmt.Fprintln(os.Stderr, "tunnel stalled — reconnecting…")
	config.Log("watchdog: tunnel stalled, reconnecting")

	for offset := 1; offset <= len(s.candidates); offset++ {
		idx := (from + offset) % len(s.candidates)
		srv := s.candidates[idx]
		s.mu.Lock()
		s.current = idx
		s.instance = nil
		s.mu.Unlock()
		if err := s.startAt(ctx, idx); err != nil {
			config.Log("watchdog: %v", err)
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", srv.Endpoint(), err)
			continue
		}
		fmt.Fprintf(os.Stderr, "reconnected to %s (exit %s)\n", srv.Endpoint(), s.exitIP)
		return
	}
	fmt.Fprintln(os.Stderr, "reconnect failed: no server available")
	config.Log("watchdog: reconnect failed")
}

// startAt starts one candidate by index and verifies it.
func (s *session) startAt(ctx context.Context, idx int) error {
	srv := s.candidates[idx]
	cfgJSON, err := engine.BuildConfig(engine.Options{
		Server:    srv,
		SocksPort: s.socksPort,
		HTTPPort:  s.httpPort,
		LogLevel:  s.cfg.LogLevel,
		Upstream:  s.upstream,
	})
	if err != nil {
		return err
	}
	instance, err := engine.Start(ctx, cfgJSON)
	if err != nil {
		return err
	}
	timeout := 12 * time.Second
	exitIP, err := probe.ExitIP(s.socksPort, timeout)
	if err != nil {
		_ = instance.Close()
		return err
	}
	latency, _ := probe.Health(s.socksPort, timeout)
	s.mu.Lock()
	s.instance = instance
	s.exitIP = exitIP
	s.latencyMS = latency.Milliseconds()
	s.mu.Unlock()
	config.Log("reconnected %s exit=%s", srv.Endpoint(), exitIP)
	_ = config.SaveState(config.State{
		PID:       os.Getpid(),
		StartedAt: time.Now().UnixMilli(),
		Server:    srv.Display(),
		Proto:     srv.Proto,
		IP:        srv.IP,
		Port:      srv.Port,
		SocksPort: s.socksPort,
		HTTPPort:  s.httpPort,
		ExitIP:    exitIP,
		LatencyMS: latency.Milliseconds(),
		Mode:      s.mode,
		Upstream:  upstreamDesc(s.upstream),
	})
	return nil
}

// upstreamDesc is the credential-free form stored in the state file.
func upstreamDesc(up *upstream.Upstream) string {
	if up == nil {
		return ""
	}
	return up.String()
}

func (s *session) shutdown() {
	s.mu.Lock()
	inst := s.instance
	s.instance = nil
	s.mu.Unlock()
	if inst != nil {
		_ = inst.Close()
	}
	config.ClearState()
	config.Log("disconnected")
}

// ---------- status / stop ----------

func cmdStatus(args []string) int {
	fs := newFlagSet("status")
	asJSON := fs.Bool("json", false, "print JSON")
	check := fs.Bool("check", false, "also test the tunnel now")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st := config.LoadState()
	if st == nil || !st.Alive() {
		if st != nil {
			config.ClearState()
		}
		if *asJSON {
			printJSON(map[string]any{"running": false})
		} else {
			fmt.Println("not connected")
		}
		return 1
	}
	if *check {
		if d, err := probe.Health(st.SocksPort, 10*time.Second); err == nil {
			st.LatencyMS = d.Milliseconds()
		} else {
			st.LatencyMS = -1
		}
	}
	if *asJSON {
		printJSON(map[string]any{
			"running":    true,
			"pid":        st.PID,
			"uptime":     st.Uptime().String(),
			"server":     st.Server,
			"proto":      st.Proto,
			"exit_ip":    st.ExitIP,
			"latency_ms": st.LatencyMS,
			"socks":      fmt.Sprintf("127.0.0.1:%d", st.SocksPort),
			"http":       fmt.Sprintf("127.0.0.1:%d", st.HTTPPort),
			"mode":       st.Mode,
			"upstream":   st.Upstream,
		})
		return 0
	}
	fmt.Println("connected")
	fmt.Printf("  server:  %s\n", st.Server)
	if st.Upstream != "" {
		fmt.Printf("  via:     %s\n", st.Upstream)
	}
	fmt.Printf("  SOCKS5:  127.0.0.1:%d\n", st.SocksPort)
	if st.HTTPPort > 0 && st.HTTPPort != st.SocksPort {
		fmt.Printf("  HTTP:    127.0.0.1:%d\n", st.HTTPPort)
	}
	fmt.Printf("  exit IP: %s\n", st.ExitIP)
	if st.LatencyMS >= 0 {
		fmt.Printf("  latency: %d ms\n", st.LatencyMS)
	}
	fmt.Printf("  uptime:  %s (pid %d)\n", st.Uptime(), st.PID)
	return 0
}

func cmdStop() int {
	st := config.LoadState()
	if st == nil || !st.Alive() {
		config.ClearState()
		fmt.Println("not connected")
		return 0
	}
	_ = syscall.Kill(st.PID, syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !st.Alive() {
			config.ClearState()
			fmt.Println("stopped")
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(st.PID, syscall.SIGKILL)
	config.ClearState()
	fmt.Println("stopped (forced)")
	return 0
}

// ---------- ports ----------

// cmdPorts prints or saves the local proxy ports; `veepn ports 1081 8081`
// is the short form of two `config set` calls.
func cmdPorts(args []string) int {
	cfg := config.Load()
	if len(args) == 0 {
		fmt.Printf("SOCKS (and HTTP if unset): 127.0.0.1:%d\n", cfg.SocksPort)
		if cfg.HTTPPort <= 0 || cfg.HTTPPort == cfg.SocksPort {
			fmt.Println("HTTP: disabled (mixed inbound covers both protocols)")
		} else {
			fmt.Printf("HTTP: 127.0.0.1:%d\n", cfg.HTTPPort)
		}
		return 0
	}
	fs := newFlagSet("ports")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	socks := cfg.SocksPort
	http := cfg.HTTPPort
	if len(rest) > 2 {
		return fail("usage: veepn ports [SOCKS] [HTTP]")
	}
	if len(rest) >= 1 {
		n, err := strconv.Atoi(rest[0])
		if err != nil {
			return fail("invalid SOCKS port %q", rest[0])
		}
		socks = n
	}
	if len(rest) == 2 {
		n, err := strconv.Atoi(rest[1])
		if err != nil {
			return fail("invalid HTTP port %q", rest[1])
		}
		http = n
	}
	if err := validatePorts(socks, http); err != nil {
		return fail("%v", err)
	}
	cfg.SocksPort = socks
	cfg.HTTPPort = http
	if err := cfg.Save(); err != nil {
		return fail("%v", err)
	}
	fmt.Printf("saved: SOCKS 127.0.0.1:%d", socks)
	if http <= 0 || http == socks {
		fmt.Println(", HTTP off")
	} else {
		fmt.Printf(", HTTP 127.0.0.1:%d\n", http)
	}
	fmt.Println("takes effect on the next `veepn connect`")
	return 0
}

func validatePorts(socks, http int) error {
	if socks < 1 || socks > 65535 {
		return fmt.Errorf("SOCKS port must be 1-65535 (got %d)", socks)
	}
	if http < 0 || http > 65535 {
		return fmt.Errorf("HTTP port must be 0-65535, 0 = off (got %d)", http)
	}
	// Equal ports are fine: the mixed listener serves SOCKS and
	// HTTP on the same port, so no separate HTTP inbound is made.
	return nil
}

// ---------- ip / log / config ----------

func cmdIP(args []string) int {
	fs := newFlagSet("ip")
	direct := fs.Bool("direct", false, "fetch the real IP, not through the proxy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *direct {
		ip, err := directIP()
		if err != nil {
			return fail("%v", err)
		}
		fmt.Println(ip)
		return 0
	}
	st := config.LoadState()
	if st == nil || !st.Alive() {
		return fail("not connected — run `veepn connect` (or use --direct)")
	}
	ip, err := probe.ExitIP(st.SocksPort, 15*time.Second)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Println(ip)
	return 0
}

func directIP() (string, error) {
	cfg := config.Load()
	client := newDirectClient(cfg)
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || v.IP == "" {
		return "", fmt.Errorf("unexpected ipify response")
	}
	return v.IP, nil
}

func cmdLog(args []string) int {
	fs := newFlagSet("log")
	n := fs.Int("n", 40, "number of lines")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(config.LogPath())
	if err != nil {
		fmt.Println("no connect log yet")
		return 0
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	start := len(lines) - *n
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:] {
		fmt.Println(l)
	}
	return 0
}

func cmdConfig(args []string) int {
	cfg := config.Load()
	if len(args) == 0 || args[0] == "show" {
		raw, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(raw))
		return 0
	}
	switch args[0] {
	case "path":
		fmt.Println(config.Dir())
		return 0
	case "set":
		if len(args) < 3 {
			return fail("usage: veepn config set KEY VALUE")
		}
		if err := cfg.Set(args[1], strings.Join(args[2:], " ")); err != nil {
			return fail("%v", err)
		}
		if err := cfg.Save(); err != nil {
			return fail("%v", err)
		}
		fmt.Printf("%s = %s\n", args[1], strings.Join(args[2:], " "))
		return 0
	default:
		return fail("unknown config command %q (show|path|set)", args[0])
	}
}

// ---------- small utilities ----------

// serverLabel is the human label; for ss:// links the fragment is
// the whole name (the app keeps it in the flag field).
func serverLabel(s sub.Server) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Flag != "" {
		return s.Flag
	}
	return "-"
}

func serverFlag(s sub.Server) string {
	if f := sub.FlagFromName(s.Flag); f != "" {
		return f
	}
	if s.Proto == "ss" {
		return "🌐"
	}
	return "-"
}

func printJSON(v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("%v", err)
		return
	}
	fmt.Println(string(raw))
}

func truncate(s string, n int) string {
	if s == "" {
		return "-"
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
