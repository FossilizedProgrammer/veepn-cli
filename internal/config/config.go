// Package config holds the CLI settings, the runtime state file and
// the connect log — the desktop counterparts of AppSettings,
// ConnectLog and the Android service state.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config is the persistent settings file (~/.config/veepn/config.json).
type Config struct {
	SubscriptionURL string `json:"subscription_url"`
	BackupURL       string `json:"backup_url"`
	SocksPort       int    `json:"socks_port"`
	HTTPPort        int    `json:"http_port"`
	PingTimeoutMS   int    `json:"ping_timeout_ms"`
	CacheTTLMinutes int    `json:"cache_ttl_minutes"`
	LogLevel        string `json:"log_level"`
	Watchdog        bool   `json:"watchdog"`
	HTTPProxy       string `json:"http_proxy"`
	// Upstream is an optional SOCKS5/HTTP proxy the servers are
	// reached through (socks5://host:port or http://host:port).
	Upstream string `json:"upstream"`
}

// State is written by `connect` while the proxy is running.
type State struct {
	PID       int    `json:"pid"`
	StartedAt int64  `json:"started_at"`
	Server    string `json:"server"` // credential-free label
	Proto     string `json:"proto"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	SocksPort int    `json:"socks_port"`
	HTTPPort  int    `json:"http_port"`
	ExitIP    string `json:"exit_ip"`
	LatencyMS int64  `json:"latency_ms"`
	Mode      string `json:"mode"`     // "fastest" | "server"
	Upstream  string `json:"upstream"` // credential-free upstream URL
}

const appDirName = "veepn"

// The official VeePN app ships with a built-in free subscription;
// its public source only has placeholders, but the official v2.5 APK
// uses these endpoints (primary ss:// list + vmess backup). They are
// the defaults here so the CLI works with no setup at all.
const (
	DefaultSubscriptionURL = "https://aloha-sub.kralali.workers.dev/?format=text"
	DefaultBackupURL       = "https://sub.shadowproxy66.workers.dev/sub/d41ecf64-93e5-49ed-866c-277cccac890f"
)

// Dir returns the config/state directory.
func Dir() string {
	if d := os.Getenv("VEEPN_HOME"); d != "" {
		return d
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "." + string(os.PathSeparator) + appDirName
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, appDirName)
}

// Load reads the settings, applying defaults. VEEPN_SUB and
// VEEPN_SUB_BACKUP override the subscription URLs.
func Load() Config {
	c := Config{
		SubscriptionURL: DefaultSubscriptionURL,
		BackupURL:       DefaultBackupURL,
		SocksPort:       1080,
		HTTPPort:        8080,
		PingTimeoutMS:   3000,
		CacheTTLMinutes: 30,
		LogLevel:        "warn",
		Watchdog:        true,
	}
	if raw, err := os.ReadFile(filepath.Join(Dir(), "config.json")); err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	if v := os.Getenv("VEEPN_SUB"); v != "" {
		c.SubscriptionURL = v
	}
	if v := os.Getenv("VEEPN_SUB_BACKUP"); v != "" {
		c.BackupURL = v
	}
	if v := os.Getenv("VEEPN_HTTP_PROXY"); v != "" {
		c.HTTPProxy = v
	}
	if v := os.Getenv("VEEPN_UPSTREAM"); v != "" {
		c.Upstream = v
	}
	// An empty URL (e.g. a config file written before the free
	// defaults existed) still means "use the built-in free servers".
	if c.SubscriptionURL == "" {
		c.SubscriptionURL = DefaultSubscriptionURL
	}
	if c.BackupURL == "" {
		c.BackupURL = DefaultBackupURL
	}
	if c.SocksPort <= 0 || c.SocksPort > 65535 {
		c.SocksPort = 1080
	}
	if c.HTTPPort < 0 || c.HTTPPort > 65535 {
		c.HTTPPort = 8080
	}
	if c.PingTimeoutMS <= 0 {
		c.PingTimeoutMS = 3000
	}
	if c.CacheTTLMinutes < 0 {
		c.CacheTTLMinutes = 30
	}
	if c.LogLevel == "" {
		c.LogLevel = "warn"
	}
	return c
}

// Save writes the settings (0600: it can hold subscription URLs
// that embed a token).
func (c Config) Save() error {
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := filepath.Join(dir, "config.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "config.json"))
}

// Set applies one `config set key value` pair.
func (c *Config) Set(key, value string) error {
	switch key {
	case "subscription_url", "sub":
		c.SubscriptionURL = value
	case "backup_url", "backup":
		c.BackupURL = value
	case "http_proxy":
		c.HTTPProxy = value
	case "upstream":
		c.Upstream = value
	case "log_level":
		c.LogLevel = value
	case "socks_port", "http_port", "ping_timeout_ms", "cache_ttl_minutes":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("invalid value %q for %s", value, key)
		}
		if key == "socks_port" && (n < 1 || n > 65535) {
			return fmt.Errorf("socks_port must be 1-65535 (got %d)", n)
		}
		if key == "ping_timeout_ms" && n < 1 {
			return fmt.Errorf("ping_timeout_ms must be at least 1")
		}
		switch key {
		case "socks_port":
			c.SocksPort = n
		case "http_port":
			c.HTTPPort = n
		case "ping_timeout_ms":
			c.PingTimeoutMS = n
		case "cache_ttl_minutes":
			c.CacheTTLMinutes = n
		}
	case "watchdog":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid value %q for watchdog (true/false)", value)
		}
		c.Watchdog = b
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

// LoadState returns the running-proxy state, or nil when none exists.
func LoadState() *State {
	raw, err := os.ReadFile(filepath.Join(Dir(), "state.json"))
	if err != nil {
		return nil
	}
	var s State
	if json.Unmarshal(raw, &s) != nil || s.PID <= 0 {
		return nil
	}
	return &s
}

// SaveState writes the state file atomically.
func SaveState(s State) error {
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "state.json"))
}

// ClearState removes the state file.
func ClearState() {
	_ = os.Remove(filepath.Join(Dir(), "state.json"))
}

// Alive reports whether the process recorded in the state is running.
func (s *State) Alive() bool {
	if s == nil || s.PID <= 0 {
		return false
	}
	return processRunning(s.PID)
}

// Uptime is the time since the proxy started.
func (s *State) Uptime() time.Duration {
	return time.Since(time.UnixMilli(s.StartedAt)).Round(time.Second)
}

// Log appends one credential-free line to connect.log.
func Log(format string, args ...any) {
	dir := Dir()
	_ = os.MkdirAll(dir, 0o700)
	f, err := os.OpenFile(filepath.Join(dir, "connect.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line := time.Now().Format("2006-01-02 15:04:05") + " " + fmt.Sprintf(format, args...) + "\n"
	_, _ = f.WriteString(line)
}

// LogPath is the connect log file.
func LogPath() string { return filepath.Join(Dir(), "connect.log") }
