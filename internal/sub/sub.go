// Package sub fetches and parses VeePN subscriptions.
//
// The primary subscription serves plain-text ss:// links (one per
// line); the backup one is a standard V2Ray subscription: one base64
// blob that decodes to vmess:// links. Both are parsed exactly like
// the Android app does (SubscriptionApi.java): malformed lines are
// skipped, loopback addresses and account-info names are dropped,
// and credentials are never logged.
package sub

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	userAgent  = "VeePN/1.9"
	timeout    = 15 * time.Second
	maxBodyLen = 8 << 20
)

// The built-in (free) subscription of the official app encrypts every
// Shadowsocks password with AES-256-GCM; the link carries
// base64url(iv || ciphertext || tag) as the password and the app
// decrypts it in AlohaApi.decryptPassword. A user's own subscription
// has plain passwords, which fail the GCM check and are kept as-is.
const freePasswordKey = "f3ABPyroJiTxnuP4R3GQOBo3j8KyK1Lb"

// decryptFreePassword returns the plaintext when s is a GCM blob from
// the free subscription.
func decryptFreePassword(s string) (string, bool) {
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(s)
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(normalized, "="))
	if err != nil || len(raw) < 12+16 {
		return "", false
	}
	// AlohaApi.getAesKey(): SecretKeySpec(sha256(SHA256), "AES").
	key := sha256.Sum256([]byte(freePasswordKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil || len(plain) == 0 {
		return "", false
	}
	return string(plain), true
}

// Server is one entry from a subscription. Password/UUID stay in
// memory and are written to the cache file only (mode 0600).
type Server struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	Flag     string `json:"flag,omitempty"`
	Proto    string `json:"proto"` // "ss", "vmess", "vless" or "trojan"
	Name     string `json:"name,omitempty"`

	// VMess/VLESS/Trojan.
	UUID       string `json:"uuid,omitempty"`
	AlterID    int    `json:"alter_id,omitempty"`
	Network    string `json:"network,omitempty"`
	Type       string `json:"type,omitempty"`
	Host       string `json:"host,omitempty"`
	Path       string `json:"path,omitempty"`
	TLS        string `json:"tls,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	// VLESS/Trojan extras from the share link query.
	Flow        string `json:"flow,omitempty"`
	PublicKey   string `json:"pbk,omitempty"`  // REALITY
	ShortID     string `json:"sid,omitempty"`  // REALITY
	Fingerprint string `json:"fp,omitempty"`   // uTLS
	ALPN        string `json:"alpn,omitempty"` // comma separated
	Insecure    bool   `json:"insecure,omitempty"`
}

// Display is the credential-free label used in tables and logs.
func (s Server) Display() string {
	name := s.Name
	if name == "" {
		name = s.Flag
	}
	if name == "" {
		name = "-"
	}
	return fmt.Sprintf("%s %-22s %-8s %s", protoShort(s.Proto), name, s.IP+":"+strconv.Itoa(s.Port), s.Method)
}

func protoShort(p string) string {
	switch p {
	case "vmess":
		return "VM"
	case "vless":
		return "VL"
	case "trojan":
		return "TR"
	default:
		return "SS"
	}
}

// Endpoint is the host:port the client connects to.
func (s Server) Endpoint() string { return s.IP + ":" + strconv.Itoa(s.Port) }

// CacheFormat is the on-disk shape, identical to the app's
// lastFetchForCache()/parseCacheJson() blob.
type CacheFormat struct {
	FetchedAt int64  `json:"fetchedAt"`
	Kind      string `json:"kind"` // "ss" | "mixed"
	Text      string `json:"text"`
}

// Options for a subscription fetch.
type Options struct {
	URL      string
	Backup   string
	Proxy    string // optional upstream proxy (http/https/socks5)
	CacheDir string
	TTL      time.Duration
}

// Fetch returns the server list. A fresh copy is fetched when the
// in-file cache is older than TTL; when both endpoints fail the
// cached list is returned (the app keeps the cached list too).
func Fetch(o Options) (servers []Server, fromCache bool, err error) {
	cachePath := filepath.Join(o.CacheDir, "cache.json")

	var cache *CacheFormat
	if raw, rerr := os.ReadFile(cachePath); rerr == nil {
		var c CacheFormat
		if json.Unmarshal(raw, &c) == nil && c.Text != "" {
			cache = &c
		}
	}

	if cache != nil && o.TTL > 0 && time.Since(time.UnixMilli(cache.FetchedAt)) < o.TTL {
		if list := ParseCache(cache); len(list) > 0 {
			return list, true, nil
		}
	}

	list, kind, raw, ferr := fetchFresh(o)
	if ferr == nil && len(list) > 0 {
		writeCache(cachePath, CacheFormat{
			FetchedAt: time.Now().UnixMilli(),
			Kind:      kind,
			Text:      raw,
		})
		return list, false, nil
	}

	if cache != nil {
		if list := ParseCache(cache); len(list) > 0 {
			return list, true, ferr
		}
	}
	if ferr == nil {
		ferr = errors.New("subscription returned no usable servers")
	}
	return nil, false, ferr
}

func writeCache(path string, c CacheFormat) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// ClearCache removes the cached subscription.
func ClearCache(dir string) error {
	err := os.Remove(filepath.Join(dir, "cache.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ParseCache turns a stored blob into servers.
func ParseCache(c *CacheFormat) []Server {
	if c == nil || c.Text == "" {
		return nil
	}
	if c.Kind == "vmess" {
		return ParseVmessBlob(c.Text)
	}
	var out []Server
	sc := bufio.NewScanner(strings.NewReader(c.Text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if s := ParseSSLine(strings.TrimSpace(sc.Text())); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

func fetchFresh(o Options) (list []Server, kind, raw string, err error) {
	var primaryErr error
	if strings.TrimSpace(o.URL) != "" {
		body, e := get(o, o.URL)
		if e == nil {
			list = ParseSSLines(body)
			if len(list) > 0 {
				return list, "ss", body, nil
			}
			primaryErr = errors.New("primary subscription had no parsable ss:// links")
		} else {
			primaryErr = fmt.Errorf("primary subscription: %w", e)
		}
	} else {
		primaryErr = errors.New("no subscription URL configured")
	}

	if strings.TrimSpace(o.Backup) != "" {
		body, e := get(o, o.Backup)
		if e == nil {
			list = ParseVmessBlob(body)
			if len(list) > 0 {
				return list, "vmess", body, nil
			}
			if primaryErr == nil {
				primaryErr = errors.New("backup subscription had no usable servers")
			}
		}
	}
	return nil, "", "", primaryErr
}

func client(o Options) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
	if p := strings.TrimSpace(o.Proxy); p != "" {
		if u, err := url.Parse(p); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

func get(o Options, endpoint string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")
	resp, err := client(o).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyLen))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ParseSSLines parses a plain-text ss:// list.
func ParseSSLines(text string) []Server {
	var out []Server
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if s := ParseSSLine(strings.TrimSpace(sc.Text())); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// ParseSSLine parses
// ss://base64url(method:password)@ip:port#urlencoded-flag
// (SIP002's plain method:password form is accepted too).
func ParseSSLine(line string) *Server {
	if !strings.HasPrefix(line, "ss://") {
		return nil
	}
	rest := strings.TrimPrefix(line, "ss://")

	flag := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		if f, err := url.PathUnescape(rest[i+1:]); err == nil {
			flag = f
		}
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 { // plugin/query params
		rest = rest[:i]
	}

	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return nil
	}
	userinfo := rest[:at]
	hostport := rest[at+1:]
	colon := strings.LastIndex(hostport, ":")
	if colon <= 0 {
		return nil
	}
	ip := strings.Trim(hostport[:colon], "[]")
	port, err := strconv.Atoi(hostport[colon+1:])
	if err != nil || ip == "" || port <= 0 || port > 65535 {
		return nil
	}

	cred := ""
	if decoded, ok := decodeBase64(userinfo); ok {
		cred = decoded
	} else if strings.Contains(userinfo, ":") {
		if unescaped, err := url.PathUnescape(userinfo); err == nil {
			cred = unescaped
		}
	}
	if cred == "" {
		return nil
	}
	sep := strings.Index(cred, ":")
	if sep <= 0 {
		return nil
	}
	method, password := cred[:sep], cred[sep+1:]
	if method == "" || password == "" {
		return nil
	}
	if plain, ok := decryptFreePassword(password); ok {
		password = plain
	}
	return &Server{Proto: "ss", IP: ip, Port: port, Method: method, Password: password, Flag: flag}
}

// ParseVmessBlob decodes a whole-body subscription and parses every
// supported link in it. The name is historical: the backup used to be
// vmess-only, but it now ships a mixed list (ss://, vmess://, and
// protocols this client does not run). Parsing just vmess dropped
// almost the whole list, which left the app with one dead server.
func ParseVmessBlob(blob string) []Server {
	decoded, ok := decodeBase64(strings.TrimSpace(blob))
	if !ok {
		// Some subscriptions serve the plain text directly.
		decoded = blob
	}
	var out []Server
	sc := bufio.NewScanner(strings.NewReader(decoded))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if s := ParseAnyLine(strings.TrimSpace(sc.Text())); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

// ParseAnyLine parses one subscription line of any scheme this client
// can run. Unsupported schemes are skipped instead of aborting.
func ParseAnyLine(line string) *Server {
	switch {
	case strings.HasPrefix(line, "ss://"):
		return ParseSSLine(line)
	case strings.HasPrefix(line, "vmess://"):
		return ParseVmessLine(line)
	case strings.HasPrefix(line, "vless://"):
		return ParseVlessLine(line)
	case strings.HasPrefix(line, "trojan://"):
		return ParseTrojanLine(line)
	default:
		return nil
	}
}

// ParseVlessLine parses a vless:// link (TCP/WS/gRPC, TLS or REALITY).
func ParseVlessLine(line string) *Server {
	u, err := url.Parse(line)
	if err != nil || u.Scheme != "vless" || u.Hostname() == "" {
		return nil
	}
	uuid := strings.TrimSpace(u.User.Username())
	if uuid == "" {
		return nil
	}
	s := shareLinkBase(u, "vless")
	if s == nil {
		return nil
	}
	s.UUID = uuid
	applyShareQuery(s, u.Query())
	if s.Name == "" {
		s.Name = "vless " + s.Endpoint()
	}
	return s
}

// ParseTrojanLine parses a trojan:// link.
func ParseTrojanLine(line string) *Server {
	u, err := url.Parse(line)
	if err != nil || u.Scheme != "trojan" || u.Hostname() == "" {
		return nil
	}
	password := strings.TrimSpace(u.User.Username())
	if password == "" {
		return nil
	}
	s := shareLinkBase(u, "trojan")
	if s == nil {
		return nil
	}
	s.Password = password
	applyShareQuery(s, u.Query())
	if s.TLS == "" {
		// Trojan is TLS by default unless the link says otherwise.
		s.TLS = "tls"
	}
	if s.Name == "" {
		s.Name = "trojan " + s.Endpoint()
	}
	return s
}

// shareLinkBase fills the fields shared by vless:// and trojan:// links.
func shareLinkBase(u *url.URL, proto string) *Server {
	host := u.Hostname()
	port := 443
	if raw := u.Port(); raw != "" {
		p, err := strconv.Atoi(raw)
		if err != nil {
			return nil
		}
		port = p
	}
	if port <= 0 || port > 65535 || IsLoopback(host) {
		return nil
	}
	name := strings.TrimSpace(u.Fragment)
	if IsInfoName(name) {
		return nil
	}
	s := &Server{Proto: proto, IP: host, Port: port, Name: name}
	if f := FlagFromName(name); f != "" {
		s.Flag = f
	} else {
		s.Flag = "\U0001F310"
	}
	return s
}

// applyShareQuery maps the V2Ray share-link query onto the outbound.
func applyShareQuery(s *Server, q url.Values) {
	if t := strings.ToLower(q.Get("type")); t != "" && t != "tcp" && t != "none" {
		s.Network = t
	} else {
		s.Network = "tcp"
	}
	s.Path = q.Get("path")
	s.Host = q.Get("host")
	s.Flow = q.Get("flow")
	s.ServerName = q.Get("sni")
	if s.ServerName == "" {
		s.ServerName = q.Get("peer")
	}
	s.PublicKey = q.Get("pbk")
	s.ShortID = q.Get("sid")
	s.Fingerprint = q.Get("fp")
	s.ALPN = q.Get("alpn")

	security := strings.ToLower(q.Get("security"))
	switch security {
	case "tls", "reality", "xtls":
		s.TLS = "tls"
	case "none", "":
		s.TLS = "none"
	default:
		s.TLS = "tls"
	}
	if s.TLS == "tls" && s.ServerName == "" {
		s.ServerName = s.IP
	}
	switch strings.ToLower(q.Get("insecure") + q.Get("allowinsecure")) {
	case "1", "true", "1true", "true1":
		s.Insecure = true
	}
}

// ParseVmessLine parses one vmess://base64url(JSON) link.
func ParseVmessLine(line string) *Server {
	if !strings.HasPrefix(line, "vmess://") {
		return nil
	}
	encoded := strings.TrimPrefix(line, "vmess://")
	decoded, ok := decodeBase64(encoded)
	if !ok {
		return nil
	}
	var j struct {
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		AID  any    `json:"aid"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(decoded)), &j) != nil {
		return nil
	}
	ip := strings.TrimSpace(j.Add)
	port := toInt(j.Port)
	uuid := strings.TrimSpace(j.ID)
	if ip == "" || port <= 0 || port > 65535 || uuid == "" {
		return nil
	}
	if IsLoopback(ip) || IsInfoName(j.PS) {
		return nil
	}
	network := j.Net
	if network == "" {
		network = "tcp"
	}
	tls := j.TLS
	if tls == "" {
		tls = "none"
	}
	s := &Server{
		Proto:      "vmess",
		IP:         ip,
		Port:       port,
		UUID:       uuid,
		AlterID:    toInt(j.AID),
		Network:    network,
		Type:       j.Type,
		Host:       j.Host,
		Path:       j.Path,
		TLS:        tls,
		Name:       j.PS,
		ServerName: ip,
	}
	if f := FlagFromName(j.PS); f != "" {
		s.Flag = f
	} else {
		s.Flag = "\U0001F310" // globe, like the app
	}
	if s.Host != "" {
		s.ServerName = s.Host
	}
	return s
}

// IsLoopback reports whether addr is an info entry (127/8, ::1,
// localhost) rather than a usable server.
func IsLoopback(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	if a == "" || a == "localhost" || a == "::1" || a == "[::1]" {
		return true
	}
	return strings.HasPrefix(a, "127.")
}

// IsInfoName reports account-status lines that are not servers.
func IsInfoName(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"status", "validity", "expire", "traffic", "active", "account", "remaining", "balance"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// FlagFromName extracts a regional-indicator pair (flag emoji).
func FlagFromName(name string) string {
	rs := []rune(name)
	for i := 0; i+1 < len(rs); i++ {
		if rs[i] >= 0x1F1E6 && rs[i] <= 0x1F1FF && rs[i+1] >= 0x1F1E6 && rs[i+1] <= 0x1F1FF {
			return string(rs[i : i+2])
		}
	}
	return ""
}

func toInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	}
	return 0
}

func decodeBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 1:
		return "", false
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(b), true
}
