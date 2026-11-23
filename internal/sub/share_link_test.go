package sub

import "testing"

func TestParseVlessLineReality(t *testing.T) {
	line := "vless://11111111-1111-1111-1111-111111111111@eu124.cdn77.icu:20038" +
		"?type=ws&headerType=none&security=reality&encryption=none&sni=eu124.cdn77.icu" +
		"&fp=firefox&pbk=EltWI8AOqkN8lMjRycweRRoFRah5hu6xiKtgBmQOdE8&sid=1ed13648" +
		"&path=%2Fws#%F0%9F%87%A6%F0%9F%87%AA"
	s := ParseAnyLine(line)
	if s == nil {
		t.Fatal("link not parsed")
	}
	if s.Proto != "vless" || s.IP != "eu124.cdn77.icu" || s.Port != 20038 {
		t.Fatalf("got proto=%q ip=%q port=%d", s.Proto, s.IP, s.Port)
	}
	if s.UUID != "11111111-1111-1111-1111-111111111111" ||
		s.TLS != "tls" || s.Network != "ws" || s.Path != "/ws" {
		t.Fatalf("got uuid=%q tls=%q network=%q path=%q", s.UUID, s.TLS, s.Network, s.Path)
	}
	if s.ServerName != "eu124.cdn77.icu" || s.Fingerprint != "firefox" ||
		s.PublicKey == "" || s.ShortID != "1ed13648" {
		t.Fatalf("got sni=%q fp=%q pbk=%q sid=%q", s.ServerName, s.Fingerprint, s.PublicKey, s.ShortID)
	}
	if s.Flag != "🇦🇪" {
		t.Fatalf("flag = %q", s.Flag)
	}
}

func TestParseTrojanLine(t *testing.T) {
	line := "trojan://p%40ss@64.118.130.152:443?type=tcp&security=tls&sni=nb1hk.hikigo.com#HK%20one"
	s := ParseAnyLine(line)
	if s == nil {
		t.Fatal("link not parsed")
	}
	if s.Proto != "trojan" || s.Password != "p@ss" || s.IP != "64.118.130.152" || s.Port != 443 {
		t.Fatalf("got proto=%q password=%q ip=%q port=%d", s.Proto, s.Password, s.IP, s.Port)
	}
	if s.TLS != "tls" || s.ServerName != "nb1hk.hikigo.com" || s.Network != "tcp" {
		t.Fatalf("got tls=%q sni=%q network=%q", s.TLS, s.ServerName, s.Network)
	}
	if s.Name != "HK one" {
		t.Fatalf("name = %q", s.Name)
	}
}

func TestUnsupportedShareLinkIgnored(t *testing.T) {
	if s := ParseAnyLine("hysteria2://pw@example.com:443?sni=x#HY"); s != nil {
		t.Fatalf("hysteria2 should be skipped, got %+v", s)
	}
}
