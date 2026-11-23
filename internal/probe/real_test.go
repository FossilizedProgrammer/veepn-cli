package probe

import "testing"

// TestProbeSSMethod keeps the direct Shadowsocks dial path limited to
// the methods shadowaead implements. Unknown names with a password make
// shadowaead.New return a nil constructor, which used to panic inside
// writeRequest; those must fall back to the sing-box engine instead.
func TestProbeSSMethod(t *testing.T) {
	for _, m := range []string{
		"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	} {
		if !probeSSMethod(m) {
			t.Errorf("%q should use the direct SS path", m)
		}
	}
	for _, m := range []string{
		"", "aes-256-cfb", "2022-blake3-aes-128-gcm", "none",
	} {
		if probeSSMethod(m) {
			t.Errorf("%q must go through the engine", m)
		}
	}
}
