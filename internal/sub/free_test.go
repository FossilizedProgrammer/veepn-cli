package sub

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func sealFreePassword(t *testing.T, plain string) string {
	t.Helper()
	key := sha256.Sum256([]byte(freePasswordKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...))
}

func TestDecryptFreePassword(t *testing.T) {
	blob := sealFreePassword(t, "s3cret-pass")
	got, ok := decryptFreePassword(blob)
	if !ok || got != "s3cret-pass" {
		t.Fatalf("decrypt = %q, %v", got, ok)
	}
	for _, plain := range []string{"plain-password", "", "not-base64!!"} {
		if got, ok := decryptFreePassword(plain); ok {
			t.Fatalf("%q should not decrypt, got %q", plain, got)
		}
	}
}

// TestParseSSLineFreeLink parses a link shaped like the built-in free
// subscription: the password is an encrypted blob, not plaintext.
func TestParseSSLineFreeLink(t *testing.T) {
	blob := sealFreePassword(t, "hello-world")
	cred := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:" + blob))
	line := "ss://" + cred + "@195.154.171.236:990#%F0%9F%87%AB%F0%9F%87%B7"
	s := ParseSSLine(line)
	if s == nil {
		t.Fatal("link not parsed")
	}
	if s.Method != "chacha20-ietf-poly1305" || s.Password != "hello-world" {
		t.Fatalf("got method=%q password=%q", s.Method, s.Password)
	}
	if s.IP != "195.154.171.236" || s.Port != 990 || s.Flag != "🇫🇷" {
		t.Fatalf("got ip=%q port=%d flag=%q", s.IP, s.Port, s.Flag)
	}
}

// TestParseVmessBlobMixed keeps every supported server when the backup
// subscription serves a mixed list instead of vmess-only.
func TestParseVmessBlobMixed(t *testing.T) {
	cred := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	ssLine := "ss://" + cred + "@1.2.3.4:8388#DE"
	vmessJSON := `{"ps":"NL","add":"5.6.7.8","port":443,"id":"11111111-1111-1111-1111-111111111111","aid":0,"net":"ws","type":"none","host":"a.example","path":"/ws","tls":"tls"}`
	vmessLine := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(vmessJSON))
	plain := vmessLine + "\n" + ssLine + "\n" +
		"hysteria2://pw@9.9.9.9:443?sni=x#unsupported\n"

	for name, blob := range map[string]string{
		"base64":    base64.StdEncoding.EncodeToString([]byte(plain)),
		"plaintext": plain,
	} {
		list := ParseVmessBlob(blob)
		if len(list) != 2 {
			t.Fatalf("%s: got %d servers, want 2 (%+v)", name, len(list), list)
		}
		protos := map[string]bool{}
		for _, s := range list {
			protos[s.Proto] = true
		}
		if !protos["ss"] || !protos["vmess"] {
			t.Fatalf("%s: protos = %v, want ss and vmess", name, protos)
		}
	}
}
