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
