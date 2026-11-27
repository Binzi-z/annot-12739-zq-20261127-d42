package store_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"example.invalid/local-fixture/internal/endorsement"
	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/store"
)

func testKeyring(t *testing.T) *endorsement.Keyring {
	t.Helper()
	kr := endorsement.NewKeyring(
		[]byte("policy-key-0000000000000000000001"),
		[]byte("event-v1-key-00000000000000000001"),
	)
	if err := kr.AddVersion(2, []byte("event-v2-key-00000000000000000002")); err != nil {
		t.Fatal(err)
	}
	return kr
}

func sign(t *testing.T, kr *endorsement.Keyring, e event.Event) string {
	t.Helper()
	sig, err := kr.SignEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func mustOpen(t *testing.T, dir string, kr *endorsement.Keyring, opts store.Options) *store.Store {
	t.Helper()
	s, err := store.Open(dir, kr, opts)
	if err != nil {
		t.Fatalf("打开 store: %v", err)
	}
	return s
}

// hmacHex 供测试构造“真实但错误版本”的签名。
func hmacHex(key, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func ev(alert, digest string, prio int, source string, endorsementV int, watermark int64) event.Event {
	return event.Event{
		AlertID: alert, Digest: digest, Priority: prio, Source: source,
		Endorsement: endorsementV, ReceivedAt: watermark,
	}
}
