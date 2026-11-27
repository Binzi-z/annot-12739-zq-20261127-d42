package endorsement

import (
	"path/filepath"
	"testing"

	"example.invalid/local-fixture/internal/event"
)

func TestSignVerifyAndRevocationKeyIsolation(t *testing.T) {
	kr := NewKeyring([]byte("policy-secret-32-bytes-0000000001"), []byte("event-v1-secret-32-bytes-00000001"))
	if err := kr.AddVersion(2, []byte("event-v2-secret-32-bytes-00000002")); err != nil {
		t.Fatal(err)
	}
	e := event.Event{AlertID: "A1", Digest: "d1", Priority: 5, Source: "ca", Endorsement: 1, ReceivedAt: 10}
	sig, err := kr.SignEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.VerifyEvent(e, sig); err != nil {
		t.Fatalf("真实签名复验失败: %v", err)
	}
	// 改一个字节即失效。
	e2 := e
	e2.Priority = 6
	if err := kr.VerifyEvent(e2, sig); err == nil {
		t.Fatal("被篡改事件未被发现")
	}
	// 未知代次无法签注。
	e3 := e
	e3.Endorsement = 9
	if _, err := kr.SignEvent(e3); err == nil {
		t.Fatal("未知代次竟可签注")
	}
	// 撤回记录用独立策略密钥；事件密钥签出的“撤回”必须无效。
	canonical := []byte(`{"alert_id":"A1"}`)
	good := kr.SignRevocation(canonical)
	if err := kr.VerifyRevocation(canonical, good); err != nil {
		t.Fatalf("策略签名复验: %v", err)
	}
	mac := hmacSHA1(kr.Keys[1], canonical)
	if err := kr.VerifyRevocation(canonical, mac); err == nil {
		t.Fatal("事件密钥竟通过了撤回策略签名校验")
	}
}

func TestKeyringRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr := NewKeyring([]byte("policy-policy-policy-policy-1234"), []byte("v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1v1"))
	if err := kr.AddVersion(3, []byte("v3v3v3v3v3v3v3v3v3v3v3v3v3v3v3v3")); err != nil {
		t.Fatal(err)
	}
	if err := kr.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	e := event.Event{AlertID: "A", Digest: "d", Priority: 1, Source: "s", Endorsement: 3, ReceivedAt: 1}
	sig, err := kr.SignEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.VerifyEvent(e, sig); err != nil {
		t.Fatalf("落盘后历史代次密钥丢失: %v", err)
	}
}
