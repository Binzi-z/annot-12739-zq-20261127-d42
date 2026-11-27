// Package endorsement 实现版本化 HMAC 签注与签注撤回。
//
// 离线设备上没有公钥基础设施，采用 HMAC-SHA256：密钥只存在于离线安全值班主机。
// 事件由采集进程持有的版本化密钥签注；撤回记录由独立的策略密钥签注，
// 因此撤回某个事件签注版本不影响撤回记录自身的可验证性。
package endorsement

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"example.invalid/local-fixture/internal/event"
)

// Keyring 保存各签注代次的对称密钥与撤回策略密钥。
type Keyring struct {
	// Policy 用于签注撤回记录，与事件签注密钥隔离。
	Policy []byte `json:"-"`
	// Keys 为签注代次 -> 密钥。撤回后代次条目保留，验证历史事件仍需要它。
	Keys map[int][]byte `json:"-"`
}

// keyringFile 是落盘格式（离线主机，依赖文件 ACL 保护）。
type keyringFile struct {
	PolicyHex string            `json:"policy_hex"`
	KeysHex   map[string]string `json:"keys_hex"`
}

// NewKeyring 创建仅含策略密钥与初始事件签注密钥（代次 1）的钥匙环。
func NewKeyring(policy, initial []byte) *Keyring {
	return &Keyring{
		Policy: append([]byte(nil), policy...),
		Keys:   map[int][]byte{1: append([]byte(nil), initial...)},
	}
}

// LoadKeyring 从 JSON 文件读取钥匙环。
func LoadKeyring(path string) (*Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f keyringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("keyring 解析失败: %w", err)
	}
	policy, err := hex.DecodeString(f.PolicyHex)
	if err != nil {
		return nil, fmt.Errorf("policy key: %w", err)
	}
	kr := &Keyring{Policy: policy, Keys: make(map[int][]byte, len(f.KeysHex))}
	for ver, hx := range f.KeysHex {
		var v int
		if _, err := fmt.Sscanf(ver, "%d", &v); err != nil {
			return nil, fmt.Errorf("keyring 代次 %q: %w", ver, err)
		}
		key, err := hex.DecodeString(hx)
		if err != nil {
			return nil, fmt.Errorf("keyring 密钥 %d: %w", v, err)
		}
		kr.Keys[v] = key
	}
	return kr, nil
}

// Save 以确定性 JSON 写钥匙环（先临时文件后原子改名）。
func (k *Keyring) Save(path string) error {
	f := keyringFile{PolicyHex: hex.EncodeToString(k.Policy), KeysHex: map[string]string{}}
	versions := make([]int, 0, len(k.Keys))
	for v := range k.Keys {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	for _, v := range versions {
		f.KeysHex[fmt.Sprintf("%d", v)] = hex.EncodeToString(k.Keys[v])
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddVersion 增加一个签注代次密钥。
func (k *Keyring) AddVersion(version int, secret []byte) error {
	if version <= 0 {
		return fmt.Errorf("签注代次必须为正: %d", version)
	}
	if _, exists := k.Keys[version]; exists {
		return fmt.Errorf("签注代次已存在: %d", version)
	}
	k.Keys[version] = append([]byte(nil), secret...)
	return nil
}

// SignEvent 用指定代次密钥为事件规范字节计算 HMAC，返回十六进制签名。
func (k *Keyring) SignEvent(e event.Event) (string, error) {
	key, ok := k.Keys[e.Endorsement]
	if !ok {
		return "", fmt.Errorf("未知签注代次: %d", e.Endorsement)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(e.Canonical())
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyEvent 校验事件签名是否由其签注代次密钥真实签发。
// 注意：本函数只验证“真实签名”，是否已撤回由索引层结合撤回表判断。
func (k *Keyring) VerifyEvent(e event.Event, sigHex string) error {
	key, ok := k.Keys[e.Endorsement]
	if !ok {
		return fmt.Errorf("未知签注代次: %d", e.Endorsement)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("签名不是十六进制: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(e.Canonical())
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return fmt.Errorf("事件 %s 的签注签名无效", e.AlertID)
	}
	return nil
}

// SignRevocation 用策略密钥签注一条撤回记录的规范字节。
func (k *Keyring) SignRevocation(canonical []byte) string {
	mac := hmac.New(sha256.New, k.Policy)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRevocation 校验撤回记录的策略签名。
func (k *Keyring) VerifyRevocation(canonical []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("撤回签名不是十六进制: %w", err)
	}
	mac := hmac.New(sha256.New, k.Policy)
	mac.Write(canonical)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return fmt.Errorf("撤回记录策略签名无效")
	}
	return nil
}
