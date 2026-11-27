// Package event 定义两个采集进程产生的合成告警事件，以及其规范编码与摘要。
//
// 摘要只对规范字节计算，因此 JSON 字段顺序、空白差异不会影响同号异摘要判定。
package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Event 是采集进程提交的一条合成告警。
type Event struct {
	// AlertID 是告警逻辑编号（题面中的“同号”）。同一 AlertID 可被多个采集进程重复上报。
	AlertID string `json:"alert_id"`
	// Digest 是采集侧对告警负载计算的内容摘要（题面中的“异摘要”）。
	Digest string `json:"digest"`
	// Priority 数值越大越优先；根代表事件按它取舍。
	Priority int `json:"priority"`
	// Source 标识来源采集进程（两个采集进程即两个来源），也是分区共享来源键。
	Source string `json:"source"`
	// Endorsement 标识签注代次（旧版签注可被撤回）。
	Endorsement int `json:"endorsement"`
	// ReceivedAt 是写端接收到该事件的逻辑单调水位（毫秒时间戳或序列号）。
	ReceivedAt int64 `json:"received_at"`
	// Payload 是不透明告警负载，仅用于展示，不参与折叠判定。
	Payload string `json:"payload,omitempty"`
}

// Canonical 返回确定性规范编码：字段固定顺序、紧凑 JSON、无空白。
func (e Event) Canonical() []byte {
	// 手工拼装而不是 json.Marshal，保证字段顺序与格式永远确定，
	// 不依赖结构体字段排序的隐式行为。
	return []byte(fmt.Sprintf(
		`{"alert_id":%s,"digest":%s,"priority":%d,"source":%s,"endorsement":%d,"received_at":%d,"payload":%s}`,
		jsonString(e.AlertID),
		jsonString(e.Digest),
		e.Priority,
		jsonString(e.Source),
		e.Endorsement,
		e.ReceivedAt,
		jsonString(e.Payload),
	))
}

// Hash 返回事件内容摘要（SHA-256 over canonical）。
func (e Event) Hash() []byte {
	sum := sha256.Sum256(e.Canonical())
	return sum[:]
}

// HashHex 便于日志与证书展示。
func (e Event) HashHex() string { return hex.EncodeToString(e.Hash()) }

// Validate 检查必填字段与基本取值范围。
func (e Event) Validate() error {
	if e.AlertID == "" {
		return fmt.Errorf("event: 空 alert_id")
	}
	if e.Digest == "" {
		return fmt.Errorf("event %s: 空 digest", e.AlertID)
	}
	if e.Source == "" {
		return fmt.Errorf("event %s: 空 source", e.AlertID)
	}
	if e.Endorsement < 0 {
		return fmt.Errorf("event %s: 签注代次为负", e.AlertID)
	}
	if e.ReceivedAt < 0 {
		return fmt.Errorf("event %s: 接收水位为负", e.AlertID)
	}
	return nil
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// 字符串 json.Marshal 仅在无效 UTF-8 等极端情形失败，转义后重试。
		b, _ = json.Marshal(string([]rune(s)))
	}
	return string(b)
}
