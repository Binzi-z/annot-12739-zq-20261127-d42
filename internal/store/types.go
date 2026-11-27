// Package store 是持久化索引核心：每个采集进程一个仅追加分区日志，
// 控制日志保存撤回记录，代清单以“临时文件 + fsync + 原子改名 + 目录屏障”发布。
//
// 目录布局：
//
//	<dir>/write.lock                  写端跨进程排他锁
//	<dir>/keyring.json                版本化签注密钥（离线 ACL 保护）
//	<dir>/part-<partition>.log        采集分区仅追加记录日志（哈希链）
//	<dir>/control.log                 撤回控制日志（独立策略签名）
//	<dir>/gen-<n>.json                代清单（不可变）
//	<dir>/gen-<n>.json.tmp            发布中的临时清单（崩溃残留即作废）
//	<dir>/receipts/gen-<n>.rcpt       代回执（晚于清单发布）
//	<dir>/CURRENT                     当前代指针（最后一步原子改名）
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"example.invalid/local-fixture/internal/event"
)

// 记录类型（分区日志）。
const (
	RecEvent      uint32 = 1 // 已接收事件信封
	RecQuarantine uint32 = 2 // 签名无效事件隔离
)

// 记录类型（控制日志）。
const (
	RecRevocation uint32 = 1 // 签注撤回
	RecRollback   uint32 = 2 // 分区局部回滚标签
)

// Envelope 是分区日志中的事件记录；顺序号即日志 Seq。
type Envelope struct {
	LogSeq    uint64      `json:"log_seq"`
	Partition string      `json:"partition"`
	Event     event.Event `json:"event"`
	Signature string      `json:"signature"` // 采集侧版本化 HMAC（十六进制）
	Valid     bool        `json:"valid"`     // 写入时的签名校验结论
}

// LeafData 是进入分区 Merkle 树的规范叶子内容。
func (env Envelope) LeafData() []byte {
	return env.Event.Canonical()
}

// LeafHash 是叶子哈希（带 Merkle 域分隔）。
func (env Envelope) LeafHash() []byte {
	return leafHashOf(env.LeafData())
}

// Revocation 是控制日志中的签注撤回记录。
// 撤回某个 (AlertID, Endorsement) 后，原始事件记录仍完整保留在分区日志中：
// 已承诺的原始前缀不可丢弃，只是该事件不再具备代表资格。
type Revocation struct {
	ControlSeq  uint64 `json:"control_seq"`
	AlertID     string `json:"alert_id"`
	Endorsement int    `json:"endorsement"`
	Reason      string `json:"reason"`
	IssuedAt    int64  `json:"issued_at"`
	Signature   string `json:"signature"` // 策略密钥 HMAC，见 Canonical
}

// Canonical 是撤回记录的规范签名输入。
func (r Revocation) Canonical() []byte {
	return []byte(`{"alert_id":` + jsonString(r.AlertID) +
		`,"endorsement":` + itoa(r.Endorsement) +
		`,"issued_at":` + itoa64(r.IssuedAt) +
		`,"reason":` + jsonString(r.Reason) + `}`)
}

// Rollback 是控制日志中的分区局部回滚标签。
// 被回滚的是分区树的一个后缀（LogSeq >= ToSeq 的记录不再入树），
// 原始记录在分区日志中一字不删——全量事实仍可独立重放。
type Rollback struct {
	ControlSeq uint64 `json:"control_seq"`
	Partition  string `json:"partition"`
	// ToSeq 是回滚水位（排他）：日志序 >= ToSeq 的记录被剔出代树。
	ToSeq     uint64 `json:"to_seq"`
	Reason    string `json:"reason"`
	IssuedAt  int64  `json:"issued_at"`
	Signature string `json:"signature"`
}

// Canonical 是回滚记录的规范签名输入。
func (r Rollback) Canonical() []byte {
	return []byte(`{"partition":` + jsonString(r.Partition) +
		`,"to_seq":` + strconv.FormatUint(r.ToSeq, 10) +
		`,"issued_at":` + itoa64(r.IssuedAt) +
		`,"reason":` + jsonString(r.Reason) + `}`)
}

// RootEntry 是根上保留的最少代表事件。
type RootEntry struct {
	AlertID   string      `json:"alert_id"`
	Priority  int         `json:"priority"`
	Watermark int64       `json:"watermark"`
	Partition string      `json:"partition"`
	LogSeq    uint64      `json:"log_seq"`
	LeafIndex int         `json:"leaf_index"`
	Event     event.Event `json:"event"`
	Signature string      `json:"signature"`
	LeafHash  string      `json:"leaf_hash_hex"`
}

// FoldedEntry 是被折叠进某个根的告警。高优折叠项带完整包含证明，
// 任何读端都能脱离写端独立复验其来源。
type FoldedEntry struct {
	AlertID        string       `json:"alert_id"`
	Priority       int          `json:"priority"`
	Partition      string       `json:"partition"`
	LogSeq         uint64       `json:"log_seq"`
	LeafIndex      int          `json:"leaf_index"`
	Event          *event.Event `json:"event,omitempty"` // 低优折叠可只留哈希
	Signature      string       `json:"signature,omitempty"`
	LeafHash       string       `json:"leaf_hash_hex"`
	InclusionProof []ProofStep  `json:"inclusion_proof,omitempty"` // 高优折叠的最少独立复验证书
	FoldedUnder    string       `json:"folded_under"`
	Revoked        bool         `json:"revoked,omitempty"`
}

// ProofStep 是落盘版 Merkle 证明步。
type ProofStep struct {
	HashHex     string `json:"hash_hex"`
	SiblingLeft bool   `json:"sibling_left"`
}

// Conflict 是一对同号异摘要且签名均真实的冲突；最早一对由写端裁定。
type Conflict struct {
	AlertID      string      `json:"alert_id"`
	First        RootEntry   `json:"first"`
	Second       RootEntry   `json:"second"`
	FirstDigest  string      `json:"first_digest"`
	SecondDigest string      `json:"second_digest"`
	DetectedAt   int64       `json:"detected_at"`
	Certificate  []ProofStep `json:"certificate"` // 指向较早事件的最少证书：包含证明
}

// PartitionTree 是清单中一个分区的树承诺与成员定位信息。
type PartitionTree struct {
	Partition string   `json:"partition"`
	Size      int      `json:"size"`
	RootHex   string   `json:"root_hex"`
	LeafSeq   []uint64 `json:"leaf_seq"` // 树叶子下标 -> 分区日志 Seq（证明定位用）
}

// Manifest 是不可变的代清单。
type Manifest struct {
	Generation  int   `json:"generation"`
	PublishedAt int64 `json:"published_at"`
	// HighPriorityThreshold 是发布时生效的高优阈值，读端据此判定折叠证书是否齐备。
	HighPriorityThreshold int `json:"high_priority_threshold"`
	// 分区树承诺：每个采集进程分区的大小、根与定位表。
	Partitions []PartitionTree `json:"partitions"`
	// 根：最少代表事件集合（每个同号摘要组恰一个代表）。
	Roots []RootEntry `json:"roots"`
	// 被折叠告警（高优折叠带完整证书）。
	Folded []FoldedEntry `json:"folded"`
	// 最早已证冲突（按检测顺序，首个即“最早已证冲突”）。
	Conflicts []Conflict `json:"conflicts"`
	// 被隔离（签名无效）事件定位。
	Quarantined []EnvelopeRef `json:"quarantined"`
	// 已撤回但保留的原始前缀定位。
	RevokedRefs []RevokedRef `json:"revoked_refs"`
	// 本代生效的分区局部回滚（仅影响点名分区，无关分区根保持不变）。
	Rollbacks []RollbackRef `json:"rollbacks,omitempty"`
	// 控制日志水位与链尾，撤回前缀可独立复验。
	ControlSize int    `json:"control_size"`
	ControlTail string `json:"control_tail_hex"`
	// 回执（发布后单独写入；为空表示“合并完成而回执未写”）。
	Receipt *Receipt `json:"receipt,omitempty"`
}

// EnvelopeRef 定位分区日志中的一条记录。
type EnvelopeRef struct {
	Partition string `json:"partition"`
	LogSeq    uint64 `json:"log_seq"`
	LeafIndex int    `json:"leaf_index"`
	Reason    string `json:"reason,omitempty"`
}

// RevokedRef 记录被撤回事件：原始前缀保留位置 + 对应撤回控制序号。
type RevokedRef struct {
	AlertID     string `json:"alert_id"`
	Endorsement int    `json:"endorsement"`
	Partition   string `json:"partition"`
	LogSeq      uint64 `json:"log_seq"`
	ControlSeq  uint64 `json:"control_seq"`
}

// RollbackRef 是清单中的回滚事实：分区、回滚前后树大小与控制记录定位。
type RollbackRef struct {
	Partition  string `json:"partition"`
	FromSize   int    `json:"from_size"`
	ToSize     int    `json:"to_size"`
	ToSeq      uint64 `json:"to_seq"`
	ControlSeq uint64 `json:"control_seq"`
}

// Receipt 是代回执；晚于清单本身落盘，缺失时读端只承认上一代。
type Receipt struct {
	Generation  int    `json:"generation"`
	ManifestHex string `json:"manifest_hash_hex"`
	IssuedAt    int64  `json:"issued_at"`
	Signature   string `json:"signature"` // 策略密钥对清单哈希的 HMAC
}

// Digest 计算清单规范哈希（确定性 JSON）。
func (m Manifest) Digest() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		panic(err) // 纯数据结构，Marshal 不应失败
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// DigestHex 返回清单哈希十六进制。
func (m Manifest) DigestHex() string { return hex.EncodeToString(m.Digest()) }
