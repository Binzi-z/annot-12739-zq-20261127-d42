package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"example.invalid/local-fixture/internal/endorsement"
	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/lock"
	"example.invalid/local-fixture/internal/log"
)

// 崩溃屏障注入点（仅测试用）。
const (
	// CrashAfterManifestTemp：清单临时文件已 fsync、尚未原子改名。
	CrashAfterManifestTemp = "after-manifest-temp"
	// CrashAfterRenameBeforeReceipt：清单已改名落盘（合并完成），回执未写。
	CrashAfterRenameBeforeReceipt = "after-rename-before-receipt"
	// CrashAfterReceiptBeforeCurrent：回执已写，CURRENT 指针未翻转。
	CrashAfterReceiptBeforeCurrent = "after-receipt-before-current"
)

// ErrCrashInjected 表示在命名屏障处模拟崩溃。
var ErrCrashInjected = errors.New("store: 已在命名屏障处注入崩溃")

// Options 控制折叠策略。
type Options struct {
	// HighPriorityThreshold：达到该优先级的被折叠告警必须带完整独立复验证书。
	HighPriorityThreshold int
	// CrashPoint：命名崩溃注入点，空字符串表示不注入。
	CrashPoint string
}

// Store 是合并写端句柄：持有跨进程排他锁，管理全部分区与控制日志。
type Store struct {
	dir     string
	kr      *endorsement.Keyring
	lk      *lock.Lock
	opts    Options
	parts   map[string]*log.Log
	control *log.Log

	byPart    map[string][]Envelope
	revoked   map[revKey]Revocation
	rollbacks map[string]Rollback // 分区 -> 当前生效的最新回滚标签
	revs      []Revocation
	current   int
	repaired  []string // 本次打开完成的前向恢复动作
}

type revKey struct {
	alertID     string
	endorsement int
}

// Open 获得目录排他锁并重放全部持久化状态，同时完成未竟发布的前向恢复。
func Open(dir string, kr *endorsement.Keyring, opts Options) (*Store, error) {
	if opts.HighPriorityThreshold == 0 {
		opts.HighPriorityThreshold = 8
	}
	if err := os.MkdirAll(filepath.Join(dir, "receipts"), 0o700); err != nil {
		return nil, err
	}
	lk, err := lock.Acquire(filepath.Join(dir, "write.lock"))
	if err != nil {
		return nil, err
	}
	s := &Store{
		dir: dir, kr: kr, lk: lk, opts: opts,
		parts:     map[string]*log.Log{},
		byPart:    map[string][]Envelope{},
		revoked:   map[revKey]Revocation{},
		rollbacks: map[string]Rollback{},
	}
	if err := s.openLogs(); err != nil {
		_ = lk.Release()
		return nil, err
	}
	if err := s.replay(); err != nil {
		_ = lk.Release()
		return nil, err
	}
	if err := s.recoverPublishes(); err != nil {
		_ = lk.Release()
		return nil, err
	}
	return s, nil
}

// RepairedActions 返回本次打开执行的崩溃恢复动作（供测试与审计断言）。
func (s *Store) RepairedActions() []string { return append([]string(nil), s.repaired...) }

// CurrentGeneration 返回 CURRENT 指针指向的已提交代次（0 表示尚未发布）。
func (s *Store) CurrentGeneration() int { return s.current }

func (s *Store) partPath(partition string) string {
	return filepath.Join(s.dir, "part-"+sanitize(partition)+".log")
}

func (s *Store) controlPath() string { return filepath.Join(s.dir, "control.log") }

func sanitize(name string) string {
	r := strings.NewReplacer("..", "_", string(filepath.Separator), "_", "/", "_", "\\", "_")
	return r.Replace(name)
}

func (s *Store) openLogs() error {
	matches, err := filepath.Glob(filepath.Join(s.dir, "part-*.log"))
	if err != nil {
		return err
	}
	for _, m := range matches {
		partition := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "part-"), ".log")
		l, err := log.Open(m)
		if err != nil {
			return fmt.Errorf("分区 %s 日志: %w", partition, err)
		}
		s.parts[partition] = l
		s.byPart[partition] = nil
	}
	cl, err := log.Open(s.controlPath())
	if err != nil {
		return err
	}
	s.control = cl
	return nil
}

func (s *Store) ensurePartition(partition string) (*log.Log, error) {
	if l, ok := s.parts[partition]; ok {
		return l, nil
	}
	l, err := log.Open(s.partPath(partition))
	if err != nil {
		return nil, err
	}
	s.parts[partition] = l
	s.byPart[partition] = nil
	return l, nil
}

func (s *Store) replay() error {
	for partition, l := range s.parts {
		recs, err := log.ReadAll(l.Path())
		if err != nil {
			return fmt.Errorf("重放分区 %s: %w", partition, err)
		}
		for _, rec := range recs {
			var env Envelope
			if err := json.Unmarshal(rec.Body, &env); err != nil {
				return fmt.Errorf("分区 %s 记录 %d 损坏: %w", partition, rec.Seq, err)
			}
			if env.LogSeq != rec.Seq || env.Partition != partition {
				return fmt.Errorf("分区 %s 记录 %d 定位字段不一致", partition, rec.Seq)
			}
			s.byPart[partition] = append(s.byPart[partition], env)
		}
	}
	crecs, err := log.ReadAll(s.control.Path())
	if err != nil {
		return fmt.Errorf("重放控制日志: %w", err)
	}
	for _, rec := range crecs {
		switch rec.Type {
		case RecRevocation:
			var rev Revocation
			if err := json.Unmarshal(rec.Body, &rev); err != nil {
				return fmt.Errorf("控制记录 %d 损坏: %w", rec.Seq, err)
			}
			if rev.ControlSeq != rec.Seq {
				return fmt.Errorf("控制记录 %d 序号不一致", rec.Seq)
			}
			if err := s.kr.VerifyRevocation(rev.Canonical(), rev.Signature); err != nil {
				return fmt.Errorf("控制记录 %d 策略签名无效: %w", rec.Seq, err)
			}
			s.revs = append(s.revs, rev)
			s.revoked[revKey{rev.AlertID, rev.Endorsement}] = rev
		case RecRollback:
			var rb Rollback
			if err := json.Unmarshal(rec.Body, &rb); err != nil {
				return fmt.Errorf("回滚控制记录 %d 损坏: %w", rec.Seq, err)
			}
			if rb.ControlSeq != rec.Seq {
				return fmt.Errorf("回滚控制记录 %d 序号不一致", rec.Seq)
			}
			if err := s.kr.VerifyRevocation(rb.Canonical(), rb.Signature); err != nil {
				return fmt.Errorf("回滚控制记录 %d 策略签名无效: %w", rec.Seq, err)
			}
			s.rollbacks[rb.Partition] = rb
		default:
			return fmt.Errorf("控制记录 %d 未知类型 %d", rec.Seq, rec.Type)
		}
	}
	cur, err := os.ReadFile(filepath.Join(s.dir, "CURRENT"))
	if err != nil {
		if os.IsNotExist(err) {
			s.current = 0
			return nil
		}
		return err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(cur)), "%d", &n); err != nil {
		return fmt.Errorf("CURRENT 指针损坏: %w", err)
	}
	s.current = n
	return nil
}

// Ingest 接收一条采集事件：先验真实签名，再以屏障方式追加进分区日志。
// 签名无效不会被丢弃，而是以隔离记录留痕（仍在哈希链上）。
func (s *Store) Ingest(partition string, e event.Event, sigHex string) (*Envelope, error) {
	envs, err := s.IngestBatch(partition, []IngestItem{{Event: e, Signature: sigHex}})
	if err != nil {
		return nil, err
	}
	return &envs[0], nil
}

// IngestItem 是批量摄入的一条输入。
type IngestItem struct {
	Event     event.Event
	Signature string
}

// IngestBatch 在一次 fsync 屏障内摄入整批事件（组提交），
// 保证同一批要么全部可重放，要么整体停在崩溃前。
func (s *Store) IngestBatch(partition string, items []IngestItem) ([]Envelope, error) {
	if len(items) == 0 {
		return nil, nil
	}
	l, err := s.ensurePartition(partition)
	if err != nil {
		return nil, err
	}
	envs := make([]Envelope, 0, len(items))
	batch := make([]log.BatchItem, 0, len(items))
	for _, it := range items {
		if err := it.Event.Validate(); err != nil {
			return nil, err
		}
		env := Envelope{Partition: partition, Event: it.Event, Signature: it.Signature, LogSeq: l.Seq() + uint64(len(batch))}
		if verr := s.kr.VerifyEvent(it.Event, it.Signature); verr != nil {
			env.Valid = false
		} else {
			env.Valid = true
		}
		body, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		recType := RecEvent
		if !env.Valid {
			recType = RecQuarantine
		}
		envs = append(envs, env)
		batch = append(batch, log.BatchItem{Type: recType, Body: body})
	}
	recs, err := l.AppendBatch(batch)
	if err != nil {
		return nil, err
	}
	for i := range envs {
		envs[i].LogSeq = recs[i].Seq // 以日志实际分配序号为准
		s.byPart[partition] = append(s.byPart[partition], envs[i])
	}
	return envs, nil
}

// Revoke 撤回某告警的指定签注代次。晚到撤回同样受理：原始事件记录保留，
// 仅在后续代次中失去代表资格；撤回记录本身由独立策略密钥签注并进入控制日志。
func (s *Store) Revoke(alertID string, version int, reason string, issuedAt int64) (*Revocation, error) {
	if alertID == "" {
		return nil, errors.New("store: 撤回缺少 alert_id")
	}
	key := revKey{alertID, version}
	if _, exists := s.revoked[key]; exists {
		return nil, fmt.Errorf("store: %s 代次 %d 已被撤回", alertID, version)
	}
	rev := Revocation{
		ControlSeq:  s.control.Seq(),
		AlertID:     alertID,
		Endorsement: version,
		Reason:      reason,
		IssuedAt:    issuedAt,
	}
	rev.Signature = s.kr.SignRevocation(rev.Canonical())
	body, _ := json.Marshal(rev)
	if _, err := s.control.Append(RecRevocation, body); err != nil {
		return nil, err
	}
	s.revs = append(s.revs, rev)
	s.revoked[key] = rev
	return &rev, nil
}

// RollbackPartition 对单个分区追加局部回滚标签：该分区 LogSeq >= toSeq 的记录
// 从后续代树中剔除；分区日志原始字节保留，无关分区不受影响。
func (s *Store) RollbackPartition(partition string, toSeq uint64, reason string, issuedAt int64) (*Rollback, error) {
	if _, ok := s.parts[partition]; !ok {
		return nil, fmt.Errorf("store: 未知分区 %s", partition)
	}
	if prev, ok := s.rollbacks[partition]; ok && toSeq > prev.ToSeq {
		return nil, fmt.Errorf("store: 回滚水位只能前移（当前 %d，请求 %d）", prev.ToSeq, toSeq)
	}
	if toSeq > s.parts[partition].Seq() {
		return nil, fmt.Errorf("store: 回滚水位 %d 超出分区日志长度 %d", toSeq, s.parts[partition].Seq())
	}
	rb := Rollback{
		ControlSeq: s.control.Seq(),
		Partition:  partition,
		ToSeq:      toSeq,
		Reason:     reason,
		IssuedAt:   issuedAt,
	}
	rb.Signature = s.kr.SignRevocation(rb.Canonical())
	body, _ := json.Marshal(rb)
	if _, err := s.control.Append(RecRollback, body); err != nil {
		return nil, err
	}
	s.rollbacks[partition] = rb
	return &rb, nil
}

// RollbackWatermark 返回分区当前回滚水位；无回滚返回 0。
func (s *Store) RollbackWatermark(partition string) uint64 {
	if rb, ok := s.rollbacks[partition]; ok {
		return rb.ToSeq
	}
	return 0
}

// Rollbacks 返回当前全部生效的回滚标签（按分区名排序）。
func (s *Store) Rollbacks() []Rollback {
	out := make([]Rollback, 0, len(s.rollbacks))
	for _, rb := range s.rollbacks {
		out = append(out, rb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Partition < out[j].Partition })
	return out
}

// IsRevoked 报告某事件的签注当前是否已撤回。
func (s *Store) IsRevoked(e event.Event) bool {
	_, ok := s.revoked[revKey{e.AlertID, e.Endorsement}]
	return ok
}

// Partitions 返回排序后的分区名。
func (s *Store) Partitions() []string {
	names := make([]string, 0, len(s.byPart))
	for p := range s.byPart {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

// Envelopes 返回某分区的全部信封（含隔离项），按日志顺序。
func (s *Store) Envelopes(partition string) []Envelope {
	return append([]Envelope(nil), s.byPart[partition]...)
}

// Revocations 返回控制日志中的全部撤回记录。
func (s *Store) Revocations() []Revocation { return append([]Revocation(nil), s.revs...) }

// Close 释放分区句柄与排他锁。
func (s *Store) Close() error {
	var first error
	for _, l := range s.parts {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := s.control.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.lk.Release(); err != nil && first == nil {
		first = err
	}
	return first
}

// nowMillis 是命令层传入时间之外的兜底。
func nowMillis() int64 { return time.Now().UnixMilli() }

func mustHex(b []byte) string { return hex.EncodeToString(b) }
