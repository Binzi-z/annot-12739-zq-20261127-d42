// Package reader 是独立读端：不持有写锁、不依赖写端内存状态，
// 直接重放分区/控制日志，独立重建 Merkle 根并与固定代清单逐项比对。
package reader

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"example.invalid/local-fixture/internal/endorsement"
	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/log"
	"example.invalid/local-fixture/internal/merkle"
	"example.invalid/local-fixture/internal/store"
)

// Reader 固定在某一代清单上；写端后续发布不会改变其视图（旧读者固定旧代）。
type Reader struct {
	dir      string
	kr       *endorsement.Keyring
	pinned   int
	manifest *store.Manifest
	receipt  *store.Receipt

	// 独立重放结果
	envByPart   map[string][]store.Envelope
	flatLeaves  map[string][]byte // 固定代允许叶子的连续哈希（每叶 32 字节，按 LeafSeq 顺序）
	revs        []store.Revocation
	controlRecs []log.Record // 重放得到的控制日志前缀，Verify 直接复用，不再读盘
}

// Open 打开只读读端并固定代次。pinGeneration 为 0 时固定 CURRENT。
// 固定后即使写端发布新代，本 Reader 的全部查询仍返回旧代事实。
func Open(dir string, kr *endorsement.Keyring, pinGeneration int) (*Reader, error) {
	if pinGeneration == 0 {
		cur, err := store.ReadCurrent(dir)
		if err != nil {
			return nil, err
		}
		if cur == 0 {
			return nil, fmt.Errorf("reader: 尚无已提交代（CURRENT 不存在）")
		}
		pinGeneration = cur
	}
	m, err := store.ReadManifest(dir, pinGeneration)
	if err != nil {
		return nil, fmt.Errorf("reader: 固定代 %d 清单不可读: %w", pinGeneration, err)
	}
	rcpt, err := store.ReadReceipt(dir, pinGeneration)
	if err != nil {
		return nil, fmt.Errorf("reader: 代 %d 回执缺失（合并完成而回执未写时读端拒绝承认）: %w", pinGeneration, err)
	}
	r := &Reader{
		dir: dir, kr: kr, pinned: pinGeneration,
		manifest:   m,
		receipt:    rcpt,
		envByPart:  map[string][]store.Envelope{},
		flatLeaves: map[string][]byte{},
	}
	if err := r.replay(); err != nil {
		return nil, err
	}
	return r, nil
}

// Pinned 返回固定代次。
func (r *Reader) Pinned() int { return r.pinned }

func (r *Reader) replay() error {
	// 控制日志：独立校验策略签名，按清单水位截取，重建该代可见撤回集合。
	crecs, err := log.ReadAll(filepath.Join(r.dir, "control.log"))
	if err != nil {
		// 控制日志可能尚不存在（首次发布前无撤回）。
		if !os.IsNotExist(err) {
			return err
		}
	}
	revoked := map[pairKey]bool{}
	rollbacks := map[string]store.Rollback{}
	r.controlRecs = crecs
	for _, rec := range crecs {
		if int(rec.Seq) >= r.manifest.ControlSize {
			break // 固定代只承认发布时已存在的控制前缀
		}
		switch rec.Type {
		case store.RecRevocation:
			var rev store.Revocation
			if err := json.Unmarshal(rec.Body, &rev); err != nil {
				return fmt.Errorf("控制记录 %d 损坏: %w", rec.Seq, err)
			}
			if err := r.kr.VerifyRevocation(rev.Canonical(), rev.Signature); err != nil {
				return fmt.Errorf("控制记录 %d 策略签名无效: %w", rec.Seq, err)
			}
			r.revs = append(r.revs, rev)
			revoked[pairKey{rev.AlertID, rev.Endorsement}] = true
		case store.RecRollback:
			var rb store.Rollback
			if err := json.Unmarshal(rec.Body, &rb); err != nil {
				return fmt.Errorf("回滚控制记录 %d 损坏: %w", rec.Seq, err)
			}
			if err := r.kr.VerifyRevocation(rb.Canonical(), rb.Signature); err != nil {
				return fmt.Errorf("回滚控制记录 %d 策略签名无效: %w", rec.Seq, err)
			}
			rollbacks[rb.Partition] = rb
		default:
			return fmt.Errorf("控制记录 %d 未知类型 %d", rec.Seq, rec.Type)
		}
	}

	// 分区日志：独立重放哈希链并重建该代 Merkle 叶子序列。
	// 允许集合取自固定代清单的 LeafSeq——旧读者不受发布后追加/回滚影响，
	// 因为每代清单都显式持有自己的叶子定位表，且原始日志记录永不删除。
	for _, pt := range r.manifest.Partitions {
		path := filepath.Join(r.dir, "part-"+pt.Partition+".log")
		recs, err := log.ReadAll(path)
		if err != nil {
			return fmt.Errorf("重放分区 %s: %w", pt.Partition, err)
		}
		allowed := make(map[uint64]bool, len(pt.LeafSeq))
		for _, seq := range pt.LeafSeq {
			allowed[seq] = true
		}
		var envs []store.Envelope
		flat := make([]byte, 0, len(pt.LeafSeq)*32)
		var leafSeq []uint64
		for _, rec := range recs {
			var env store.Envelope
			if err := json.Unmarshal(rec.Body, &env); err != nil {
				return fmt.Errorf("分区 %s 记录 %d 损坏: %w", pt.Partition, rec.Seq, err)
			}
			envs = append(envs, env)
			if !allowed[env.LogSeq] {
				continue // 属于后续代（追加或回滚前后缀），固定代不予承认
			}
			flat = append(flat, env.LeafHash()...)
			leafSeq = append(leafSeq, env.LogSeq)
			// 对有效且未撤回的记录独立复验真实签名，不相信信封 Valid 位。
			if env.Valid && !revoked[keyOf(env.Event)] {
				if err := r.kr.VerifyEvent(env.Event, env.Signature); err != nil {
					return fmt.Errorf("分区 %s 记录 %d 签名复验失败: %w", pt.Partition, rec.Seq, err)
				}
			}
		}
		r.envByPart[pt.Partition] = envs
		r.flatLeaves[pt.Partition] = flat
		gotRoot := merkle.RootFromFlat(flat, len(flat)/32)
		if len(flat)/32 != pt.Size {
			return fmt.Errorf("分区 %s 叶子数不符: 日志重建 %d 清单 %d", pt.Partition, len(flat)/32, pt.Size)
		}
		if hex.EncodeToString(gotRoot) != pt.RootHex {
			return fmt.Errorf("分区 %s Merkle 根与清单不符（日志被改写）", pt.Partition)
		}
		for i, seq := range leafSeq {
			if i >= len(pt.LeafSeq) || pt.LeafSeq[i] != seq {
				return fmt.Errorf("分区 %s 叶子定位表不符", pt.Partition)
			}
		}
	}
	return nil
}

type pairKey struct {
	id  string
	ver int
}

func keyOf(e event.Event) pairKey { return pairKey{e.AlertID, e.Endorsement} }

// Verify 对固定代执行完整独立复验，返回发现的问题（空切片即全部通过）。
func (r *Reader) Verify() []string {
	var problems []string
	m := r.manifest

	// 1) 回执：清单哈希与策略签名。
	if r.receipt.Generation != r.pinned {
		problems = append(problems, "回子代次与固定代不一致")
	}
	if r.receipt.ManifestHex != m.DigestHex() {
		problems = append(problems, "回执内嵌清单哈希不匹配")
	}
	if err := r.kr.VerifyRevocation(m.Digest(), r.receipt.Signature); err != nil {
		problems = append(problems, fmt.Sprintf("回执策略签名无效: %v", err))
	}

	// 2) 控制日志水位/链尾承诺（复用重放结果，不重复读盘）。
	if len(r.controlRecs) < m.ControlSize {
		problems = append(problems, fmt.Sprintf("控制日志收缩: 清单承诺 %d 实际 %d", m.ControlSize, len(r.controlRecs)))
	}

	// 3) 根条目：叶子哈希与包含关系均可在重建树中定位。
	rootIndex := map[string]map[uint64]bool{}
	for _, pt := range m.Partitions {
		rootIndex[pt.Partition] = map[uint64]bool{}
		for _, seq := range pt.LeafSeq {
			rootIndex[pt.Partition][seq] = true
		}
	}
	rootIDs := map[string]int{}
	for _, e := range m.Roots {
		rootIDs[e.AlertID]++
		if !rootIndex[e.Partition][e.LogSeq] {
			problems = append(problems, fmt.Sprintf("根 %s 定位不在分区树中", e.AlertID))
		}
		env, err := r.findEnvelope(e.Partition, e.LogSeq)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if hex.EncodeToString(env.LeafHash()) != e.LeafHash {
			problems = append(problems, fmt.Sprintf("根 %s 叶子哈希与日志不符", e.AlertID))
		}
		if err := r.kr.VerifyEvent(env.Event, env.Signature); err != nil {
			problems = append(problems, fmt.Sprintf("根 %s 签名无效: %v", e.AlertID, err))
		}
	}

	// 4) 折叠项：高优折叠必须带可独立复验的包含证明。
	for _, f := range m.Folded {
		env, err := r.findEnvelope(f.Partition, f.LogSeq)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if hex.EncodeToString(env.LeafHash()) != f.LeafHash {
			problems = append(problems, fmt.Sprintf("折叠 %s 叶子哈希与日志不符", f.AlertID))
		}
		if env.Event.Priority >= r.highThreshold() {
			// 单叶分区无需包含证明（叶哈希即分区根）；多叶分区必须带完整证明。
			pt := r.partitionTree(f.Partition)
			needProof := pt != nil && pt.Size > 1
			if f.Event == nil || (needProof && len(f.InclusionProof) == 0) {
				problems = append(problems, fmt.Sprintf("高优折叠 %s 缺少独立复验证书", f.AlertID))
				continue
			}
			if needProof {
				if err := r.verifyProof(f.Partition, f.LeafIndex, env.LeafHash(), f.InclusionProof); err != nil {
					problems = append(problems, fmt.Sprintf("高优折叠 %s 包含证明无效: %v", f.AlertID, err))
				}
			} else if hex.EncodeToString(env.LeafHash()) != pt.RootHex {
				problems = append(problems, fmt.Sprintf("高优折叠 %s 单叶哈希不等于分区根", f.AlertID))
			}
			if err := r.kr.VerifyEvent(*f.Event, f.Signature); err != nil {
				problems = append(problems, fmt.Sprintf("高优折叠 %s 签注无效: %v", f.AlertID, err))
			}
		}
	}

	// 5) 冲突：同号异摘要必须全部留根，最早一对带最少证书。
	conflictIDs := map[string]bool{}
	for _, c := range m.Conflicts {
		conflictIDs[c.AlertID] = true
		if c.FirstDigest == c.SecondDigest {
			problems = append(problems, fmt.Sprintf("冲突 %s 两造摘要相同", c.AlertID))
		}
		if err := r.verifyProof(c.First.Partition, c.First.LeafIndex, mustDecode(c.First.LeafHash), c.Certificate); err != nil {
			problems = append(problems, fmt.Sprintf("冲突 %s 最少证书无效: %v", c.AlertID, err))
		}
	}
	for id := range conflictIDs {
		if rootIDs[id] < 2 {
			problems = append(problems, fmt.Sprintf("冲突 %s 未在根上全量保留", id))
		}
	}

	// 6) 撤回引用：原始前缀仍在日志中（未被丢弃）。
	for _, rv := range m.RevokedRefs {
		if _, err := r.findEnvelope(rv.Partition, rv.LogSeq); err != nil {
			problems = append(problems, fmt.Sprintf("撤回引用 %s 原始记录丢失: %v", rv.AlertID, err))
		}
	}

	// 7) 与上一代的关系：基于独立重放叶子重算前缀根，无需相信清单内嵌证明。
	//    普通分区：旧叶子序列必须是新序列前缀，且前缀重算根等于旧根；
	//    回滚分区：新叶子序列必须是旧序列前缀（见 verifyRollbackPrefix）。
	if r.pinned > 1 {
		prev, err := store.ReadManifest(r.dir, r.pinned-1)
		if err == nil {
			rolled := map[string]store.RollbackRef{}
			for _, rb := range r.manifest.Rollbacks {
				rolled[rb.Partition] = rb
			}
			for _, pt := range prev.Partitions {
				cur := r.partitionTree(pt.Partition)
				if cur == nil {
					continue
				}
				if rb, ok := rolled[pt.Partition]; ok {
					r.verifyRollbackPrefix(pt, *cur, rb, &problems)
					continue
				}
				if cur.Size < pt.Size {
					problems = append(problems, fmt.Sprintf("分区 %s 未声明收缩: %d -> %d", pt.Partition, pt.Size, cur.Size))
					continue
				}
				for i := 0; i < pt.Size; i++ {
					if i >= len(cur.LeafSeq) || pt.LeafSeq[i] != cur.LeafSeq[i] {
						problems = append(problems, fmt.Sprintf("分区 %s 旧代叶子第 %d 项不再是新代前缀", pt.Partition, i))
						break
					}
				}
				prefixRoot := merkle.RootFromFlat(r.flatLeaves[pt.Partition][:pt.Size*32], pt.Size)
				if hex.EncodeToString(prefixRoot) != pt.RootHex {
					problems = append(problems, fmt.Sprintf("分区 %s 前缀重算根与旧代根不符（历史被改写）", pt.Partition))
				}
			}
		}
	}

	// 8) 回滚标签本身：控制记录必须存在且策略签名有效，水位与清单一致。
	for _, rb := range r.manifest.Rollbacks {
		found := false
		for _, rec := range r.controlRecs {
			if rec.Seq != rb.ControlSeq || rec.Type != store.RecRollback {
				continue
			}
			var got store.Rollback
			if jerr := json.Unmarshal(rec.Body, &got); jerr != nil {
				problems = append(problems, fmt.Sprintf("回滚控制记录 %d 损坏: %v", rb.ControlSeq, jerr))
				break
			}
			if got.Partition != rb.Partition || got.ToSeq != rb.ToSeq ||
				r.kr.VerifyRevocation(got.Canonical(), got.Signature) != nil {
				problems = append(problems, fmt.Sprintf("分区 %s 回滚标签与控制日志不符", rb.Partition))
			}
			found = true
		}
		if !found {
			problems = append(problems, fmt.Sprintf("分区 %s 回滚控制记录 %d 缺失", rb.Partition, rb.ControlSeq))
		}
	}
	return problems
}

// verifyRollbackPrefix 复验局部回滚：新代保留的叶子序列必须是旧代的严格前缀，
// 且由旧叶子哈希重建的前缀根与新代根一致——被剔除后缀之外的事实一字未改。
func (r *Reader) verifyRollbackPrefix(old, cur store.PartitionTree, rb store.RollbackRef, problems *[]string) {
	if cur.Size > old.Size {
		*problems = append(*problems, fmt.Sprintf("回滚分区 %s 叶子数反而增长", rb.Partition))
		return
	}
	if cur.Size != rb.ToSize || old.Size != rb.FromSize {
		*problems = append(*problems, fmt.Sprintf("分区 %s 回滚前后大小与标签不符", rb.Partition))
	}
	for i := 0; i < cur.Size; i++ {
		if i >= len(old.LeafSeq) || old.LeafSeq[i] != cur.LeafSeq[i] {
			*problems = append(*problems, fmt.Sprintf("分区 %s 回滚保留前缀第 %d 叶不一致", rb.Partition, i))
			return
		}
	}
	// 用独立重放得到的扁平叶子重建前缀根。
	flat := r.flatLeaves[rb.Partition]
	if rb.ToSize > 0 {
		flat = flat[:rb.ToSize*32]
	}
	if hex.EncodeToString(merkle.RootFromFlat(flat, rb.ToSize)) != cur.RootHex {
		*problems = append(*problems, fmt.Sprintf("分区 %s 回滚后根与前缀重建不符", rb.Partition))
	}
}

func (r *Reader) highThreshold() int { return r.manifest.HighPriorityThreshold }

func (r *Reader) partitionTree(name string) *store.PartitionTree {
	for i := range r.manifest.Partitions {
		if r.manifest.Partitions[i].Partition == name {
			return &r.manifest.Partitions[i]
		}
	}
	return nil
}

func (r *Reader) findEnvelope(partition string, seq uint64) (store.Envelope, error) {
	for _, env := range r.envByPart[partition] {
		if env.LogSeq == seq {
			return env, nil
		}
	}
	return store.Envelope{}, fmt.Errorf("分区 %s 日志序 %d 不存在", partition, seq)
}

func (r *Reader) verifyProof(partition string, leafIndex int, leafHash []byte, steps []store.ProofStep) error {
	pt := r.partitionTree(partition)
	if pt == nil {
		return fmt.Errorf("未知分区 %s", partition)
	}
	return merkle.VerifyInclusion(leafHash, leafIndex, pt.Size, fromSteps(steps), mustDecode(pt.RootHex))
}

func fromSteps(in []store.ProofStep) []merkle.Step {
	out := make([]merkle.Step, 0, len(in))
	for _, s := range in {
		out = append(out, merkle.Step{Hash: mustDecode(s.HashHex), SiblingLeft: s.SiblingLeft})
	}
	return out
}

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Roots 返回固定代的根代表事件（按告警号排序）。
func (r *Reader) Roots() []store.RootEntry {
	out := append([]store.RootEntry(nil), r.manifest.Roots...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].AlertID < out[j].AlertID })
	return out
}

// Folded 返回固定代的折叠条目。
func (r *Reader) Folded() []store.FoldedEntry {
	return append([]store.FoldedEntry(nil), r.manifest.Folded...)
}

// Conflicts 返回固定代的全部已证冲突（按检测顺序，首个即最早）。
func (r *Reader) Conflicts() []store.Conflict {
	return append([]store.Conflict(nil), r.manifest.Conflicts...)
}

// EarliestConflict 返回最早已证冲突；无冲突返回 nil。
func (r *Reader) EarliestConflict() *store.Conflict {
	if len(r.manifest.Conflicts) == 0 {
		return nil
	}
	c := r.manifest.Conflicts[0]
	return &c
}

// MinimalCertificate 返回最早冲突的最少证书（较早事件的包含证明）及其独立复验结论。
func (r *Reader) MinimalCertificate() (*store.Conflict, error) {
	c := r.EarliestConflict()
	if c == nil {
		return nil, nil
	}
	if err := r.verifyProof(c.First.Partition, c.First.LeafIndex, mustDecode(c.First.LeafHash), c.Certificate); err != nil {
		return nil, fmt.Errorf("最少证书复验失败: %w", err)
	}
	return c, nil
}

// RevokedPrefixes 返回固定代中“已撤回但原始前缀保留”的定位记录。
func (r *Reader) RevokedPrefixes() []store.RevokedRef {
	return append([]store.RevokedRef(nil), r.manifest.RevokedRefs...)
}

// Quarantined 返回隔离留痕。
func (r *Reader) Quarantined() []store.EnvelopeRef {
	return append([]store.EnvelopeRef(nil), r.manifest.Quarantined...)
}

// ManifestDigest 返回固定代清单哈希。
func (r *Reader) ManifestDigest() string { return r.manifest.DigestHex() }

// Summary 返回单行摘要，供命令行输出。
func (r *Reader) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "generation=%d roots=%d folded=%d(high-cert=%d) conflicts=%d quarantined=%d revoked-prefix=%d control=%d",
		r.pinned,
		len(r.manifest.Roots),
		len(r.manifest.Folded),
		countHighCert(r.manifest.Folded),
		len(r.manifest.Conflicts),
		len(r.manifest.Quarantined),
		len(r.manifest.RevokedRefs),
		r.manifest.ControlSize,
	)
	return b.String()
}

func countHighCert(fs []store.FoldedEntry) int {
	n := 0
	for _, f := range fs {
		if len(f.InclusionProof) > 0 {
			n++
		}
	}
	return n
}
