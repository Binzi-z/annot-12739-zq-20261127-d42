package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/merkle"
)

// treeState 是发布时单个分区的建树中间状态。
type treeState struct {
	envs      []Envelope
	tree      *merkle.Tree   // 缓存层级哈希，证明生成 O(log n)
	leafOf    map[uint64]int // 日志 Seq -> 叶子下标
	root      []byte
	fullCount int // 回滚前日志中的记录总数
	watermark uint64
}

// member 是某告警分组内的一个候选成员。
type member struct {
	env  Envelope
	part string
}

// Publish 依据当前持久化事实构建并发布新一代清单。
//
// 折叠策略（全部结论只来自已落盘且签名真实的记录）：
//   - 按 AlertID 分组；组内出现多个真实签名的不同 Digest 即为同号异摘要冲突，不折叠、全量保留；
//   - 单摘要组按“优先级降序、历史接收水位升序、分区/日志序”选唯一根代表，其余折叠；
//   - 被折叠的高优告警（Priority >= HighPriorityThreshold）携带完整 Merkle 包含证明，
//     读端无需写端配合即可独立复验来源；低优折叠只留叶子哈希与定位；
//   - 签注已撤回的事件不进入根/折叠，仅登记 RevokedRefs，原始记录继续保留在分区日志前缀中；
//   - 签名无效记录隔离留痕（Quarantined），不参与任何根。
func (s *Store) Publish(publishedAt int64) (*Manifest, error) {
	if publishedAt == 0 {
		publishedAt = nowMillis()
	}
	gen := s.current + 1

	m := &Manifest{Generation: gen, PublishedAt: publishedAt, HighPriorityThreshold: s.opts.HighPriorityThreshold}

	// 1) 分区 Merkle 树与成员索引。
	// 树承诺分区日志在回滚水位内的全部记录（含隔离/撤回项）：
	// 树大小只随追加增长、只随显式回滚收缩，撤回不改变树形状。
	trees := map[string]*treeState{}
	var partNames []string
	for _, p := range s.Partitions() {
		envs := s.Envelopes(p)
		wm := s.RollbackWatermark(p) // 0 表示不回滚
		st := &treeState{leafOf: map[uint64]int{}, fullCount: len(envs), watermark: wm}
		var hashes [][]byte
		for _, env := range envs {
			if wm > 0 && env.LogSeq >= wm {
				continue // 局部回滚：后缀不进树，原始记录仍在日志中
			}
			st.leafOf[env.LogSeq] = len(st.envs)
			st.envs = append(st.envs, env)
			hashes = append(hashes, env.LeafHash())
		}
		st.tree = merkle.NewTree(hashes)
		st.root = st.tree.Root()
		trees[p] = st
		partNames = append(partNames, p)
		seqs := make([]uint64, 0, len(st.envs))
		for _, env := range st.envs {
			seqs = append(seqs, env.LogSeq)
		}
		m.Partitions = append(m.Partitions, PartitionTree{
			Partition: p, Size: len(st.envs), RootHex: mustHex(st.root), LeafSeq: seqs,
		})
		if wm > 0 {
			m.Rollbacks = append(m.Rollbacks, RollbackRef{
				Partition: p, FromSize: st.fullCount, ToSize: len(st.envs),
				ToSeq: wm, ControlSeq: s.rollbacks[p].ControlSeq,
			})
		}
	}

	// 2) 撤回引用：原始前缀保留，仅登记定位与控制序号。
	revSeen := map[string]bool{}
	for _, p := range partNames {
		for _, env := range s.Envelopes(p) {
			if rev, ok := s.revoked[revKey{env.Event.AlertID, env.Event.Endorsement}]; ok {
				ref := RevokedRef{
					AlertID: env.Event.AlertID, Endorsement: env.Event.Endorsement,
					Partition: p, LogSeq: env.LogSeq, ControlSeq: rev.ControlSeq,
				}
				key := fmt.Sprintf("%s|%d|%s|%d", ref.AlertID, ref.Endorsement, ref.Partition, ref.LogSeq)
				if !revSeen[key] {
					revSeen[key] = true
					m.RevokedRefs = append(m.RevokedRefs, ref)
				}
			}
		}
	}

	// 3) 隔离留痕。
	for _, p := range partNames {
		for _, env := range s.Envelopes(p) {
			if !env.Valid {
				m.Quarantined = append(m.Quarantined, EnvelopeRef{
					Partition: p, LogSeq: env.LogSeq, Reason: "签名校验失败",
				})
			}
		}
	}

	// 4) 分组与冲突裁定（仅真实签名且未撤回的记录具备根/折叠资格）。
	groups := map[string][]member{}
	var groupOrder []string
	for _, p := range partNames {
		st := trees[p]
		for _, env := range st.envs {
			if !env.Valid || s.IsRevoked(env.Event) {
				continue
			}
			id := env.Event.AlertID
			if _, ok := groups[id]; !ok {
				groupOrder = append(groupOrder, id)
			}
			groups[id] = append(groups[id], member{env: env, part: p})
		}
	}
	sort.Strings(groupOrder) // 确定性输出

	conflictSeen := map[string]bool{}
	for _, id := range groupOrder {
		members := groups[id]
		digests := map[string]bool{}
		for _, mb := range members {
			digests[mb.env.Event.Digest] = true
		}
		if len(digests) > 1 {
			// 同号异摘要：按摘要再分组，每个不同摘要选一个根代表；
			// 同摘要重复项仍按普通规则折叠（高优折叠带证书），不制造重复根。
			byDigest := map[string][]member{}
			var digestOrder []string
			for _, mb := range members {
				d := mb.env.Event.Digest
				if _, ok := byDigest[d]; !ok {
					digestOrder = append(digestOrder, d)
				}
				byDigest[d] = append(byDigest[d], mb)
			}
			sort.Strings(digestOrder)
			// 最早冲突对：两个不同摘要中各自最早成员，按历史接收水位裁定先后。
			var earliest []member
			for _, d := range digestOrder {
				grp := byDigest[d]
				sort.SliceStable(grp, func(i, j int) bool {
					return lessForConflict(grp[i].env.Event, grp[j].env.Event, grp[i].part, grp[j].part)
				})
				earliest = append(earliest, grp[0])
			}
			sort.SliceStable(earliest, func(i, j int) bool {
				return lessForConflict(earliest[i].env.Event, earliest[j].env.Event, earliest[i].part, earliest[j].part)
			})
			first, second := earliest[0], earliest[1]
			cKey := id + "|" + first.env.Event.Digest + "|" + second.env.Event.Digest
			if !conflictSeen[cKey] {
				conflictSeen[cKey] = true
				cert, err := s.inclusionFor(trees, first.part, first.env.LogSeq)
				if err != nil {
					return nil, err
				}
				m.Conflicts = append(m.Conflicts, Conflict{
					AlertID:      id,
					First:        s.toRootEntry(trees, first.part, first.env),
					Second:       s.toRootEntry(trees, second.part, second.env),
					FirstDigest:  first.env.Event.Digest,
					SecondDigest: second.env.Event.Digest,
					DetectedAt:   publishedAt,
					Certificate:  cert,
				})
			}
			for _, d := range digestOrder {
				grp := byDigest[d]
				sort.SliceStable(grp, func(i, j int) bool {
					return repBefore(grp[i].env.Event, grp[j].env.Event, grp[i].part, grp[j].part)
				})
				m.Roots = append(m.Roots, s.toRootEntry(trees, grp[0].part, grp[0].env))
				for _, mb := range grp[1:] {
					folded, err := s.buildFolded(trees, mb, members[0].env.Event.AlertID)
					if err != nil {
						return nil, err
					}
					m.Folded = append(m.Folded, folded)
				}
			}
			continue
		}
		// 单摘要组：选唯一代表。
		sort.SliceStable(members, func(i, j int) bool {
			return repBefore(members[i].env.Event, members[j].env.Event, members[i].part, members[j].part)
		})
		rep := members[0]
		m.Roots = append(m.Roots, s.toRootEntry(trees, rep.part, rep.env))
		for _, mb := range members[1:] {
			folded, err := s.buildFolded(trees, mb, rep.env.Event.AlertID)
			if err != nil {
				return nil, err
			}
			m.Folded = append(m.Folded, folded)
		}
	}

	// 5) 代间只追加/回滚关系由读端基于独立重放的叶子数组重算前缀根复验，
	// 清单本身不嵌入可被误解的证明，只保留回滚标签与每代叶子定位表。

	// 6) 控制日志水位与链尾承诺。
	m.ControlSize = int(s.control.Seq())
	m.ControlTail = mustHex(s.control.Tail())

	if err := s.commit(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) toRootEntry(trees map[string]*treeState, part string, env Envelope) RootEntry {
	return RootEntry{
		AlertID:   env.Event.AlertID,
		Priority:  env.Event.Priority,
		Watermark: env.Event.ReceivedAt,
		Partition: part,
		LogSeq:    env.LogSeq,
		LeafIndex: trees[part].leafOf[env.LogSeq],
		Event:     env.Event,
		Signature: env.Signature,
		LeafHash:  mustHex(env.LeafHash()),
	}
}

func (s *Store) inclusionFor(trees map[string]*treeState, part string, logSeq uint64) ([]ProofStep, error) {
	st := trees[part]
	idx, ok := st.leafOf[logSeq]
	if !ok {
		return nil, fmt.Errorf("日志序 %d 不在分区 %s 树中", logSeq, part)
	}
	proof, err := st.tree.Proof(idx)
	if err != nil {
		return nil, err
	}
	out := make([]ProofStep, 0, len(proof))
	for _, stp := range proof {
		out = append(out, ProofStep{HashHex: mustHex(stp.Hash), SiblingLeft: stp.SiblingLeft})
	}
	return out, nil
}

// buildFolded 构造折叠条目；高优折叠带完整事件、真实签名与包含证明。
func (s *Store) buildFolded(trees map[string]*treeState, mb member, foldedUnder string) (FoldedEntry, error) {
	folded := FoldedEntry{
		AlertID:     mb.env.Event.AlertID,
		Priority:    mb.env.Event.Priority,
		Partition:   mb.part,
		LogSeq:      mb.env.LogSeq,
		LeafIndex:   trees[mb.part].leafOf[mb.env.LogSeq],
		LeafHash:    mustHex(mb.env.LeafHash()),
		FoldedUnder: foldedUnder,
	}
	if mb.env.Event.Priority >= s.opts.HighPriorityThreshold {
		ev := mb.env.Event
		folded.Event = &ev
		folded.Signature = mb.env.Signature
		proof, err := s.inclusionFor(trees, mb.part, mb.env.LogSeq)
		if err != nil {
			return FoldedEntry{}, err
		}
		folded.InclusionProof = proof
	}
	return folded, nil
}

// repBefore 选择根代表：优先级高者优先，其次历史接收水位低者（最早到达），
// 再以分区名、日志序兜底，保证确定性。
func repBefore(a, b event.Event, pa, pb string) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.ReceivedAt != b.ReceivedAt {
		return a.ReceivedAt < b.ReceivedAt
	}
	if pa != pb {
		return pa < pb
	}
	return a.AlertID < b.AlertID
}

// lessForConflict 排序冲突成员以确定“最早”一对：先看水位，再看分区/告警号。
func lessForConflict(a, b event.Event, pa, pb string) bool {
	if a.ReceivedAt != b.ReceivedAt {
		return a.ReceivedAt < b.ReceivedAt
	}
	if pa != pb {
		return pa < pb
	}
	return a.AlertID < b.AlertID
}

// stepsToJSON 已随一致性证明移除；包含证明在 inclusionFor 中直接构造。

// commit 执行带屏障的两阶段发布。
func (s *Store) commit(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	finalPath := filepath.Join(s.dir, fmt.Sprintf("gen-%d.json", m.Generation))
	tmpPath := finalPath + ".tmp"
	if err := removeStaleTemp(tmpPath); err != nil {
		return err
	}

	// 阶段一：临时文件写完并 fsync（崩溃点 1：此前崩溃等于未发布）。
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := syncFile(tmpPath); err != nil {
		return err
	}
	if s.opts.CrashPoint == CrashAfterManifestTemp {
		return ErrCrashInjected
	}

	// 阶段二：原子改名 + 目录屏障，清单自此持久可见（合并完成）。
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}

	// 崩溃点 2：合并完成而回执未写。
	if s.opts.CrashPoint == CrashAfterRenameBeforeReceipt {
		return ErrCrashInjected
	}

	// 回执独立落盘并 fsync。
	rcpt := &Receipt{
		Generation:  m.Generation,
		ManifestHex: m.DigestHex(),
		IssuedAt:    m.PublishedAt,
	}
	rcpt.Signature = s.kr.SignRevocation(m.Digest())
	rcptPath := filepath.Join(s.dir, "receipts", fmt.Sprintf("gen-%d.rcpt", m.Generation))
	rcptData, err := json.MarshalIndent(rcpt, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(rcptPath, rcptData, 0o600); err != nil {
		return err
	}
	if err := syncFile(rcptPath); err != nil {
		return err
	}
	if s.opts.CrashPoint == CrashAfterReceiptBeforeCurrent {
		return ErrCrashInjected
	}

	// CURRENT 最后翻转：读者只认 CURRENT 且必须能读到对应回执。
	curTmp := filepath.Join(s.dir, "CURRENT.tmp")
	if err := os.WriteFile(curTmp, []byte(fmt.Sprintf("%d\n", m.Generation)), 0o600); err != nil {
		return err
	}
	if err := syncFile(curTmp); err != nil {
		return err
	}
	if err := os.Rename(curTmp, filepath.Join(s.dir, "CURRENT")); err != nil {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	s.current = m.Generation
	return nil
}

func syncFile(path string) error {
	// Windows 上对只读句柄调用 FlushFileBuffers 会被拒绝（Access denied），
	// 因此用读写句柄刷盘；文件由本进程刚创建，权限满足。
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
