package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"example.invalid/local-fixture/internal/reader"
	"example.invalid/local-fixture/internal/store"
)

// 折叠策略：优先级 > 历史接收水位；高优折叠带独立复验证书。
func TestFoldingPriorityWatermarkAndCert(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{HighPriorityThreshold: 8})

	// 同号同摘要三条：A 分区两条（低优早到、高优晚到），B 分区一条高优。
	e1 := ev("A1", "dig-1", 3, "src-1", 1, 100)
	e2 := ev("A1", "dig-1", 9, "src-1", 1, 200)
	e3 := ev("A1", "dig-1", 8, "src-2", 1, 150)
	// B 分区再放一条别的告警，使其成为多叶树，高优折叠必须带非空包含证明。
	e4 := ev("A2", "dig-2", 2, "src-2", 1, 160)
	if _, err := s.Ingest("ca", e1, sign(t, kr, e1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("ca", e2, sign(t, kr, e2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("cb", e3, sign(t, kr, e3)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("cb", e4, sign(t, kr, e4)); err != nil {
		t.Fatal(err)
	}
	m, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A1 组 1 个根代表（A2 是另一个独立告警，各占 1 根）。
	var a1Root *store.RootEntry
	for i := range m.Roots {
		if m.Roots[i].AlertID == "A1" {
			a1Root = &m.Roots[i]
		}
	}
	if a1Root == nil || a1Root.Priority != 9 {
		t.Fatalf("A1 根代表选择错误: %+v", m.Roots)
	}
	if len(m.Folded) != 2 {
		t.Fatalf("折叠数 %d", len(m.Folded))
	}
	high, low := 0, 0
	for _, f := range m.Folded {
		if f.Priority >= 8 {
			high++
			if len(f.InclusionProof) == 0 || f.Event == nil || f.Signature == "" {
				t.Fatalf("高优折叠 %s 缺少独立复验材料", f.AlertID)
			}
		} else {
			low++
			if len(f.InclusionProof) != 0 {
				t.Fatalf("低优折叠不应携带完整证书: %+v", f)
			}
		}
	}
	if high != 1 || low != 1 {
		t.Fatalf("高优/低优折叠计数 %d/%d", high, low)
	}
	// 高优折叠位于多叶分区，包含证明必须非空。
	for _, f := range m.Folded {
		if f.Priority >= 8 && len(f.InclusionProof) == 0 {
			t.Fatalf("多叶分区高优折叠 %s 证明为空", f.AlertID)
		}
	}

	// 独立读端复验全部承诺。
	r, err := reader.Open(dir, kr, 0)
	if err != nil {
		t.Fatal(err)
	}
	if problems := r.Verify(); len(problems) != 0 {
		t.Fatalf("独立复验失败: %v", problems)
	}
}

// 同号异摘要：不折叠、全量留根，最早冲突对带最少证书。
func TestSameIDDifferentDigestConflict(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{})
	first := ev("A9", "dig-X", 7, "src-1", 1, 100)
	second := ev("A9", "dig-Y", 7, "src-2", 1, 200)
	third := ev("A9", "dig-X", 4, "src-1", 1, 300) // 与首条同摘要，可折叠
	if _, err := s.Ingest("ca", first, sign(t, kr, first)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("cb", second, sign(t, kr, second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("ca", third, sign(t, kr, third)); err != nil {
		t.Fatal(err)
	}
	m, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// 两个不同摘要 -> 两个根（同摘要的 third 被折叠）。
	if len(m.Roots) != 2 {
		t.Fatalf("冲突应保留两个根，实际 %d", len(m.Roots))
	}
	if len(m.Conflicts) != 1 {
		t.Fatalf("冲突数 %d", len(m.Conflicts))
	}
	c := m.Conflicts[0]
	if c.FirstDigest != "dig-X" || c.SecondDigest != "dig-Y" {
		t.Fatalf("最早冲突对摘要错误: %s/%s", c.FirstDigest, c.SecondDigest)
	}
	if c.First.Watermark != 100 || c.Second.Watermark != 200 {
		t.Fatal("最早冲突未按历史接收水位裁定")
	}
	if len(c.Certificate) == 0 {
		t.Fatal("最少证书为空")
	}
	// 独立复验最少证书。
	r, err := reader.Open(dir, kr, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.MinimalCertificate()
	if err != nil {
		t.Fatalf("最少证书复验: %v", err)
	}
	if got.AlertID != "A9" {
		t.Fatal("最早已证冲突定位错误")
	}
	if problems := r.Verify(); len(problems) != 0 {
		t.Fatalf("独立复验: %v", problems)
	}
}

// 晚到撤销：原始前缀保留，撤销后该事件失去根资格，旧代仍可固定复验。
func TestLateRevocationKeepsCommittedPrefix(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{})
	e := ev("A1", "dig", 9, "src-1", 1, 100)
	if _, err := s.Ingest("ca", e, sign(t, kr, e)); err != nil {
		t.Fatal(err)
	}
	gen1, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(gen1.Roots) != 1 {
		t.Fatal("第一代应含 1 个根")
	}
	// 晚到撤销旧版签注。
	if _, err := s.Revoke("A1", 1, "旧版签注撤回", 1500); err != nil {
		t.Fatal(err)
	}
	gen2, err := s.Publish(2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(gen2.Roots) != 0 {
		t.Fatalf("撤销后不应再有根，实际 %d", len(gen2.Roots))
	}
	if len(gen2.RevokedRefs) != 1 || gen2.RevokedRefs[0].ControlSeq != 0 {
		t.Fatalf("撤回引用错误: %+v", gen2.RevokedRefs)
	}
	// 原始记录仍在分区日志中。
	recs, err := readRaw(dir, "ca")
	if err != nil || len(recs) != 1 {
		t.Fatalf("原始前缀丢失: %v %d", err, len(recs))
	}
	// 旧读者固定旧代：根仍在、复验仍通过。
	old, err := reader.Open(dir, kr, gen1.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Roots()) != 1 {
		t.Fatal("旧读者视图被撤销改写")
	}
	if p := old.Verify(); len(p) != 0 {
		t.Fatalf("旧代复验失败: %v", p)
	}
	// 新读者同样复验通过（撤回引用可在日志定位）。
	newR, err := reader.Open(dir, kr, gen2.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if p := newR.Verify(); len(p) != 0 {
		t.Fatalf("新代复验失败: %v", p)
	}
	if len(newR.RevokedPrefixes()) != 1 {
		t.Fatal("新读者看不到保留的撤回前缀")
	}
}

// 签名无效：隔离留痕，不进根，不污染树根承诺。
func TestInvalidSignatureQuarantine(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{})
	good := ev("A1", "d1", 5, "src", 1, 1)
	bad := ev("A2", "d2", 5, "src", 1, 2)
	if _, err := s.Ingest("ca", good, sign(t, kr, good)); err != nil {
		t.Fatal(err)
	}
	if env, err := s.Ingest("ca", bad, "deadbeef"); err != nil {
		t.Fatal(err)
	} else if env.Valid {
		t.Fatal("无效签名竟被标记为有效")
	}
	m, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(m.Quarantined) != 1 || len(m.Roots) != 1 {
		t.Fatalf("隔离/根计数错误: q=%d roots=%d", len(m.Quarantined), len(m.Roots))
	}
	r, err := reader.Open(dir, kr, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Verify(); len(p) != 0 {
		t.Fatalf("复验: %v", p)
	}
}

// 局部回滚：只影响点名分区，无关分区根不变，原始日志不删。
func TestPartitionRollbackIsolation(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{})
	for i := 0; i < 6; i++ {
		ea := ev("A", "da", 5, "src", 1, int64(10+i))
		eb := ev("B", "db", 5, "src", 1, int64(20+i))
		if _, err := s.Ingest("ca", ea, sign(t, kr, ea)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Ingest("cb", eb, sign(t, kr, eb)); err != nil {
			t.Fatal(err)
		}
	}
	gen1, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RollbackPartition("ca", 4, "后缀作废", 1500); err != nil {
		t.Fatal(err)
	}
	gen2, err := s.Publish(2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var a1, a2, b1, b2 string
	for _, pt := range gen1.Partitions {
		if pt.Partition == "ca" {
			a1 = pt.RootHex
		}
		if pt.Partition == "cb" {
			b1 = pt.RootHex
		}
	}
	for _, pt := range gen2.Partitions {
		if pt.Partition == "ca" {
			a2 = pt.RootHex
			if pt.Size != 4 {
				t.Fatalf("回滚后 ca 树大小 %d", pt.Size)
			}
		}
		if pt.Partition == "cb" {
			b2 = pt.RootHex
			if pt.Size != 6 {
				t.Fatal("无关分区大小被改动")
			}
		}
	}
	if a1 == a2 {
		t.Fatal("被回滚分区根未变化")
	}
	if b1 != b2 {
		t.Fatal("无关分区根被局部回滚波及")
	}
	if len(gen2.Rollbacks) != 1 {
		t.Fatalf("回滚标签数 %d", len(gen2.Rollbacks))
	}
	// 原始 6 条记录全部保留。
	recs, err := readRaw(dir, "ca")
	if err != nil || len(recs) != 6 {
		t.Fatalf("回滚删除了原始日志: %v %d", err, len(recs))
	}
	r, err := reader.Open(dir, kr, gen2.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Verify(); len(p) != 0 {
		t.Fatalf("回滚代复验: %v", p)
	}
	// 旧代仍固定可复验。
	old, err := reader.Open(dir, kr, gen1.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if p := old.Verify(); len(p) != 0 {
		t.Fatalf("旧代复验: %v", p)
	}
	if len(old.Roots()) != 2 {
		t.Fatal("旧代根数量改变")
	}
}

// 代间只追加关系：读端基于独立重放叶子重算前缀根，旧代历史不可被改写。
func TestCrossGenerationAppendPrefix(t *testing.T) {
	dir, kr := t.TempDir(), testKeyring(t)
	s := mustOpen(t, dir, kr, store.Options{})
	for i := 0; i < 5; i++ {
		e := ev("A", "d", 5, "src", 1, int64(i))
		if _, err := s.Ingest("ca", e, sign(t, kr, e)); err != nil {
			t.Fatal(err)
		}
	}
	g1, err := s.Publish(1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 5; i < 9; i++ {
		e := ev("B", "d", 5, "src", 1, int64(i))
		if _, err := s.Ingest("ca", e, sign(t, kr, e)); err != nil {
			t.Fatal(err)
		}
	}
	g2, err := s.Publish(2000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// 新代旧分区大小必须严格增长，且旧叶子定位序列保持为前缀。
	var pt1, pt2 store.PartitionTree
	for _, pt := range g1.Partitions {
		if pt.Partition == "ca" {
			pt1 = pt
		}
	}
	for _, pt := range g2.Partitions {
		if pt.Partition == "ca" {
			pt2 = pt
		}
	}
	if pt2.Size != pt1.Size+4 {
		t.Fatalf("追加后大小 %d，期望 %d", pt2.Size, pt1.Size+4)
	}
	for i, seq := range pt1.LeafSeq {
		if pt2.LeafSeq[i] != seq {
			t.Fatalf("旧叶子第 %d 项未保持前缀", i)
		}
	}
	r, err := reader.Open(dir, kr, g2.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Verify(); len(p) != 0 {
		t.Fatalf("读端前缀重算复验: %v", p)
	}
	// 旧代固定视图仍然有效。
	old, err := reader.Open(dir, kr, g1.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if p := old.Verify(); len(p) != 0 {
		t.Fatalf("旧代复验: %v", p)
	}
}

// 崩溃屏障：三个注入点分别验证“未发布/回执未写/指针未翻转”的恢复语义。
func TestCrashBarriersAndForwardRecovery(t *testing.T) {
	cases := []struct {
		name      string
		point     string
		wantGen   int    // 恢复后 CURRENT
		repairHit string // 期望出现的恢复动作前缀
	}{
		{"清单临时文件后", store.CrashAfterManifestTemp, 0, "remove-stale-tmp"},
		{"改名后回执前", store.CrashAfterRenameBeforeReceipt, 1, "write-missing-receipt-gen-1"},
		{"回执后指针前", store.CrashAfterReceiptBeforeCurrent, 1, "repair-current"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, kr := t.TempDir(), testKeyring(t)
			s := mustOpen(t, dir, kr, store.Options{CrashPoint: tc.point})
			e := ev("A1", "d", 5, "src", 1, 1)
			if _, err := s.Ingest("ca", e, sign(t, kr, e)); err != nil {
				t.Fatal(err)
			}
			_, err := s.Publish(1000)
			if !errors.Is(err, store.ErrCrashInjected) {
				t.Fatalf("期望注入崩溃，实际 %v", err)
			}
			// 模拟进程死亡：释放锁（不经过正常 Close 的其余路径也可，这里显式释放）。
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if cur, _ := store.ReadCurrent(dir); cur != 0 && tc.wantGen == 0 {
				t.Fatal("临时文件阶段崩溃后不应存在 CURRENT")
			}
			// 新进程打开：前向恢复。
			s2 := mustOpen(t, dir, kr, store.Options{})
			hit := false
			for _, a := range s2.RepairedActions() {
				if startsWith(a, tc.repairHit) {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("恢复动作中未找到 %q，实际 %v", tc.repairHit, s2.RepairedActions())
			}
			if s2.CurrentGeneration() != tc.wantGen {
				t.Fatalf("恢复后代次 %d，期望 %d", s2.CurrentGeneration(), tc.wantGen)
			}
			// 再发布一代并完整复验，证明恢复后系统继续可用。
			m, err := s2.Publish(2000)
			if err != nil {
				t.Fatal(err)
			}
			if err := s2.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := reader.Open(dir, kr, m.Generation)
			if err != nil {
				t.Fatal(err)
			}
			if p := r.Verify(); len(p) != 0 {
				t.Fatalf("恢复后代复验: %v", p)
			}
			// 崩溃发生在改名后的场景：第一代清单与补签回执必须仍然有效。
			if tc.wantGen == 1 {
				if _, err := os.Stat(filepath.Join(dir, "gen-1.json")); err != nil {
					t.Fatal("第一代清单丢失")
				}
				if _, err := os.Stat(filepath.Join(dir, "receipts", "gen-1.rcpt")); err != nil {
					t.Fatal("补签回执未落盘")
				}
			}
		})
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
