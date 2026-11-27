package store_test

import (
	"sort"
	"testing"

	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/reader"
	"example.invalid/local-fixture/internal/store"
)

type placement struct {
	event     event.Event
	partition string
}

// TestEnumerateAllFeasibleOrders 小输入枚举全部可行摄入顺序：
// 无论事件以何种顺序到达两个分区，同号摘要组、根集合、冲突裁定必须保持不变，
// 且每种顺序下独立读端复验均通过。规模：2^4 分区分配 × 4! 排列 = 384 个场景。
func TestEnumerateAllFeasibleOrders(t *testing.T) {
	kr := testKeyring(t)
	// 小输入：4 条事件覆盖同号折叠与同号异摘要冲突。
	base := []event.Event{
		ev("A1", "dig-a", 9, "src-1", 1, 10),
		ev("A1", "dig-a", 3, "src-2", 1, 20), // 同号同摘要，可折叠
		ev("A2", "dig-x", 5, "src-1", 1, 30), // 冲突第一造
		ev("A2", "dig-y", 5, "src-2", 1, 40), // 冲突第二造
	}
	// 为每条事件枚举两个分区落点（2^4 种分区分配），再对顺序做全排列（4!）。
	var assignments [][]placement
	partChoice := []string{"ca", "cb"}
	for mask := 0; mask < (1 << len(base)); mask++ {
		ps := make([]placement, len(base))
		for i := range base {
			ps[i] = placement{event: base[i], partition: partChoice[(mask>>i)&1]}
		}
		assignments = append(assignments, ps)
	}

	permute := func(n int, fn func([]int)) {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		var rec func(int)
		rec = func(k int) {
			if k == 1 {
				fn(append([]int(nil), idx...))
				return
			}
			rec(k - 1)
			for i := 0; i < k-1; i++ {
				if k%2 == 0 {
					idx[i], idx[k-1] = idx[k-1], idx[i]
				} else {
					idx[0], idx[k-1] = idx[k-1], idx[0]
				}
				rec(k - 1)
			}
		}
		rec(n)
	}

	wantRootKey := rootSignature(base)
	orders := 0
	for _, ps := range assignments {
		permute(len(ps), func(order []int) {
			orders++
			dir := t.TempDir()
			s := mustOpen(t, dir, kr, store.Options{})
			// 按分区归组后组提交，整批只付出一次 fsync 屏障。
			byPart := map[string][]store.IngestItem{}
			for _, i := range order {
				e := ps[i].event
				byPart[ps[i].partition] = append(byPart[ps[i].partition],
					store.IngestItem{Event: e, Signature: sign(t, kr, e)})
			}
			for part, items := range byPart {
				if _, err := s.IngestBatch(part, items); err != nil {
					t.Fatalf("顺序 %v: %v", order, err)
				}
			}
			m, err := s.Publish(1000)
			if err != nil {
				t.Fatalf("顺序 %v 发布: %v", order, err)
			}
			if got := rootSignatureFromManifest(m); got != wantRootKey {
				t.Fatalf("顺序 %v 根集合漂移: got=%s want=%s", order, got, wantRootKey)
			}
			if len(m.Conflicts) != 1 {
				t.Fatalf("顺序 %v 冲突数 %d", order, len(m.Conflicts))
			}
			c := m.Conflicts[0]
			if c.FirstDigest != "dig-x" || c.SecondDigest != "dig-y" {
				t.Fatalf("顺序 %v 最早冲突裁定漂移: %s/%s", order, c.FirstDigest, c.SecondDigest)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := reader.Open(dir, kr, 0)
			if err != nil {
				t.Fatal(err)
			}
			if problems := r.Verify(); len(problems) != 0 {
				t.Fatalf("顺序 %v 独立复验: %v", order, problems)
			}
		})
	}
	t.Logf("枚举可行顺序数: %d", orders)
}

// rootSignature 计算“期望根集合”的顺序无关签名：每个同号摘要组恰一个根。
func rootSignature(events []event.Event) string {
	seen := map[string]bool{}
	var keys []string
	for _, e := range events {
		k := e.AlertID + "|" + e.Digest
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += k + ";"
	}
	return out
}

func rootSignatureFromManifest(m *store.Manifest) string {
	seen := map[string]bool{}
	var keys []string
	for _, r := range m.Roots {
		k := r.AlertID + "|" + r.Event.Digest
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += k + ";"
	}
	return out
}
