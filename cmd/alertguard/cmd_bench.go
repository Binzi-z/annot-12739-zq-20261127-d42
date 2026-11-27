package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"example.invalid/local-fixture/internal/event"
	"example.invalid/local-fixture/internal/merkle"
	"example.invalid/local-fixture/internal/reader"
	"example.invalid/local-fixture/internal/store"
)

// BenchResult 是十万条跨分区共享来源基准的机器可读结果。
type BenchResult struct {
	EventsTotal        int    `json:"events_total"`
	Partitions         int    `json:"partitions"`
	SharedSources      int    `json:"shared_sources"`
	IngestMillis       int64  `json:"ingest_ms"`
	PublishGen1Millis  int64  `json:"publish_gen1_ms"`
	RollbackPartition  string `json:"rollback_partition"`
	RollbackToSeq      uint64 `json:"rollback_to_seq"`
	PublishGen2Millis  int64  `json:"publish_gen2_ms"`
	ReaderVerifyMillis int64  `json:"reader_verify_ms"`
	ReaderAllocBytes   uint64 `json:"reader_total_alloc_bytes"`
	ReaderLiveHeap     uint64 `json:"reader_live_heap_bytes"`
	ReaderHeapObjects  uint64 `json:"reader_heap_objects"`
	// 回滚前第一代读端指标，用于量化局部回滚对读取路径/内存的影响。
	ReaderGen1Millis   int64  `json:"reader_gen1_verify_ms"`
	ReaderGen1LiveHeap uint64 `json:"reader_gen1_live_heap_bytes"`
	Gen1TreeLeaves     int    `json:"gen1_tree_leaves"`
	Gen2TreeLeaves     int    `json:"gen2_tree_leaves"`
	Gen1RootCount      int    `json:"gen1_root_count"`
	Gen2RootCount      int    `json:"gen2_root_count"`
	UnrelatedRootSame  bool   `json:"unrelated_partition_root_unchanged"`
	RolledRootChanged  bool   `json:"rolled_partition_root_changed"`
	FullFactMatch      bool   `json:"full_fact_replay_match"`
	LogRecordsTotal    int    `json:"log_records_total"`
	TreeLeavesTotal    int    `json:"tree_leaves_total"`
	Notes              string `json:"notes"`
}

// runBench 在临时目录内构建十万条事件（跨分区共享来源），
// 实测局部回滚对读取路径耗时、内存与无关分区的影响，并与全量重放事实对照。
func runBench(args []string) {
	fs := flagSet("bench")
	dir := fs.String("dir", "", "基准存储目录（建议空目录）")
	total := fs.Int("events", 100000, "事件总数")
	partitions := fs.Int("partitions", 4, "分区数（采集进程）")
	sources := fs.Int("sources", 2, "跨分区共享来源数")
	rollbackPct := fs.Int("rollback-pct", 10, "被回滚分区后缀百分比")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("bench 需要 -dir"))
	}
	if err := initStore(*dir); err != nil {
		fail(err)
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	res := &BenchResult{EventsTotal: *total, Partitions: *partitions, SharedSources: *sources}

	// 1) 生成并签注、摄入：各分区共享同一组来源（source 跨分区复用）。
	const batchSize = 2000
	const highThreshold = 9
	t0 := time.Now()
	perPart := *total / *partitions
	// 跨分区共享告警号空间：每分区出现相同 ID 集合，制造大量跨分区折叠；
	// 仅约 10% 为高优（优先级 9），其余为低优，避免清单证书爆炸。
	const idSpace = 2500
	wm := int64(0)
	for p := 0; p < *partitions; p++ {
		partName := fmt.Sprintf("collector-%c", 'a'+p)
		s, err := store.Open(*dir, kr, store.Options{HighPriorityThreshold: highThreshold})
		if err != nil {
			fail(err)
		}
		var batch []store.IngestItem
		flush := func() {
			if len(batch) == 0 {
				return
			}
			if _, err := s.IngestBatch(partName, batch); err != nil {
				_ = s.Close()
				fail(err)
			}
			batch = batch[:0]
		}
		for i := 0; i < perPart; i++ {
			wm++
			id := fmt.Sprintf("alert-%06d", i%idSpace)
			digest := digestFor(i, id)
			// 周期性制造同号异摘要冲突（约每 1000 条一个冲突点）。
			if i%997 == 3 {
				digest = digestFor(i+700000, id+"-variant")
			}
			prio := 1 + (i % 8) // 1..8：全部低于高优阈值 9
			if i%10 == 0 {
				prio = highThreshold // 约 10% 高优
			}
			e := event.Event{
				AlertID:     id,
				Digest:      digest,
				Priority:    prio,
				Source:      fmt.Sprintf("source-%d", i%*sources), // 来源跨分区共享
				Endorsement: 1,
				ReceivedAt:  wm,
				Payload:     fmt.Sprintf("part=%s seq=%d", partName, i),
			}
			sig, err := kr.SignEvent(e)
			if err != nil {
				_ = s.Close()
				fail(err)
			}
			batch = append(batch, store.IngestItem{Event: e, Signature: sig})
			if len(batch) == batchSize {
				flush()
			}
		}
		flush()
		if err := s.Close(); err != nil {
			fail(err)
		}
	}
	res.IngestMillis = time.Since(t0).Milliseconds()

	// 2) 第一代发布（回滚前全量事实）。
	var gen1 *store.Manifest
	t0 = time.Now()
	func() {
		s, err := store.Open(*dir, kr, store.Options{HighPriorityThreshold: highThreshold})
		if err != nil {
			fail(err)
		}
		defer s.Close()
		gen1, err = s.Publish(1000)
		if err != nil {
			fail(err)
		}
	}()
	res.PublishGen1Millis = time.Since(t0).Milliseconds()
	res.Gen1RootCount = len(gen1.Roots)

	// 3) 对一个分区做局部回滚：剔除后缀，其余分区不动。
	rbPart := gen1.Partitions[0].Partition
	fullSize := gen1.Partitions[0].Size
	toSeq := uint64(fullSize * (100 - *rollbackPct) / 100)
	s, err := store.Open(*dir, kr, store.Options{HighPriorityThreshold: highThreshold})
	if err != nil {
		fail(err)
	}
	if _, err := s.RollbackPartition(rbPart, toSeq, "bench 局部回滚", 2000); err != nil {
		fail(err)
	}
	res.RollbackPartition, res.RollbackToSeq = rbPart, toSeq

	// 4) 第二代发布。
	t0 = time.Now()
	gen2, err := s.Publish(2001)
	if err != nil {
		fail(err)
	}
	res.PublishGen2Millis = time.Since(t0).Milliseconds()
	if err := s.Close(); err != nil {
		fail(err)
	}
	res.Gen2RootCount = len(gen2.Roots)

	// 5) 无关分区根不变、被回滚分区根变化。
	var gen1Root, gen2Root, unrelated1, unrelated2 string
	for _, pt := range gen1.Partitions {
		if pt.Partition == rbPart {
			gen1Root = pt.RootHex
		} else if unrelated1 == "" {
			unrelated1 = pt.RootHex
			unrelatedPart := pt.Partition
			for _, q := range gen2.Partitions {
				if q.Partition == unrelatedPart {
					unrelated2 = q.RootHex
				}
			}
		}
	}
	for _, pt := range gen2.Partitions {
		if pt.Partition == rbPart {
			gen2Root = pt.RootHex
		}
	}
	res.UnrelatedRootSame = unrelated1 != "" && unrelated1 == unrelated2
	res.RolledRootChanged = gen1Root != gen2Root

	// 6) 独立读端：回滚前（gen1）与回滚后（gen2）分别测量读取路径与内存。
	// TotalAlloc 为累计分配（含已回收）；HeapAlloc 为读端存活堆，反映实际驻留。
	measure := func(gen int) (ms int64, totalAlloc, liveHeap uint64, problems []string) {
		runtime.GC()
		debug.FreeOSMemory() // 让 HeapAlloc 只反映本代读端的真实驻留
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		r, err := reader.Open(*dir, kr, gen)
		if err != nil {
			fail(err)
		}
		problems = r.Verify()
		ms = time.Since(start).Milliseconds()
		runtime.ReadMemStats(&after)
		totalAlloc = after.TotalAlloc - before.TotalAlloc
		liveHeap = after.HeapAlloc
		return
	}
	gen1Ms, _, gen1Heap, gen1Problems := measure(gen1.Generation)
	if len(gen1Problems) != 0 {
		fail(fmt.Errorf("回滚前代独立复验失败: %v", gen1Problems))
	}
	res.ReaderGen1Millis, res.ReaderGen1LiveHeap = gen1Ms, gen1Heap
	res.Gen1TreeLeaves = totalLeaves(gen1)
	res.Gen2TreeLeaves = totalLeaves(gen2)
	gen2Ms, gen2Alloc, gen2Heap, gen2Problems := measure(gen2.Generation)
	res.ReaderVerifyMillis, res.ReaderAllocBytes, res.ReaderLiveHeap = gen2Ms, gen2Alloc, gen2Heap
	if len(gen2Problems) != 0 {
		fail(fmt.Errorf("基准代独立复验失败: %v", gen2Problems))
	}

	// 7) 全量事实对照：独立重放分区日志，逐叶哈希重建，与清单承诺完全一致。
	res.FullFactMatch, res.LogRecordsTotal, res.TreeLeavesTotal = checkFullFacts(*dir, gen2)
	if !res.FullFactMatch {
		res.Notes = "全量重放与清单承诺不一致"
	} else {
		res.Notes = fmt.Sprintf("回滚仅作用于 %s；日志记录 %d 条全部保留，代树叶子 %d 个",
			rbPart, res.LogRecordsTotal, res.TreeLeavesTotal)
	}
	printJSON(res)
}

func digestFor(i int, salt string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", salt, i)))
	return hex.EncodeToString(sum[:16])
}

func totalLeaves(m *store.Manifest) int {
	n := 0
	for _, pt := range m.Partitions {
		n += pt.Size
	}
	return n
}

// checkFullFacts 不依赖 store/reader 的内部结论，直接顺序重放日志做独立对照。
func checkFullFacts(dir string, m *store.Manifest) (bool, int, int) {
	logTotal, treeTotal := 0, 0
	wmByPart := map[string]uint64{}
	for _, rb := range m.Rollbacks {
		wmByPart[rb.Partition] = rb.ToSeq
	}
	ok := true
	for _, pt := range m.Partitions {
		recs, err := readPartitionLog(dir, pt.Partition)
		if err != nil {
			return false, 0, 0
		}
		logTotal += len(recs)
		wm := wmByPart[pt.Partition]
		var hashes [][]byte
		for _, env := range recs {
			if wm > 0 && env.LogSeq >= wm {
				continue
			}
			hashes = append(hashes, env.LeafHash())
		}
		treeTotal += len(hashes)
		if len(hashes) != pt.Size {
			ok = false
		}
		if hex.EncodeToString(merkle.RootFromHashes(hashes)) != pt.RootHex {
			ok = false
		}
	}
	return ok, logTotal, treeTotal
}
