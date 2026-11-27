package main

import (
	"fmt"
	"os"

	"example.invalid/local-fixture/internal/store"
)

// runIngest 合并写端：把某采集进程的带签名事件摄入指定分区日志。
// 同一目录同时只允许一个写端（跨进程排他锁，第二进程直接失败）。
func runIngest(args []string) {
	fs := flagSet("ingest")
	dir := fs.String("dir", "", "存储目录")
	partition := fs.String("partition", "", "采集分区名（如 collector-a）")
	in := fs.String("in", "", "带签名事件 JSONL")
	mustParse(fs, args)
	if *dir == "" || *partition == "" || *in == "" {
		fail(fmt.Errorf("ingest 需要 -dir -partition -in"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	events, err := readSignedEvents(*in)
	if err != nil {
		fail(err)
	}
	s, err := store.Open(*dir, kr, store.Options{})
	if err != nil {
		fail(err)
	}
	defer s.Close()
	var accepted, quarantined int
	for _, se := range events {
		env, err := s.Ingest(*partition, se.Event, se.Signature)
		if err != nil {
			fail(err)
		}
		if env.Valid {
			accepted++
		} else {
			quarantined++
		}
	}
	fmt.Printf("分区 %s 摄入 %d 条（真实签名 %d，隔离 %d）\n",
		*partition, len(events), accepted, quarantined)
}

// runPublish 依据当前持久化事实发布新一代清单。
func runPublish(args []string) {
	fs := flagSet("publish")
	dir := fs.String("dir", "", "存储目录")
	threshold := fs.Int("high-threshold", 8, "高优阈值：达到该优先级的折叠项带完整证书")
	crashPoint := fs.String("crash-point", "", "崩溃注入点（测试用）")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("publish 需要 -dir"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	s, err := store.Open(*dir, kr, store.Options{HighPriorityThreshold: *threshold, CrashPoint: *crashPoint})
	if err != nil {
		fail(err)
	}
	defer s.Close()
	m, err := s.Publish(0)
	if err != nil {
		if err == store.ErrCrashInjected {
			fmt.Fprintf(os.Stderr, "已在屏障 %s 注入崩溃（进程退出，未翻转 CURRENT）\n", *crashPoint)
			osExit(3)
		}
		fail(err)
	}
	fmt.Printf("已发布代 %d: %s\n", m.Generation, summaryOf(m))
	if acts := s.RepairedActions(); len(acts) > 0 {
		fmt.Println("前向恢复动作:")
		for _, a := range acts {
			fmt.Println("  -", a)
		}
	}
}

// runRevoke 撤回某告警的指定签注代次；原始记录保留。
func runRevoke(args []string) {
	fs := flagSet("revoke")
	dir := fs.String("dir", "", "存储目录")
	alertID := fs.String("alert", "", "告警号")
	version := fs.Int("endorsement", 0, "被撤回的签注代次")
	reason := fs.String("reason", "", "撤回原因")
	mustParse(fs, args)
	if *dir == "" || *alertID == "" || *version <= 0 {
		fail(fmt.Errorf("revoke 需要 -dir -alert -endorsement"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	s, err := store.Open(*dir, kr, store.Options{})
	if err != nil {
		fail(err)
	}
	defer s.Close()
	rev, err := s.Revoke(*alertID, *version, *reason, 0)
	if err != nil {
		fail(err)
	}
	fmt.Printf("已登记撤回控制记录 %d: alert=%s endorsement=%d（原始前缀保留）\n",
		rev.ControlSeq, rev.AlertID, rev.Endorsement)
}

// runRollback 对单个分区追加局部回滚标签（不删除任何日志字节）。
func runRollback(args []string) {
	fs := flagSet("rollback")
	dir := fs.String("dir", "", "存储目录")
	partition := fs.String("partition", "", "被回滚分区")
	toSeq := fs.Uint("to-seq", 0, "回滚水位（排他）：日志序 >= 该值的记录剔出代树")
	reason := fs.String("reason", "", "回滚原因")
	mustParse(fs, args)
	if *dir == "" || *partition == "" {
		fail(fmt.Errorf("rollback 需要 -dir -partition -to-seq"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	s, err := store.Open(*dir, kr, store.Options{})
	if err != nil {
		fail(err)
	}
	defer s.Close()
	rb, err := s.RollbackPartition(*partition, uint64(*toSeq), *reason, 0)
	if err != nil {
		fail(err)
	}
	fmt.Printf("已登记回滚控制记录 %d: 分区 %s 水位 -> %d（原始日志保留）\n",
		rb.ControlSeq, rb.Partition, rb.ToSeq)
}

func summaryOf(m *store.Manifest) string {
	return fmt.Sprintf("roots=%d folded=%d conflicts=%d quarantined=%d revoked=%d rollbacks=%d control=%d",
		len(m.Roots), len(m.Folded), len(m.Conflicts),
		len(m.Quarantined), len(m.RevokedRefs), len(m.Rollbacks), m.ControlSize)
}
