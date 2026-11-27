package main

import (
	"fmt"
	"time"

	"example.invalid/local-fixture/internal/store"
)

// runHoldLock 打开写端并持锁一段时间，供跨进程锁测试：
// 第二个写端进程在此期间必须被排他锁拒绝。
func runHoldLock(args []string) {
	fs := flagSet("holdlock")
	dir := fs.String("dir", "", "存储目录")
	dur := fs.Duration("duration", 2*time.Second, "持锁时长")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("holdlock 需要 -dir"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	s, err := store.Open(*dir, kr, store.Options{})
	if err != nil {
		fail(err)
	}
	fmt.Printf("locked %s\n", *dir)
	time.Sleep(*dur)
	if err := s.Close(); err != nil {
		fail(err)
	}
	fmt.Println("unlocked")
}
