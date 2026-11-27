package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"example.invalid/local-fixture/internal/event"
)

// runCollect 模拟采集进程：读取未签注事件 JSONL，用钥匙环中对应代次密钥
// 逐条计算真实 HMAC，输出带签名 JSONL。它不触碰写端目录锁。
func runCollect(args []string) {
	fs := flagSet("collect")
	dir := fs.String("dir", "", "存储目录（取钥匙环）")
	in := fs.String("in", "", "未签注事件 JSONL")
	out := fs.String("out", "", "带签名事件 JSONL 输出路径")
	mustParse(fs, args)
	if *dir == "" || *in == "" || *out == "" {
		fail(fmt.Errorf("collect 需要 -dir -in -out"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	f, err := os.Open(*in)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	of, err := os.Create(*out)
	if err != nil {
		fail(err)
	}
	defer of.Close()
	w := bufio.NewWriter(of)
	defer w.Flush()
	enc := json.NewEncoder(w)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	n := 0
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e event.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			fail(fmt.Errorf("第 %d 条事件解析失败: %w", n+1, err))
		}
		if err := e.Validate(); err != nil {
			fail(err)
		}
		sig, err := kr.SignEvent(e)
		if err != nil {
			fail(err)
		}
		if err := enc.Encode(signedEvent{Event: e, Signature: sig}); err != nil {
			fail(err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		fail(err)
	}
	fmt.Printf("采集签注完成: %d 条 -> %s\n", n, *out)
}
