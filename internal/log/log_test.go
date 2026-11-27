package log

import (
	"path/filepath"
	"testing"
)

func TestAppendReplayChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "part.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := l.Append(uint32(1+i%2), []byte{byte(i), byte(i >> 8)}); err != nil {
			t.Fatal(err)
		}
	}
	if l.Seq() != 100 {
		t.Fatalf("Seq=%d", l.Seq())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 100 {
		t.Fatalf("读回 %d 条", len(recs))
	}
	for i, r := range recs {
		if r.Seq != uint64(i) || r.Type != uint32(1+i%2) || len(r.Body) != 2 {
			t.Fatalf("记录 %d 字段不符: %+v", i, r)
		}
	}
}

func TestTornWriteTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "part.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := l.Append(1, []byte("body-"+string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// 模拟崩溃：在文件末尾追加半帧垃圾。
	f, err := openAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x41, 0x4C, 0x47, 0x31, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// 重新打开必须裁剪残缺帧并恢复到 10 条完整记录。
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Seq() != 10 {
		t.Fatalf("裁剪后 Seq=%d，期望 10", l2.Seq())
	}
	if _, err := l2.Append(1, []byte("after-recovery")); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 11 {
		t.Fatalf("恢复后追加读回 %d 条", len(recs))
	}
}

func TestChainBreakDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "part.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(1, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// 改写一条完整帧的链哈希字节（帧头之后、记录体内部），ReadAll 必须报链断裂。
	raw, err := readBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := writeBytes(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(path); err == nil {
		t.Fatal("哈希链被破坏但未报错")
	}
}
