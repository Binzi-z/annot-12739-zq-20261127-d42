// alertguard 是离线安全值班主机上的单文件命令行：
// 采集签注（collect）、合并写端（ingest/publish/revoke/rollback）、
// 独立读端（reader/verify/conflicts）与基准（bench）共用同一二进制，
// 全部依赖 Go 标准库。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"example.invalid/local-fixture/internal/endorsement"
	"example.invalid/local-fixture/internal/event"
)

const keyringName = "keyring.json"

func loadKeyring(dir string) (*endorsement.Keyring, error) {
	return endorsement.LoadKeyring(filepath.Join(dir, keyringName))
}

// signedEvent 是采集进程与写端之间的离线交换格式（JSONL）。
type signedEvent struct {
	Event     event.Event `json:"event"`
	Signature string      `json:"signature"`
}

func readSignedEvents(path string) ([]signedEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []signedEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var se signedEvent
		if err := json.Unmarshal(raw, &se); err != nil {
			return nil, fmt.Errorf("%s 第 %d 行: %w", path, line, err)
		}
		out = append(out, se)
	}
	return out, sc.Err()
}

func writeJSONL(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(v)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}

// flagSet 构建带统一 error handling 的子命令 flag 集合。
func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func mustParse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// osExit 包装 os.Exit，便于子命令统一调用与测试替换。
func osExit(code int) { os.Exit(code) }
