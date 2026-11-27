package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// recoverPublishes 在持锁打开时完成未竟发布的前向恢复：
//  1. 清理所有 *.tmp 残留（清单/指针均未完成原子改名）；
//  2. 对每个已改名但缺回执的清单补签回执（“合并完成而回执未写”）；
//  3. 校验/重算 CURRENT，使其只指向“清单与回执均有效”的最高代；
//  4. 全程不触碰任何分区/控制日志记录——已承诺原始前缀永不丢弃。
func (s *Store) recoverPublishes() error {
	// 1) 临时文件残留。
	tmpMatches, err := filepath.Glob(filepath.Join(s.dir, "*.tmp"))
	if err != nil {
		return err
	}
	for _, t := range tmpMatches {
		if err := os.Remove(t); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.repaired = append(s.repaired, "remove-stale-tmp:"+filepath.Base(t))
	}
	genRe := regexp.MustCompile(`^gen-(\d+)\.json$`)
	matches, err := filepath.Glob(filepath.Join(s.dir, "gen-*.json"))
	if err != nil {
		return err
	}
	type genFile struct {
		gen  int
		path string
	}
	var gens []genFile
	for _, m := range matches {
		sub := genRe.FindStringSubmatch(filepath.Base(m))
		if sub == nil {
			continue // 跳过 .tmp 等
		}
		n, err := strconv.Atoi(sub[1])
		if err != nil {
			return fmt.Errorf("代文件名非法 %s: %w", m, err)
		}
		gens = append(gens, genFile{n, m})
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i].gen < gens[j].gen })

	committed := 0
	for _, gf := range gens {
		m, err := ReadManifest(s.dir, gf.gen)
		if err != nil {
			// 清单本体损坏：不删除（保留现场），但不承认其为已提交代。
			s.repaired = append(s.repaired, fmt.Sprintf("ignore-unreadable-gen-%d", gf.gen))
			continue
		}
		rcptPath := filepath.Join(s.dir, "receipts", fmt.Sprintf("gen-%d.rcpt", gf.gen))
		raw, err := os.ReadFile(rcptPath)
		needReceipt := false
		if os.IsNotExist(err) {
			needReceipt = true
		} else if err != nil {
			return err
		} else {
			var rcpt Receipt
			if jerr := json.Unmarshal(raw, &rcpt); jerr != nil ||
				rcpt.ManifestHex != m.DigestHex() ||
				s.kr.VerifyRevocation(m.Digest(), rcpt.Signature) != nil {
				needReceipt = true // 回执损坏或与清单不符，重签
				s.repaired = append(s.repaired, fmt.Sprintf("replace-invalid-receipt-gen-%d", gf.gen))
			}
		}
		if needReceipt {
			rcpt := &Receipt{
				Generation:  gf.gen,
				ManifestHex: m.DigestHex(),
				IssuedAt:    m.PublishedAt,
				Signature:   s.kr.SignRevocation(m.Digest()),
			}
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
			s.repaired = append(s.repaired, fmt.Sprintf("write-missing-receipt-gen-%d", gf.gen))
		}
		committed = gf.gen // 代序号单调，最高有效代即当前代
	}

	// 3) CURRENT 与事实不符则重算并原子翻转。
	if committed != s.current {
		curTmp := filepath.Join(s.dir, "CURRENT.tmp")
		if err := os.WriteFile(curTmp, []byte(fmt.Sprintf("%d\n", committed)), 0o600); err != nil {
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
		s.repaired = append(s.repaired, fmt.Sprintf("repair-current:%d->%d", s.current, committed))
		s.current = committed
	}
	return nil
}

// ReadManifest 读取指定代的不可变清单（不校验回执；校验由 Reader 完成）。
func ReadManifest(dir string, generation int) (*Manifest, error) {
	path := filepath.Join(dir, fmt.Sprintf("gen-%d.json", generation))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("代 %d 清单解析失败: %w", generation, err)
	}
	if m.Generation != generation {
		return nil, fmt.Errorf("代 %d 清单内部代次为 %d", generation, m.Generation)
	}
	return &m, nil
}

// ReadReceipt 读取某代回执。
func ReadReceipt(dir string, generation int) (*Receipt, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "receipts", fmt.Sprintf("gen-%d.rcpt", generation)))
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListGenerations 返回磁盘上存在的全部代序号（升序），不论是否已提交。
func ListGenerations(dir string) ([]int, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "gen-*.json"))
	if err != nil {
		return nil, err
	}
	genRe := regexp.MustCompile(`^gen-(\d+)\.json$`)
	var out []int
	for _, m := range matches {
		if sub := genRe.FindStringSubmatch(filepath.Base(m)); sub != nil {
			n, _ := strconv.Atoi(sub[1])
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out, nil
}

// ReadCurrent 读取 CURRENT 指针；不存在返回 0。
func ReadCurrent(dir string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "CURRENT"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &n); err != nil {
		return 0, fmt.Errorf("CURRENT 指针损坏: %w", err)
	}
	return n, nil
}
