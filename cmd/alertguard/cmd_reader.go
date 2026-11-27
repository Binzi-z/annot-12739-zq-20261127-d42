package main

import (
	"fmt"
	"time"

	"example.invalid/local-fixture/internal/reader"
	"example.invalid/local-fixture/internal/store"
)

// runReader 独立读端：打开时固定代次（默认 CURRENT），输出根/折叠/冲突摘要。
// -watch 模式下保持长驻，周期性重开仍固定旧代，用于“旧读者仍固定旧代”复测。
func runReader(args []string) {
	fs := flagSet("reader")
	dir := fs.String("dir", "", "存储目录")
	pin := fs.Int("pin", 0, "固定代次（0=打开时的 CURRENT）")
	watch := fs.Duration("watch", 0, "长驻观察间隔（如 200ms）；为 0 则输出一次退出")
	rounds := fs.Int("rounds", 1, "watch 模式重开轮数")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("reader 需要 -dir"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	r, err := reader.Open(*dir, kr, *pin)
	if err != nil {
		fail(err)
	}
	printReaderView(r)
	for i := 1; i < *rounds && *watch > 0; i++ {
		time.Sleep(*watch)
		// 长驻读者不重新解析 CURRENT：仍用首次固定的代次打开，模拟旧读者。
		again, err := reader.Open(*dir, kr, r.Pinned())
		if err != nil {
			fail(err)
		}
		printReaderView(again)
	}
}

func printReaderView(r *reader.Reader) {
	c, _ := r.MinimalCertificate()
	out := struct {
		Pinned         int                 `json:"pinned_generation"`
		Summary        string              `json:"summary"`
		ManifestDigest string              `json:"manifest_digest"`
		Roots          []store.RootEntry   `json:"roots"`
		Folded         []store.FoldedEntry `json:"folded"`
		Conflicts      []store.Conflict    `json:"conflicts"`
		Earliest       *store.Conflict     `json:"earliest_conflict,omitempty"`
		RevokedPrefix  []store.RevokedRef  `json:"revoked_prefixes"`
		Quarantined    []store.EnvelopeRef `json:"quarantined"`
	}{
		Pinned: r.Pinned(), Summary: r.Summary(), ManifestDigest: r.ManifestDigest(),
		Roots: r.Roots(), Folded: r.Folded(), Conflicts: r.Conflicts(),
		Earliest: c, RevokedPrefix: r.RevokedPrefixes(), Quarantined: r.Quarantined(),
	}
	printJSON(out)
}

// runVerify 独立复验固定代全部承诺，输出问题清单；无问题退出码 0。
func runVerify(args []string) {
	fs := flagSet("verify")
	dir := fs.String("dir", "", "存储目录")
	pin := fs.Int("pin", 0, "固定代次（0=CURRENT）")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("verify 需要 -dir"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	r, err := reader.Open(*dir, kr, *pin)
	if err != nil {
		fail(err)
	}
	problems := r.Verify()
	printJSON(struct {
		Pinned   int      `json:"pinned_generation"`
		OK       bool     `json:"ok"`
		Problems []string `json:"problems"`
	}{r.Pinned(), len(problems) == 0, problems})
	if len(problems) > 0 {
		osExit(4)
	}
}

// runConflicts 只输出最早已证冲突与其最少证书。
func runConflicts(args []string) {
	fs := flagSet("conflicts")
	dir := fs.String("dir", "", "存储目录")
	pin := fs.Int("pin", 0, "固定代次（0=CURRENT）")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("conflicts 需要 -dir"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	r, err := reader.Open(*dir, kr, *pin)
	if err != nil {
		fail(err)
	}
	c, err := r.MinimalCertificate()
	if err != nil {
		fail(err)
	}
	if c == nil {
		printJSON(struct {
			Earliest any `json:"earliest_conflict"`
		}{nil})
		return
	}
	printJSON(struct {
		Pinned              int             `json:"pinned_generation"`
		Conflict            *store.Conflict `json:"earliest_conflict"`
		CertificateVerified bool            `json:"certificate_verified"`
	}{r.Pinned(), c, true})
}
