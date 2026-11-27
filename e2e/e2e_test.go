// Package e2e 通过真实子进程驱动编译出的 alertguard 二进制，
// 复测题面要求的四个跨进程/崩溃场景以及跨进程排他锁。
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "alertguard-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "alertguard")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	// 测试 cwd 是模块根下的 e2e/，模块根即上一级。
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	moduleRoot := filepath.Dir(wd)
	build := exec.Command("go", "build", "-o", binPath, "./cmd/alertguard")
	build.Dir = moduleRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "构建失败: %v\n%s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type procResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func run(t *testing.T, args ...string) procResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("启动进程失败: %v", err)
		}
	}
	return procResult{exitCode: code, stdout: out.String(), stderr: errBuf.String()}
}

func writeEvents(t *testing.T, path string, events []map[string]any) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
}

func evt(id, digest string, prio int, source string, endorsement int, watermark int64) map[string]any {
	return map[string]any{
		"alert_id": id, "digest": digest, "priority": prio, "source": source,
		"endorsement": endorsement, "received_at": watermark,
	}
}

func mustSucceed(t *testing.T, r procResult, ctx string) {
	t.Helper()
	if r.exitCode != 0 {
		t.Fatalf("%s 失败 exit=%d\nstdout=%s\nstderr=%s", ctx, r.exitCode, r.stdout, r.stderr)
	}
}

// 两个采集进程分别签注并摄入，发布后独立复验。
func TestTwoCollectorsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")

	aEvents := filepath.Join(dir, "a.jsonl")
	bEvents := filepath.Join(dir, "b.jsonl")
	writeEvents(t, aEvents, []map[string]any{
		evt("A1", "dig-1", 9, "source-1", 1, 100),
		evt("A1", "dig-1", 4, "source-1", 1, 110),
	})
	writeEvents(t, bEvents, []map[string]any{
		evt("A1", "dig-1", 8, "source-2", 1, 105),
		evt("A2", "dig-2", 2, "source-2", 1, 120),
	})
	aSigned, bSigned := filepath.Join(dir, "a.sig.jsonl"), filepath.Join(dir, "b.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", aEvents, "-out", aSigned), "collect-a")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", bEvents, "-out", bSigned), "collect-b")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "collector-a", "-in", aSigned), "ingest-a")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "collector-b", "-in", bSigned), "ingest-b")
	pub := run(t, "publish", "-dir", dir)
	mustSucceed(t, pub, "publish")
	if !strings.Contains(pub.stdout, "roots=2") {
		t.Fatalf("根计数错误: %s", pub.stdout)
	}
	verify := run(t, "verify", "-dir", dir)
	mustSucceed(t, verify, "verify")
	if !strings.Contains(verify.stdout, `"ok": true`) {
		t.Fatalf("复验未通过: %s", verify.stdout)
	}
	reader := run(t, "reader", "-dir", dir)
	mustSucceed(t, reader, "reader")
	if !strings.Contains(reader.stdout, `"pinned_generation": 1`) {
		t.Fatalf("读端代次错误: %s", reader.stdout)
	}
}

// 晚到撤销：第一代发布后另起进程撤回签注，第二代失去根资格，
// 但固定第一代的旧读者视图不变，且原始记录仍在。
func TestLateRevocationAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	raw := filepath.Join(dir, "e.jsonl")
	writeEvents(t, raw, []map[string]any{evt("A1", "dig", 9, "src", 1, 100)})
	signed := filepath.Join(dir, "e.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")
	mustSucceed(t, run(t, "publish", "-dir", dir), "publish-gen1")

	// 晚到撤销由独立进程写入控制日志。
	mustSucceed(t, run(t, "revoke", "-dir", dir, "-alert", "A1", "-endorsement", "1", "-reason", "旧版撤回"), "revoke")
	mustSucceed(t, run(t, "publish", "-dir", dir), "publish-gen2")

	old := run(t, "reader", "-dir", dir, "-pin", "1")
	mustSucceed(t, old, "reader-pin1")
	oldView := parseView(t, old.stdout)
	if oldView.Pinned != 1 || !rootContains(oldView.Roots, "A1") {
		t.Fatalf("旧读者视图被撤销改写: %s", old.stdout)
	}
	newReader := run(t, "reader", "-dir", dir)
	mustSucceed(t, newReader, "reader-current")
	newView := parseView(t, newReader.stdout)
	if newView.Pinned != 2 {
		t.Fatalf("新读者代次错误: %s", newReader.stdout)
	}
	if rootContains(newView.Roots, "A1") {
		t.Fatalf("撤销后根仍存在: %s", newReader.stdout)
	}
	if len(newView.RevokedPrefixes) != 1 || newView.RevokedPrefixes[0].AlertID != "A1" {
		t.Fatalf("缺少撤回前缀定位: %s", newReader.stdout)
	}
	// 两代独立复验均通过，且原始日志未删除。
	mustSucceed(t, run(t, "verify", "-dir", dir, "-pin", "1"), "verify-gen1")
	mustSucceed(t, run(t, "verify", "-dir", dir, "-pin", "2"), "verify-gen2")
	partLog := filepath.Join(dir, "part-ca.log")
	if info, err := os.Stat(partLog); err != nil || info.Size() == 0 {
		t.Fatal("原始分区日志丢失或为空")
	}
}

// 同号异摘要：独立进程复核最早已证冲突与最少证书。
func TestSameIDDifferentDigestAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	raw := filepath.Join(dir, "e.jsonl")
	writeEvents(t, raw, []map[string]any{
		evt("A9", "dig-X", 7, "src-1", 1, 100),
		evt("A9", "dig-Y", 7, "src-2", 1, 200),
	})
	signed := filepath.Join(dir, "e.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")
	mustSucceed(t, run(t, "publish", "-dir", dir), "publish")

	conflicts := run(t, "conflicts", "-dir", dir)
	mustSucceed(t, conflicts, "conflicts")
	if !strings.Contains(conflicts.stdout, `"certificate_verified": true`) {
		t.Fatalf("最少证书未通过复验: %s", conflicts.stdout)
	}
	if !strings.Contains(conflicts.stdout, `"alert_id": "A9"`) {
		t.Fatalf("冲突定位错误: %s", conflicts.stdout)
	}
	verify := run(t, "verify", "-dir", dir)
	mustSucceed(t, verify, "verify")
}

// 合并完成而回执未写：发布进程在屏障处死亡，新读端拒绝承认；
// 下一个写端进程前向恢复补签回执后，读端恢复且固定旧代仍可用。
func TestReceiptMissingRecoveryAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	raw := filepath.Join(dir, "e.jsonl")
	writeEvents(t, raw, []map[string]any{evt("A1", "d", 5, "src", 1, 1)})
	signed := filepath.Join(dir, "e.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")

	crashed := run(t, "publish", "-dir", dir, "-crash-point", "after-rename-before-receipt")
	if crashed.exitCode != 3 {
		t.Fatalf("崩溃进程退出码 %d，期望 3: %s", crashed.exitCode, crashed.stderr)
	}
	// 清单已落盘但回执缺失：固定代 1 的独立读端必须拒绝；CURRENT 也尚未翻转。
	blocked := run(t, "reader", "-dir", dir, "-pin", "1")
	if blocked.exitCode == 0 || !strings.Contains(blocked.stderr, "回执缺失") {
		t.Fatalf("回执未写时读端竟被承认: %+v", blocked)
	}
	if cur := run(t, "reader", "-dir", dir); cur.exitCode == 0 ||
		!strings.Contains(cur.stderr, "尚无已提交代") {
		t.Fatalf("CURRENT 不应承认未回执代: %+v", cur)
	}
	// 新写端进程打开即前向恢复，并继续发布第二代。
	recovered := run(t, "publish", "-dir", dir)
	mustSucceed(t, recovered, "recover-publish")
	if !strings.Contains(recovered.stdout, "write-missing-receipt-gen-1") {
		t.Fatalf("未观察到补签回执动作: %s", recovered.stdout)
	}
	mustSucceed(t, run(t, "verify", "-dir", dir, "-pin", "1"), "verify-gen1")
	mustSucceed(t, run(t, "verify", "-dir", dir, "-pin", "2"), "verify-gen2")
}

// 三个崩溃注入点全部由真实进程复测。
func TestAllCrashBarriersAcrossProcesses(t *testing.T) {
	cases := []struct {
		point      string
		repairText string
		canRead    bool
	}{
		{"after-manifest-temp", "remove-stale-tmp", false},
		{"after-rename-before-receipt", "write-missing-receipt", false},
		{"after-receipt-before-current", "repair-current", false},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			dir := t.TempDir()
			mustSucceed(t, run(t, "init", "-dir", dir), "init")
			raw := filepath.Join(dir, "e.jsonl")
			writeEvents(t, raw, []map[string]any{evt("A1", "d", 5, "src", 1, 1)})
			signed := filepath.Join(dir, "e.sig.jsonl")
			mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
			mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")
			crashed := run(t, "publish", "-dir", dir, "-crash-point", tc.point)
			if crashed.exitCode != 3 {
				t.Fatalf("注入崩溃退出码 %d", crashed.exitCode)
			}
			if tc.canRead {
				t.Fatal("用例数据错误")
			}
			recovered := run(t, "publish", "-dir", dir)
			mustSucceed(t, recovered, "recovery")
			if !strings.Contains(recovered.stdout, tc.repairText) {
				t.Fatalf("恢复输出缺少 %q: %s", tc.repairText, recovered.stdout)
			}
			mustSucceed(t, run(t, "verify", "-dir", dir), "verify-after-recovery")
		})
	}
}

// 旧读者固定旧代：写端连放三代，长驻读者用 -pin 1 反复打开均得到第一代事实。
func TestOldReaderPinnedAcrossGenerations(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	for gen := int64(1); gen <= 3; gen++ {
		raw := filepath.Join(dir, fmt.Sprintf("e%d.jsonl", gen))
		writeEvents(t, raw, []map[string]any{
			evt(fmt.Sprintf("A%d", gen), "d", 5, "src", 1, gen*10),
		})
		signed := filepath.Join(dir, fmt.Sprintf("e%d.sig.jsonl", gen))
		mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
		mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")
		mustSucceed(t, run(t, "publish", "-dir", dir), "publish")
	}
	watch := run(t, "reader", "-dir", dir, "-pin", "1", "-watch", "20ms", "-rounds", "3")
	mustSucceed(t, watch, "watch-reader")
	if strings.Count(watch.stdout, `"pinned_generation": 1`) != 3 {
		t.Fatalf("旧读者未持续固定第一代: %s", watch.stdout)
	}
	// 第一代清单哈希在三次输出中保持一致。
	if strings.Count(watch.stdout, firstDigest(watch.stdout)) != 3 || firstDigest(watch.stdout) == "" {
		t.Fatalf("固定代清单哈希不稳定: %s", watch.stdout)
	}
	current := run(t, "reader", "-dir", dir)
	mustSucceed(t, current, "current-reader")
	if !strings.Contains(current.stdout, `"pinned_generation": 3`) {
		t.Fatalf("新读者未读到最新代: %s", current.stdout)
	}
}

type readerView struct {
	Pinned int `json:"pinned_generation"`
	Roots  []struct {
		AlertID string `json:"alert_id"`
	} `json:"roots"`
	RevokedPrefixes []struct {
		AlertID string `json:"alert_id"`
	} `json:"revoked_prefixes"`
}

func parseView(t *testing.T, raw string) readerView {
	t.Helper()
	var v readerView
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("解析读端输出失败: %v\n%s", err, raw)
	}
	return v
}

func rootContains(roots []struct {
	AlertID string `json:"alert_id"`
}, id string) bool {
	for _, r := range roots {
		if r.AlertID == id {
			return true
		}
	}
	return false
}

func firstDigest(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, `"manifest_digest":`); i >= 0 {
			rest := line[i+len(`"manifest_digest":`):]
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, `",`)
			return rest
		}
	}
	return ""
}

// bench 命令小规模端到端：断言回滚隔离、原始记录保留与全量事实对照全部成立。
func TestBenchCommandSmallScale(t *testing.T) {
	dir := t.TempDir()
	r := run(t, "bench", "-dir", dir, "-events", "2000", "-partitions", "4", "-sources", "2", "-rollback-pct", "25")
	mustSucceed(t, r, "bench")
	var res struct {
		EventsTotal       int    `json:"events_total"`
		UnrelatedRootSame bool   `json:"unrelated_partition_root_unchanged"`
		RolledRootChanged bool   `json:"rolled_partition_root_changed"`
		FullFactMatch     bool   `json:"full_fact_replay_match"`
		LogRecordsTotal   int    `json:"log_records_total"`
		TreeLeavesTotal   int    `json:"tree_leaves_total"`
		Notes             string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil {
		t.Fatalf("解析基准输出: %v\n%s", err, r.stdout)
	}
	if res.EventsTotal != 2000 || res.LogRecordsTotal != 2000 {
		t.Fatalf("记录计数错误: %+v", res)
	}
	if res.TreeLeavesTotal >= 2000 {
		t.Fatalf("回滚后树叶子应少于日志记录: %+v", res)
	}
	if !res.UnrelatedRootSame || !res.RolledRootChanged || !res.FullFactMatch {
		t.Fatalf("基准正确性标志失败: %+v", res)
	}
}

// 篡改分区日志一个字节：独立读端必须在哈希链或树根复验处失败。
func TestTamperDetectionAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	raw := filepath.Join(dir, "e.jsonl")
	writeEvents(t, raw, []map[string]any{
		evt("A1", "d1", 5, "src", 1, 1),
		evt("A2", "d2", 5, "src", 1, 2),
	})
	signed := filepath.Join(dir, "e.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest")
	mustSucceed(t, run(t, "publish", "-dir", dir), "publish")
	mustSucceed(t, run(t, "verify", "-dir", dir), "verify-before-tamper")

	partLog := filepath.Join(dir, "part-ca.log")
	data, err := os.ReadFile(partLog)
	if err != nil {
		t.Fatal(err)
	}
	// 改写记录区靠后的一个负载字节（跳过文件头与帧头）。
	idx := len(data) - 5
	data[idx] ^= 0x01
	if err := os.WriteFile(partLog, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := run(t, "verify", "-dir", dir)
	if bad.exitCode == 0 {
		t.Fatalf("篡改后复验竟通过: %+v", bad)
	}
	combined := bad.stdout + bad.stderr
	if !strings.Contains(combined, "链哈希") && !strings.Contains(combined, "根") &&
		!strings.Contains(combined, `"ok": false`) {
		t.Fatalf("篡改未被识别为完整性错误: %+v", bad)
	}
}

// 跨进程排他锁：持锁进程存活期间，第二个写端进程必须被拒绝；锁释放后成功。
func TestCrossProcessLock(t *testing.T) {
	dir := t.TempDir()
	mustSucceed(t, run(t, "init", "-dir", dir), "init")
	holder := exec.Command(binPath, "holdlock", "-dir", dir, "-duration", "2s")
	var holdOut bytes.Buffer
	holder.Stdout, holder.Stderr = &holdOut, &holdOut
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(holdOut.String(), "locked") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(holdOut.String(), "locked") {
		t.Fatalf("持锁进程未就绪: %s", holdOut.String())
	}
	raw := filepath.Join(dir, "e.jsonl")
	writeEvents(t, raw, []map[string]any{evt("A1", "d", 5, "src", 1, 1)})
	signed := filepath.Join(dir, "e.sig.jsonl")
	mustSucceed(t, run(t, "collect", "-dir", dir, "-in", raw, "-out", signed), "collect")
	denied := run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed)
	if denied.exitCode == 0 || !strings.Contains(denied.stderr, "锁定") {
		t.Fatalf("排他锁未阻止第二个写端: %+v", denied)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("持锁进程异常: %v %s", err, holdOut.String())
	}
	// 锁释放后同一操作成功。
	mustSucceed(t, run(t, "ingest", "-dir", dir, "-partition", "ca", "-in", signed), "ingest-after-unlock")
}
