package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"example.invalid/local-fixture/internal/log"
	"example.invalid/local-fixture/internal/store"
)

func readPartitionLog(dir, partition string) ([]store.Envelope, error) {
	path := filepath.Join(dir, "part-"+partition+".log")
	recs, err := log.ReadAll(path)
	if err != nil {
		return nil, err
	}
	out := make([]store.Envelope, 0, len(recs))
	for _, rec := range recs {
		var env store.Envelope
		if err := json.Unmarshal(rec.Body, &env); err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		osExit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "init":
		runInit(args)
	case "addkey":
		runAddKey(args)
	case "collect":
		runCollect(args)
	case "ingest":
		runIngest(args)
	case "publish":
		runPublish(args)
	case "revoke":
		runRevoke(args)
	case "rollback":
		runRollback(args)
	case "reader":
		runReader(args)
	case "verify":
		runVerify(args)
	case "conflicts":
		runConflicts(args)
	case "bench":
		runBench(args)
	case "holdlock":
		runHoldLock(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n", cmd)
		usage()
		osExit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `alertguard — 离线合成告警合并、持久化索引与独立读端（仅 Go 标准库）

用法: alertguard <子命令> [参数]
  init      -dir <目录>                              初始化存储与钥匙环
  addkey    -dir <目录> -version <代次>              增加签注代次（旧代密钥保留）
  collect   -dir -in <事件.jsonl> -out <签名.jsonl>  采集进程签注
  ingest    -dir -partition <分区> -in <签名.jsonl>  合并写入分区日志
  publish   -dir [-high-threshold N] [-crash-point 屏障]  发布新一代清单
  revoke    -dir -alert <号> -endorsement <代次> [-reason] 撤回签注（原始前缀保留）
  rollback  -dir -partition <分区> -to-seq <水位> [-reason] 分区局部回滚标签
  reader    -dir [-pin 代次] [-watch 间隔 -rounds N] 独立读端（默认固定 CURRENT）
  verify    -dir [-pin 代次]                          独立复验全部承诺
  conflicts -dir [-pin 代次]                          最早已证冲突与最少证书
  bench     -dir [-events N -partitions N -sources N -rollback-pct N] 基准
`)
}
