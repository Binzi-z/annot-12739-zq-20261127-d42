# 告警压缩上界与回滚标签（alertguard）

离线 Windows 安全值班场景：两个采集进程分别产生带版本化签注的合成告警，
合并写端把它们持久化为**仅追加哈希链日志**，按代发布**不可变清单**；
独立读端不依赖写端内存，重放日志即可固定任一旧代并独立复验全部承诺。
**仅使用 Go 标准库**，无外部服务、无网络依赖。

题面见 `task/PROMPT.txt`，仓库自带合成输入格式检查（`fixture_test.go`）。

## 题面要求 → 实现落点

| 要求 | 实现 |
| --- | --- |
| 持久化索引与独立读端 | `internal/store`（写端，持跨进程锁）+ `internal/reader`（只读、无锁、独立重放） |
| 按优先级、历史接收水位、真实签名控制根保留最少代表 | `Publish`：同号同摘要组只留 1 个根，排序键为优先级降序 → 接收水位升序 → 分区/告警号；签名 HMAC-SHA256 逐条校验 |
| 每个被折叠高优告警可独立复验 | 高优折叠项内嵌完整事件、签名与 O(log n) Merkle 包含证明；单叶分区以“叶哈希即根”替代空证明 |
| 旧签注撤回后不丢已承诺原始前缀 | 撤回只写控制日志（独立策略密钥签名），分区记录一字不删；撤回事件仅失去根资格并登记 `revoked_refs` |
| 晚到撤销 | `revoke` 可在任意代之后到达，下代生效；旧代读者固定视图不变 |
| 同号异摘要 | 不折叠：每个不同摘要各留一个根；按接收水位裁定**最早已证冲突对**，附指向较早事件的**最少证书**（包含证明） |
| 合并完成而回执未写 | 两阶段发布 + 三崩溃屏障；读端只承认“清单+回执+CURRENT”齐备的代；重开写端前向恢复补签回执 |
| 旧读者仍固定旧代 | 每代清单持有自己的叶子定位表 `LeafSeq`；读端按该表截断重放，发布后追加/回滚均不影响旧代 |
| 最早已证冲突和最少证书 | `conflicts` 命令；`reader.MinimalCertificate()` 独立复验 |
| 小输入枚举可行顺序 | `TestEnumerateAllFeasibleOrders`：2⁴ 分区分配 × 4! 排列 = 384 个场景全枚举 |
| 十万条跨分区共享来源 + 局部回滚实测 | `bench` 命令；输出读取耗时、存活堆、无关分区根、全量事实对照 |

## 目录结构

```
cmd/alertguard/        单二进制 CLI（采集/写端/读端/基准/持锁测试命令）
internal/event/        事件与确定性规范编码（摘要只依赖规范字节）
internal/endorsement/  版本化 HMAC 钥匙环；事件密钥与撤回策略密钥隔离
internal/merkle/       域分隔 Merkle 树、缓存树 O(log n) 证明、扁平哈希根
internal/log/          定长帧 + 记录哈希链仅追加日志，fsync 屏障、组提交、残帧裁剪
internal/lock/         跨进程排他锁（Windows LockFileEx / Unix flock，构建标签拆分）
internal/store/        分区日志、控制日志、折叠/冲突/撤回/回滚、代清单两阶段发布与恢复
internal/reader/       独立读端：固定代、重放哈希链、重建树根、逐项复验
e2e/                   真实子进程端到端测试（先 go build 再驱动二进制）
```

## 磁盘布局（单个存储目录）

```
write.lock                  写端排他锁（进程退出 OS 自动释放）
keyring.json                事件签注密钥（按代次）+ 撤回策略密钥，0600
part-<partition>.log        每采集进程一个仅追加日志（帧 + 前链 + 本记录链哈希）
control.log                 撤回/回滚控制记录（策略密钥 HMAC），同样哈希链
gen-<n>.json                第 n 代不可变清单（临时文件 fsync 后原子改名）
gen-<n>.json.tmp            发布中残留即作废，重开时清理
receipts/gen-<n>.rcpt       代回执（清单哈希的策略签名），晚于清单落盘
CURRENT                     当前代指针，最后一步原子改名
```

记录帧：`magic(4) | 帧长(4) | 序号(8) | 体长度(4) | 类型(4) | 前链哈希(32) | 本记录链哈希(32) | 体`。
链哈希持久化在帧内，任何字节改写都会在重放时被发现（有测试覆盖）。

## 崩溃屏障与前向恢复

发布顺序（每一步都 fsync，rename 在 Windows 经 `MoveFileEx` 原子替换）：

1. 清单写临时文件并 fsync —— 崩溃：等于未发布，重开清理 `*.tmp`；
2. 原子改名清单 —— 崩溃：**合并完成而回执未写**，读端拒绝承认该代，重开补签回执；
3. 回执写盘并 fsync —— 崩溃：重开重算并翻转 `CURRENT`；
4. `CURRENT` 原子翻转 —— 读者只认指针与回执齐备的最高代。

三个注入点均有真实子进程测试（`publish -crash-point ...`，退出码 3）。

## 快速使用（离线，无第三方依赖）

```powershell
go build -o alertguard.exe ./cmd/alertguard
.\alertguard.exe init -dir D:\oncall\store
# 采集进程 A/B 各自签注（钥匙环通过离线渠道分发）
.\alertguard.exe collect -dir D:\oncall\store -in a.jsonl -out a.sig.jsonl
.\alertguard.exe ingest  -dir D:\oncall\store -partition collector-a -in a.sig.jsonl
.\alertguard.exe publish -dir D:\oncall\store
# 晚到撤销 / 局部回滚
.\alertguard.exe revoke   -dir D:\oncall\store -alert A1 -endorsement 1 -reason "旧版撤回"
.\alertguard.exe rollback -dir D:\oncall\store -partition collector-a -to-seq 22500
# 独立读端：默认固定 CURRENT，也可 -pin 任意旧代；-watch 模拟长驻旧读者
.\alertguard.exe verify    -dir D:\oncall\store
.\alertguard.exe reader    -dir D:\oncall\store -pin 1
.\alertguard.exe conflicts -dir D:\oncall\store
# 十万条基准
.\alertguard.exe bench -dir D:\oncall\bench -events 100000 -partitions 4 -sources 2 -rollback-pct 10
```

## 十万条实测（本机 Windows 11，Go 1.27.4，单进程组提交）

数据为一次实测（机器相关，波动属正常）；每次 `bench` 都会独立重放全量日志与清单承诺逐项比对：

| 指标 | 回滚前代 gen1 | 局部回滚后 gen2 |
| --- | --- | --- |
| 事件/日志记录 | 100000 | **100000（原始记录零删除）** |
| 代树叶子 | 100000 | 97500（仅 collector-a 剔除 10% 后缀） |
| 根代表数 | 25000 | 25000 |
| 读端复验耗时 | 7506 ms | 7528 ms（基本持平） |
| 读端存活堆 | ≈435 MB | ≈416 MB（随叶子数下降，无关分区零影响） |
| 无关分区根 | — | **不变（`unrelated_partition_root_unchanged=true`）** |
| 被回滚分区根 | — | 变化（`rolled_partition_root_changed=true`） |
| 全量事实对照 | — | **`full_fact_replay_match=true`** |

写入侧：摄入 100000 条约 2.6 s（2000 条/次组提交、每次一个 fsync 屏障），
两代发布分别约 2.2 s / 1.0 s。结论：局部回滚只改变点名分区的树形状，
读取路径耗时与无关分区根不受影响，内存随被剔除叶子线性下降，
而全量事实始终可从原始日志独立重建。

## 测试矩阵

- `go test ./...` 全部通过。
- 单元：Merkle 包含证明 1..64 叶全量复验与篡改检测、扁平根一致性、
  日志哈希链/残帧裁剪/链断裂、HMAC 密钥隔离与钥匙环落盘。
- 存储：折叠优先级/水位、高优证书、同号异摘要、晚到撤销、隔离、
  局部回滚隔离、追加前缀、三崩溃屏障恢复；384 顺序枚举。
- 真实进程（`e2e`）：两采集合并、晚到撤销、同号异摘要、回执未写恢复、
  三屏障、旧读者三代固定、跨进程排他锁、日志篡改拦截、bench 小规模端到端。
- 竞态检测需 CGO（本机无 gcc，`CGO_ENABLED=0`）；代码无后台 goroutine，
  并发约束由目录级排他锁在进程间强制，已由 `TestCrossProcessLock` 覆盖。

## 安全边界

- HMAC 密钥是信任根：离线主机依赖文件 ACL（0600）保护 `keyring.json`；
  撤回策略密钥与事件签注密钥相互独立，撤回旧签注不削弱撤回记录的可验证性。
- 读端不信任信封 `Valid` 位与清单数字，签名、树根、叶子定位、控制记录全部独立重算。
- 不提供保密通信/PKI；范围是离线主机上的完整性、可复验性与崩溃一致性。
