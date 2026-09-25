# 子智能体追踪证据链

面向内部调查的追踪证据服务：把分散在各 JSONL 中的父任务、委派指令、工具调用与最终产物，
汇聚成**可证明顺序与归属**的证据链。仅追加事件日志是唯一事实来源，所有状态由重放重建。

## 设计原则（对应调查场景）

| 要求 | 实现 |
| --- | --- |
| 每次委派生成稳定关联标识 | 委派 ID = `SHA256(租户 ‖ 任务族 ‖ 父任务 ‖ 指令摘要)` 确定性派生，重复上报得到同一 ID |
| 片段按来源序列号接收并形成哈希链 | `(来源, 序号)` 定位，`entry_hash = SHA256(prev_head ‖ 来源 ‖ 序号 ‖ 内容摘要)` |
| 迟到片段补入逻辑时间线 | 逻辑视图按 `(来源, 序号)` 排序；封存快照按**接收顺序**固化，迟到者不重排历史 |
| 迟到片段不得改写已封存原始顺序 | 封存后到达的**新序号**进入锚定封存头的独立补充段（`sup-*`），封存头永不变 |
| 重复上报只确认已有记录 | 同 `(来源, 序号, 内容摘要)` 追加 `fragment.duplicated` 确认事件，链状态不变 |
| 分叉链必须进入裁决，不自动选边 | 同序号不同摘要 → 开立 `fork_case`（open → adjudicating → resolved），未决期间禁止封存 |
| 凭据/个人数据/跨租户内容按角色投影 | 凭据、PII、跨租户字段由键名与内容标记自动分类；四档角色，明文/掩码/标记/剔除 |
| 不同投影共享同一原始证据 | 投影信封始终携带 `original_digest`，投影只改可见性，不改可验证性 |
| 冻结任务族 | `family.frozen` 后拒绝一切新片段、新委派、封存、裁决 |
| 证明导出由哪些片段组成 | 导出清单含逐片段原始摘要、封存头、补充段头与归集根摘要，可独立复核 |
| 记录所有读取行为 | 每次读取/导出追加 `read.audited`：操作人、角色、用途、指纹、结果摘要 |
| 重启后继续处理未决分叉和缺口 | 进程不持有权威状态；启动后重放事件日志，`pending_work()` 列出全部未决事项 |
| 不得把未收齐的链误标完整 | 封存强制检查：无未决分叉、无缺口、数量达预期或显式宣告；导出 `complete` 严格派生 |

## 目录

- `tracechain/`：证据服务实现
  - `hashing.py`：内容寻址、哈希链、稳定标识
  - `clock.py`：带时区时间策略（业务时间 vs 接收时间）
  - `models.py`：实体与不可变快照
  - `store.py`：SQLite 仅追加事件存储（成批原子写入）
  - `state.py`：事件重放聚合（链结构、缺口、分叉、封存、完整性、导出根）
  - `service.py`：用例编排（登记/接收/裁决/封存/冻结/投影/导出/恢复）
  - `projection.py`：角色投影引擎与脱敏策略
  - `errors.py`：显式领域错误（拒绝即拒绝，不静默近似）
- `domain/contract.json`：实体、状态、事件类型与业务规则（只追加扩展）
- `domain/policies.json`：调查策略（P-06-01 … P-06-04）
- `domain/projection_policy.json`：角色投影策略（可热替换，不改代码）
- `examples/events.json`：按业务时间排列的事件样例
- `tools/validate_contract.py`：领域资料一致性校验
- `tools/demo_e2e.py`：端到端工作流演示
- `tests/`：39 个测试（标识幂等、哈希链、缺口、封存、分叉裁决、裁决后语义、
  投影、审计、导出、冻结、重启恢复、并发、篡改检测）

## 关键语义

### 两条时间线

- **接收顺序**（`recv_index`，单调）：封存快照严格按它排列，是"谁先到"的司法事实。
- **逻辑时间线**（`source` + `seq` + `occurred_at`）：调查阅读视图，迟到片段可以补入。

封存的意义就是把某一时刻的接收顺序固化成哈希链；之后发生的一切都只能追加。

### 裁决之后（分叉不会被"重新上报"绕过）

- 重发**已被否决的摘要** → `DisavowedContent`，禁止重新入链。
- 全案 rejected 后补送**全新内容** → 正常接收并填补缺口，旧候选留在台账可审计。
- 已 accepted 的裁决又收到新候选挑战 → **新开一案**，旧裁决保持 resolved 不被改写。
- 败诉片段永远保留在接收台账（审计可见），但不进入封存快照与规范链。

### 封存后争议

封存后对已封存序号的冲突内容照常登记并开立分叉案（`after_seal=true`），封存头不变；
裁决结果出现在导出清单的 `post_seal_findings` 中——封存事实不可变，但证据地位变化必须可见。

### 导出完整性

`export_root` 从各委派封存头（含锚定的补充段头）归集。任一委派未封存、有缺口、
有未决分叉，或"宣告完整后又来迟到片段"，导出都标记 `complete=false` 并在 `notes`
列明原因——不存在"默认完整"。

## 快速开始

```bash
# 编译检查
python3 -m compileall -q .

# 全部测试
python3 -m unittest discover -s tests -v

# 领域资料校验
python3 tools/validate_contract.py

# 端到端演示
python3 tools/demo_e2e.py
```

```python
from tracechain.service import TraceEvidenceService

svc = TraceEvidenceService("trace.db")          # 文件路径即可持久化；":memory:" 用于测试
fam = svc.create_family("tenant-a", "case-06", actor_id="op-1")
did = svc.register_delegation(
    "tenant-a", fam, "parent-task-7", "汇总工具调用",
    actor_id="op-1", expected_count=3,
).view.delegation_id

svc.report_fragment("tenant-a", did, "agent-A", 1, {...},
                    occurred_at="2026-09-25T10:00:00+08:00", reporter_id="r-1")
# 缺口/分叉由接收过程自动登记；冲突时抛出 ConflictingReport（携带 fork_id）
svc.resolve_fork(fork_id, resolution="accepted", chosen_digest=...,
                 actor_id="reviewer-02", reason="与来源日志一致")
seal = svc.seal_chain(did, sealed_by="lead-01")  # 不满足收齐条件会被拒绝

entries, audit = svc.read_family(                 # 角色投影 + 自动读取审计
    fam, actor_id="inv-1", role="investigator",
    viewer_tenant="tenant-a", purpose="内部调查",
)
bundle = svc.export_family(                      # 组成证明 + 根摘要
    fam, actor_id="legal-1", role="auditor",
    viewer_tenant="tenant-a", purpose="法务移交",
)
assert svc.verify_export(bundle.record.export_id)

# 重启后：新进程打开同一文件，pending_work 恢复全部未决分叉与缺口
svc2 = TraceEvidenceService("trace.db")
for fork in svc2.pending_work().open_forks:
    ...
```

所有时间戳必须带时区（ISO 8601），无需外部数据库或其他服务。
