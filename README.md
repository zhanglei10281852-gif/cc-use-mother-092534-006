# 子智能体追踪证据链

委派图、追踪片段、敏感投影、签名封存与访问审计的领域资料与参考服务。
仓库在领域合同之上提供一个**仅依赖 Python 标准库**、基于 SQLite 持久化的
追踪证据服务 `tracechain`，覆盖：

1. **稳定关联标识**：每次委派生成由 `租户+任务族+父子任务+指令摘要`
   确定性派生的关联标识；同一委派重复上报只确认已有记录。
2. **来源序列号 + 内容摘要去重**：片段身份由来源序列号与内容摘要共同决定，
   重复上报只增加确认计数，绝不新增链条目。
3. **接收顺序哈希链**：片段到达即追加（WORM），每条链头绑定上一链头、
   片段身份、序列号、内容摘要与分叉案件号。
4. **逻辑时间线**：迟到片段按来源序列号补入逻辑时间线；
   **已封存的原始接收顺序永不改变**（封存快照写入 `chain.sealed` 事件）。
5. **缺口显式化**：未到达的序列号产生 `gap.detected`，补齐产生 `gap.filled`，
   `reject_all` 裁决会让缺口重开；未收齐的链禁止封存。
6. **分叉进入裁决**：同序列号不同内容即开分叉案件，必须认领并由人裁决
  （选择胜出片段或全部否决），系统不会自动选一条。
7. **按角色投影**：凭据 / 个人数据 / 其他租户内容按角色 reveal/mask/drop，
   所有投影保留同一 `raw_content_hash`，并各自有可验证的 `projection_hash`。
8. **读取审计**：所有读取（含被拒绝的原始读取、审计查询自身）都写
   `read.recorded` 事件与审计行，记录读取者、角色、访问类型与摘要。
9. **任务族冻结/解冻**：冻结期间拒绝一切写入。
10. **导出组成证明**：仅冻结家族可导出；清单逐片段列出组成、接收链哈希与
    封存根，整体摘要可重算复核；未收齐链明确标注 `complete=false` 与阻塞原因。
11. **重启恢复**：重放全局事件哈希链与每条接收链、复核封存根，未决分叉与
    缺口原样保留；检测到任何篡改即拒绝启动。

## 目录

- `domain/contract.json`：实体、状态、事件类型和关键业务规则（版本化追加）。
- `domain/policies.json`：编号业务策略。
- `domain/projection_policies.json`：按角色的字段脱敏策略。
- `examples/events.json`：按业务发生时间排列的事件样例。
- `tracechain/`：追踪证据服务（`crypto` / `store` / `projections` / `service`）。
- `tools/validate_contract.py`：使用 Python 标准库和 SQLite 内存表验证资料一致性。
- `tools/demo.py`：在临时数据库上演示完整调查流程。
- `tests/`：领域资料校验与服务端到端规则测试。

## 构建

```bash
python3 -m compileall -q .
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 资料校验

```bash
python3 tools/validate_contract.py
```

## 快速演示

```bash
python3 tools/demo.py
```

## 服务使用要点

```python
from tracechain import TraceEvidenceService

svc = TraceEvidenceService("trace.db")  # 文件即持久化；重启自动 recover()
svc.create_family("tenant-a", "fam-1", "task-root", actor_id="op-1")
d = svc.create_delegation(
    "tenant-a", "fam-1", "task-root", "task-child",
    {"cmd": "调查登录日志"}, expected_total=3, actor_id="op-1",
)
svc.report_fragment("tenant-a", d["delegation_id"], source_id="agent-1",
                    source_seq=1, content={"tool": "bash"}, actor_id="agent-1")
# 冲突内容 -> outcome == "candidate"，分叉案件等待 claim/adjudicate，绝不自动选边
# 缺口未补齐 / 分叉未裁决时 seal_delegation 抛 StateError
svc.freeze_family("tenant-a", "fam-1", actor_id="op-1", reason="冻结取证")
export = svc.export_family("tenant-a", "fam-1", reader_id="inv-1", role="investigator")
svc.verify_export("tenant-a", export["export_id"], reader_id="aud-1", role="auditor")
```

所有命令都在项目根目录执行，数据库之外不需要任何外部服务。
