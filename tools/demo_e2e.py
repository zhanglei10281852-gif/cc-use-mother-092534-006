"""端到端演示：调查人员处理一个任务族的完整证据链生命周期。

运行：python3 tools/demo_e2e.py
（使用临时数据库，不依赖任何外部服务。）
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracechain.errors import ConflictingReport  # noqa: E402
from tracechain.service import TraceEvidenceService  # noqa: E402


def main() -> None:
    tmp = tempfile.TemporaryDirectory()
    db = str(Path(tmp.name) / "demo.db")
    svc = TraceEvidenceService(db)

    # 1) 登记任务族与委派（标识稳定可复算）
    family = svc.create_family("tenant-a", "case-2026-06", actor_id="operator-01")
    reg = svc.register_delegation(
        "tenant-a", family, "parent-task-77", "汇总外发数据并生成结论",
        actor_id="operator-01", expected_count=3,
    )
    did = reg.view.delegation_id
    print(f"[1] 任务族 {family}  委派 {did}")

    # 2) 片段到达：第 3 号先于第 2 号（乱序接收，链路仍按接收顺序）
    svc.report_fragment("tenant-a", did, "subagent-A", 1,
                        {"action": "query", "sql": "select * from logs"},
                        occurred_at="2026-09-25T09:00:00+08:00", reporter_id="agent")
    svc.report_fragment("tenant-a", did, "subagent-A", 3,
                        {"action": "upload", "api_key": "sk-demo-0123456789",
                         "user_email": "zhang.san@example.com"},
                        occurred_at="2026-09-25T09:10:00+08:00", reporter_id="agent")
    print(f"[2] 缺口：{[(g.source, g.missing_seq) for g in svc.delegation_status(did)['gaps']]}")

    # 3) 迟到片段补入逻辑时间线
    svc.report_fragment("tenant-a", did, "subagent-A", 2,
                        {"action": "scan"},
                        occurred_at="2026-09-25T09:05:00+08:00", reporter_id="agent")

    # 4) 分叉：同序号不同内容，自动进入裁决队列
    try:
        svc.report_fragment("tenant-a", did, "subagent-A", 2,
                            {"action": "scan", "tampered": True},
                            occurred_at="2026-09-25T09:05:00+08:00", reporter_id="agent")
    except ConflictingReport as exc:
        fork = svc.list_forks(family)[0]
        print(f"[3] 分叉立案 {fork.fork_id}，候选数 {len(fork.candidate_digests)}，状态 {fork.status}")
        # 未裁决前禁止封存
        try:
            svc.seal_chain(did, sealed_by="lead")
        except Exception as block:  # noqa: BLE001
            print(f"[4] 未裁决拒绝封存：{type(block).__name__}")
        svc.start_adjudication(fork.fork_id, adjudicator="reviewer-02", reason="比对原始日志")
        svc.resolve_fork(fork.fork_id, resolution="accepted",
                         chosen_digest=exc.existing_digest,
                         actor_id="reviewer-02", reason="原始片段与来源日志一致")

    # 5) 封存：哈希链快照按接收顺序
    seal = svc.seal_chain(did, sealed_by="lead-01")
    print(f"[5] 封存完成 head={seal.head_hash[:32]}... 共 {seal.fragment_count} 片段")

    # 6) 不同角色投影读取（各留审计）
    entries, _ = svc.read_family(family, actor_id="inv-1", role="investigator",
                                 viewer_tenant="tenant-a", purpose="内部调查")
    masked = next(e.projection.content for e in entries
                  if e.fragment.seq == 3 and e.fragment.source == "subagent-A")
    print(f"[6] 调查员投影：api_key={masked['api_key']} email={masked['user_email']}")
    print(f"    投影仍锚定原始摘要：{entries[0].projection.original_digest[:28]}...")

    # 7) 冻结任务族
    svc.freeze_family(family, actor_id="lead-01", reason="证据固定，移交法务")
    print(f"[7] 任务族状态：{svc.family_status(family)['state']}")

    # 8) 导出组成证明
    bundle = svc.export_family(family, actor_id="legal-1", role="auditor",
                               viewer_tenant="tenant-a", purpose="法务移交包")
    manifest = {k: v for k, v in bundle.manifest.items()
                if k in ("export_id", "root_digest", "complete", "fragment_ids", "notes")}
    print("[8] 导出清单：")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"    导出根摘要复核：{svc.verify_export(bundle.record.export_id)}")
    print(f"[9] 读取审计条数：{len(svc.list_audits(family))}（含投影读取与导出）")
    svc.close()
    tmp.cleanup()


if __name__ == "__main__":
    main()
