"""在临时数据库上演示完整的追踪证据调查流程。

运行：python3 tools/demo.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracechain import TraceEvidenceService

TENANT = "tenant-acme"
FAMILY = "fam-login-breach"
ACTOR_OP = "operator-01"


def main() -> None:
    tmp = tempfile.TemporaryDirectory()
    db_path = str(Path(tmp.name) / "demo.db")
    svc = TraceEvidenceService(db_path)

    print("== 1. 建立任务族与委派（稳定关联标识） ==")
    svc.create_family(TENANT, FAMILY, "task-root", title="登录异常调查", actor_id=ACTOR_OP)
    delegation = svc.create_delegation(
        TENANT, FAMILY, "task-root", "subagent-log",
        {"cmd": "拉取 2026-09-24 登录日志并标注可疑 IP"},
        expected_total=3, actor_id=ACTOR_OP,
    )
    did = delegation["delegation_id"]
    print("委派标识:", did)
    again = svc.create_delegation(
        TENANT, FAMILY, "task-root", "subagent-log",
        {"cmd": "拉取 2026-09-24 登录日志并标注可疑 IP"},
        expected_total=3, actor_id=ACTOR_OP,
    )
    print("重复上报同一委派 -> deduplicated:", again["deduplicated"], "标识相同:",
          again["delegation_id"] == did)

    print("\n== 2. 接收片段：缺口、迟到补入、哈希链 ==")
    svc.report_fragment(
        TENANT, did, source_id="agent-log-1", source_seq=1, actor_id="agent-log-1",
        content={"tool": "bash", "cmd": "grep sshd /var/log/auth.log",
                 "api_key": "sk-prod-9f3a",
                 "_security_labels": {"api_key": ["credentials"]}},
    )
    print("seq3 先到，状态:", svc.report_fragment(
        TENANT, did, source_id="agent-log-1", source_seq=3, actor_id="agent-log-1",
        content={"result": "发现 12 条可疑登录"},
    )["delegation_status"])
    print("迟到 seq2 补入后状态:", svc.report_fragment(
        TENANT, did, source_id="agent-log-1", source_seq=2, actor_id="agent-log-1",
        content={"tool": "read", "path": "/var/log/auth.log"},
    )["delegation_status"])
    print("重复上报 seq2:", svc.report_fragment(
        TENANT, did, source_id="agent-log-1", source_seq=2, actor_id="agent-log-1",
        content={"tool": "read", "path": "/var/log/auth.log"},
    )["outcome"])

    print("\n== 3. 分叉必须裁决（演示第二条委派链） ==")
    d2 = svc.create_delegation(
        TENANT, FAMILY, "task-root", "subagent-net",
        {"cmd": "汇总可疑 IP 的归属"}, expected_total=2, actor_id=ACTOR_OP,
    )
    did2 = d2["delegation_id"]
    svc.report_fragment(TENANT, did2, source_id="agent-net-1", source_seq=1,
                        actor_id="agent-net-1", content={"ip": "10.0.0.9", "region": "内网"})
    conflict = svc.report_fragment(TENANT, did2, source_id="agent-net-2", source_seq=1,
                                   actor_id="agent-net-2",
                                   content={"ip": "10.0.0.9", "region": "境外代理"})
    print("同序列号不同内容 -> outcome:", conflict["outcome"], "fork:", conflict["fork_id"])
    svc.report_fragment(TENANT, did2, source_id="agent-net-1", source_seq=2,
                        actor_id="agent-net-1", content={"result": "完成"})
    try:
        svc.seal_delegation(TENANT, did2, actor_id=ACTOR_OP)
    except Exception as exc:  # noqa: BLE001 - 演示预期失败
        print("未裁决即封存被拒绝:", exc)
    svc.claim_fork(TENANT, conflict["fork_id"], actor_id="investigator-07")
    candidates = svc.conn.execute(
        "select candidate_ids from fork_cases where fork_id=?", (conflict["fork_id"],)
    ).fetchone()[0]
    import json
    winner = json.loads(candidates)[0]
    svc.adjudicate_fork(TENANT, conflict["fork_id"], action="choose_winner",
                        winner_fragment_id=winner, actor_id="investigator-07",
                        rationale="来源 agent-net-1 有签名且与原始日志一致")
    svc.seal_delegation(TENANT, did, actor_id=ACTOR_OP)
    svc.seal_delegation(TENANT, did2, actor_id=ACTOR_OP)
    print("两条链均已封存；重放校验:",
          svc.verify_delegation(TENANT, did, reader_id=ACTOR_OP, role="auditor")["seal_ok"],
          svc.verify_delegation(TENANT, did2, reader_id=ACTOR_OP, role="auditor")["seal_ok"])

    print("\n== 4. 按角色投影，同一原始摘要 ==")
    first_fragment = svc.conn.execute(
        "select fragment_id from fragments where delegation_id=? order by source_seq limit 1",
        (did,),
    ).fetchone()[0]
    for role in ("security_administrator", "investigator", "auditor"):
        p = svc.get_fragment_projection(TENANT, first_fragment, reader_id="user-1", role=role)
        print(f"  {role:24s} -> {p['content']}  raw={p['raw_content_hash'][:12]}")
    print("调查员读取原始证据被拒绝（拒绝行为也审计）:")
    try:
        svc.get_fragment_raw(TENANT, first_fragment, reader_id="user-1", role="investigator")
    except Exception as exc:  # noqa: BLE001
        print("  ", type(exc).__name__, exc)

    print("\n== 5. 冻结、导出组成证明、审计 ==")
    svc.freeze_family(TENANT, FAMILY, actor_id=ACTOR_OP, reason="证据固定")
    export = svc.export_family(TENANT, FAMILY, reader_id="investigator-07",
                               role="investigator")
    print("导出:", export["export_id"], "摘要:", export["export_digest"][:16], "...")
    for d in export["manifest"]["delegations"]:
        print(f"  委派 {d['delegation_id']}: {len(d['timeline'])} 个片段, "
              f"接收链条目 {len(d['received_order_entries'])}, complete={d['complete']}")
    verify = svc.verify_export(TENANT, export["export_id"], reader_id="auditor-02",
                               role="auditor")
    print("导出复核 digest_ok:", verify["digest_ok"], "链校验:", verify["delegation_checks"])

    print("\n== 6. 重启恢复（未决状态保留、封存可验证） ==")
    svc.close()
    svc = TraceEvidenceService(db_path)
    print("恢复报告:", svc.recovery_report)
    svc.close()
    tmp.cleanup()
    print("\n演示完成。")


if __name__ == "__main__":
    main()
