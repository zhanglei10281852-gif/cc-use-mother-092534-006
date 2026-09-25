"""追踪证据服务的端到端规则测试。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tracechain import (
    AccessDeniedError,
    ChainSealedError,
    FrozenError,
    StateError,
    TraceEvidenceService,
    ValidationError,
)
from tracechain.crypto import chain_entry_hash, hash_content
from tracechain.projections import load_projection_policy
from tracechain.service import GENESIS_HASH

TENANT = "tenant-a"
FAMILY = "fam-06"
ROOT = "task-root"
CHILD = "task-child"


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        # 单调时钟：同一用例内事件时间严格递增，便于断言顺序。
        from datetime import datetime, timedelta, timezone
        self._tick = 0
        base = datetime(2026, 9, 25, 9, 0, tzinfo=timezone.utc)

        def clock() -> str:
            self._tick += 1
            return (base + timedelta(seconds=self._tick)).isoformat()

        self.clock = clock
        self.svc = TraceEvidenceService(":memory:", clock=clock)
        self.svc.create_family(TENANT, FAMILY, ROOT, title="内部调查案", actor_id="op-1")

    def tearDown(self) -> None:
        self.svc.close()

    def create_delegation(self, expected_total: int | None = 3, instruction=None):
        return self.svc.create_delegation(
            TENANT, FAMILY, ROOT, CHILD,
            instruction if instruction is not None else {"cmd": "调查日志", "q": "q1"},
            expected_total=expected_total, actor_id="op-1",
        )

    def report(self, did: str, seq: int, content, source_id: str = "agent-1", labels=None):
        return self.svc.report_fragment(
            TENANT, did, source_id=source_id, source_seq=seq,
            content=content, actor_id=source_id, labels=labels,
        )


class CorrelationTest(ServiceTestBase):
    def test_delegation_id_is_stable_and_dedup_is_idempotent(self) -> None:
        d1 = self.create_delegation()
        d2 = self.create_delegation()
        self.assertFalse(d1["deduplicated"])
        self.assertTrue(d2["deduplicated"])
        self.assertEqual(d1["delegation_id"], d2["delegation_id"])
        # 元数据标注不影响关联标识。
        d3 = self.svc.create_delegation(
            TENANT, FAMILY, ROOT, CHILD,
            {"cmd": "调查日志", "q": "q1", "_security_labels": {"q": ["personal_data"]}},
            expected_total=3, actor_id="op-1",
        )
        self.assertEqual(d3["delegation_id"], d1["delegation_id"])
        # 指令内容变了 -> 不同委派。
        d4 = self.svc.create_delegation(
            TENANT, FAMILY, ROOT, "task-child-2", {"cmd": "其他"},
            expected_total=1, actor_id="op-1",
        )
        self.assertNotEqual(d4["delegation_id"], d1["delegation_id"])


class FragmentChainTest(ServiceTestBase):
    def test_hash_chain_follows_receive_order_late_fragment_fills_timeline(self) -> None:
        d = self.create_delegation(expected_total=3)
        did = d["delegation_id"]
        r1 = self.report(did, 1, {"step": "one"})
        r3 = self.report(did, 3, {"step": "three"})
        self.assertEqual(r3["delegation_status"], "gapped")

        # 迟到片段补入逻辑时间线。
        r2 = self.report(did, 2, {"step": "two-late"})
        self.assertEqual(r2["outcome"], "received")
        timeline = self.svc.get_timeline(TENANT, did, reader_id="inv-1", role="investigator")
        self.assertEqual([i["source_seq"] for i in timeline["items"]], [1, 2, 3])
        # 接收顺序按实际到达：seq1=1, seq3=2, seq2=3。
        orders = {i["source_seq"]: i["received_order"] for i in timeline["items"]}
        self.assertEqual(orders, {1: 1, 3: 2, 2: 3})

        info = self.svc.get_delegation(TENANT, did, reader_id="inv-1", role="investigator")
        self.assertTrue(info["complete"])
        self.assertEqual(info["blockers"], [])

        # 重放链哈希。
        check = self.svc.verify_delegation(TENANT, did, reader_id="inv-1", role="auditor")
        prev = GENESIS_HASH
        entries = self.svc.conn.execute(
            "select ce.*, f.source_seq, f.content_hash from chain_entries ce "
            "join fragments f on f.fragment_id=ce.fragment_id "
            "where ce.delegation_id=? order by received_order", (did,)
        ).fetchall()
        for e in entries:
            expected = chain_entry_hash(
                prev, fragment_id=e["fragment_id"], source_seq=e["source_seq"],
                content_hash=e["content_hash"], entry_kind=e["entry_kind"], fork_id=e["fork_id"],
            )
            self.assertEqual(expected, e["entry_hash"])
            prev = e["entry_hash"]
        self.assertTrue(check["seal_ok"] is None)  # 尚未封存

    def test_duplicate_report_only_confirms(self) -> None:
        d = self.create_delegation(expected_total=2)
        did = d["delegation_id"]
        first = self.report(did, 1, {"v": 1})
        again = self.report(did, 1, {"v": 1})
        self.assertEqual(again["outcome"], "duplicated")
        self.assertEqual(again["fragment_id"], first["fragment_id"])
        rows = self.svc.conn.execute(
            "select count(*) c from chain_entries where delegation_id=?", (did,)
        ).fetchone()["c"]
        self.assertEqual(rows, 1)  # 没有新增链条目
        confirmations = self.svc.conn.execute(
            "select confirmations from fragments where fragment_id=?", (first["fragment_id"],)
        ).fetchone()["confirmations"]
        self.assertEqual(confirmations, 2)

    def test_same_content_from_different_source_is_still_duplicate(self) -> None:
        # 合同：来源序列号与内容摘要共同决定唯一性；来源实例不同但证据相同仍算重复。
        d = self.create_delegation(expected_total=1)
        did = d["delegation_id"]
        first = self.report(did, 1, {"v": 1}, source_id="agent-1")
        again = self.report(did, 1, {"v": 1}, source_id="agent-2")
        self.assertEqual(again["outcome"], "duplicated")
        self.assertEqual(again["fragment_id"], first["fragment_id"])

    def test_incomplete_chain_cannot_be_sealed(self) -> None:
        d = self.create_delegation(expected_total=3)
        did = d["delegation_id"]
        self.report(did, 1, {"v": 1})
        self.report(did, 2, {"v": 2})
        with self.assertRaises(StateError) as ctx:
            self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertIn("open_gaps", str(ctx.exception))

    def test_unknown_total_chain_is_never_auto_complete(self) -> None:
        d = self.create_delegation(expected_total=None)
        did = d["delegation_id"]
        self.report(did, 1, {"v": 1})
        with self.assertRaises(StateError):
            self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        # 封存时可以补登总数。
        self.report(did, 2, {"v": 2})
        sealed = self.svc.seal_delegation(TENANT, did, actor_id="op-1", expected_total=2)
        self.assertEqual(sealed["status"], "sealed")


class ForkTest(ServiceTestBase):
    def _forked_chain(self):
        d = self.create_delegation(expected_total=2)
        did = d["delegation_id"]
        self.report(did, 1, {"v": "a"}, source_id="agent-1")
        conflict = self.report(did, 1, {"v": "b"}, source_id="agent-2")
        self.assertEqual(conflict["outcome"], "candidate")
        self.assertIsNotNone(conflict["fork_id"])
        return did, conflict["fork_id"]

    def test_fork_blocks_seal_and_requires_adjudication(self) -> None:
        did, fork_id = self._forked_chain()
        self.report(did, 2, {"v": "ok"})
        with self.assertRaises(StateError) as ctx:
            self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertIn("unresolved_forks", str(ctx.exception))

        # 必须先认领再裁决，裁决人为记录在案。
        self.svc.claim_fork(TENANT, fork_id, actor_id="judge-1")
        candidates = self.svc.conn.execute(
            "select candidate_ids from fork_cases where fork_id=?", (fork_id,)
        ).fetchone()["candidate_ids"]
        winner = json.loads(candidates)[0]
        self.svc.adjudicate_fork(
            TENANT, fork_id, action="choose_winner",
            winner_fragment_id=winner, actor_id="judge-1", rationale="来源签名更可信",
        )
        info = self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertEqual(info["status"], "sealed")
        check = self.svc.verify_delegation(TENANT, did, reader_id="j", role="auditor")
        self.assertTrue(check["seal_ok"])

    def test_cannot_adjudicate_without_valid_winner(self) -> None:
        _did, fork_id = self._forked_chain()
        with self.assertRaises(ValidationError):
            self.svc.adjudicate_fork(
                TENANT, fork_id, action="choose_winner",
                winner_fragment_id="frag-nope", actor_id="judge-1",
            )

    def test_reject_all_reopens_gap(self) -> None:
        did, fork_id = self._forked_chain()
        self.report(did, 2, {"v": "ok"})
        self.svc.adjudicate_fork(
            TENANT, fork_id, action="reject_all", actor_id="judge-1", rationale="两份均不可信"
        )
        with self.assertRaises(StateError) as ctx:
            self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertIn("open_gaps:1", str(ctx.exception))
        # 之后补来 seq1 的可信新片段（不同于两个候选内容）。
        self.report(did, 1, {"v": "c"}, source_id="agent-3")
        sealed = self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertEqual(sealed["status"], "sealed")


class SealedOrderTest(ServiceTestBase):
    def test_late_conflict_after_seal_enters_adjudication_but_seal_snapshot_holds(self) -> None:
        d = self.create_delegation(expected_total=2)
        did = d["delegation_id"]
        r1 = self.report(did, 1, {"v": "a"})
        r2 = self.report(did, 2, {"v": "b"})
        self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        snapshot_events = self.svc.conn.execute(
            "select payload_text from events where event_type='chain.sealed' and aggregate_id=?",
            (did,),
        ).fetchall()
        self.assertEqual(len(snapshot_events), 1)

        # 封存后到达冲突片段：入链留证并开分叉，但封存根不变。
        late = self.report(did, 1, {"v": "CONFLICT"}, source_id="agent-9")
        self.assertEqual(late["outcome"], "candidate")
        self.assertEqual(late["delegation_status"], "sealed")
        info = self.svc.get_delegation(TENANT, did, reader_id="inv-1", role="investigator")
        self.assertEqual(info["post_seal_pending_forks"], [late["fork_id"]])

        check = self.svc.verify_delegation(TENANT, did, reader_id="j", role="auditor")
        self.assertTrue(check["seal_ok"])
        self.assertEqual(len(check["entries"]), 3)  # 新片段确实追加到了链尾
        sealed_info = self.svc.get_delegation(TENANT, did, reader_id="j", role="auditor")
        self.assertIsNotNone(sealed_info["seal_root_hash"])

        # 迟到裁决不改变封存时间线快照。
        self.svc.adjudicate_fork(
            TENANT, late["fork_id"], action="choose_winner",
            winner_fragment_id=r1["fragment_id"], actor_id="judge-1",
        )
        timeline = self.svc.get_timeline(TENANT, did, reader_id="j", role="auditor")
        self.assertEqual(
            timeline["sealed_timeline"],
            [{"source_seq": 1, "fragment_id": r1["fragment_id"]},
             {"source_seq": 2, "fragment_id": r2["fragment_id"]}],
        )
        self.assertTrue(self.svc.verify_delegation(TENANT, did, reader_id="j", role="auditor")["seal_ok"])

    def test_reseal_is_rejected(self) -> None:
        d = self.create_delegation(expected_total=1)
        did = d["delegation_id"]
        self.report(did, 1, {"v": 1})
        self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        with self.assertRaises(StateError):
            self.svc.seal_delegation(TENANT, did, actor_id="op-1")


class ProjectionTest(ServiceTestBase):
    CONTENT = {
        "tool": "bash",
        "api_key": "sk-secret",
        "user_name": "张三",
        "other_tenant_note": "租户B的内部备注",
    }
    LABELS = {
        "api_key": ["credentials"],
        "user_name": ["personal_data"],
        "other_tenant_note": ["tenant_content"],
    }

    def _fragment(self):
        d = self.create_delegation(expected_total=1)
        r = self.report(d["delegation_id"], 1, self.CONTENT, labels=self.LABELS)
        return r["fragment_id"]

    def test_role_projections_differ_but_share_raw_hash(self) -> None:
        fid = self._fragment()
        sec = self.svc.get_fragment_projection(TENANT, fid, reader_id="s", role="security_administrator")
        inv = self.svc.get_fragment_projection(TENANT, fid, reader_id="i", role="investigator")
        aud = self.svc.get_fragment_projection(TENANT, fid, reader_id="a", role="auditor")
        ana = self.svc.get_fragment_projection(TENANT, fid, reader_id="n", role="analyst")
        # 同一原始证据摘要。
        self.assertEqual(sec["raw_content_hash"], hash_content(self.CONTENT))
        self.assertEqual({sec["raw_content_hash"], inv["raw_content_hash"],
                          aud["raw_content_hash"], ana["raw_content_hash"]},
                         {hash_content(self.CONTENT)})
        # 投影内容与投影摘要按角色不同。
        self.assertEqual(sec["content"]["api_key"], "***REDACTED***")
        self.assertNotIn("api_key", inv["content"])
        self.assertEqual(inv["content"]["user_name"], "***REDACTED***")
        self.assertNotIn("user_name", aud["content"])
        self.assertNotIn("other_tenant_note", ana["content"])
        self.assertEqual(len({sec["projection_hash"], inv["projection_hash"],
                              aud["projection_hash"], ana["projection_hash"]}), 4)

    def test_raw_read_requires_privileged_role_and_denial_is_audited(self) -> None:
        fid = self._fragment()
        with self.assertRaises(AccessDeniedError):
            self.svc.get_fragment_raw(TENANT, fid, reader_id="inv-1", role="investigator")
        raw = self.svc.get_fragment_raw(TENANT, fid, reader_id="sec-1",
                                        role="security_administrator")
        self.assertEqual(raw["content"]["api_key"], "sk-secret")
        denied = self.svc.list_read_audit(
            TENANT, reader_id="sec-1", role="auditor", target_reader_id="inv-1"
        )
        self.assertTrue(any(a["access_kind"] == "denied:fragment_raw" for a in denied))

    def test_inline_annotations_are_not_part_of_stored_content(self) -> None:
        d = self.create_delegation(expected_total=1)
        labeled = {**self.CONTENT, "_security_labels": self.LABELS}
        r = self.report(d["delegation_id"], 1, labeled)
        stored = self.svc.conn.execute(
            "select content_text from fragments where fragment_id=?", (r["fragment_id"],)
        ).fetchone()["content_text"]
        self.assertNotIn("_security_labels", stored)


class FreezeAndExportTest(ServiceTestBase):
    def _sealed_family(self):
        d = self.create_delegation(expected_total=2)
        did = d["delegation_id"]
        self.report(did, 1, {"v": "a", "api_key": "k",
                             "_security_labels": {"api_key": ["credentials"]}})
        self.report(did, 2, {"v": "b"})
        self.svc.seal_delegation(TENANT, did, actor_id="op-1")
        self.svc.freeze_family(TENANT, FAMILY, actor_id="op-1", reason="冻结取证")
        return did

    def test_freeze_blocks_writes_until_release(self) -> None:
        did = self._sealed_family()
        with self.assertRaises(FrozenError):
            self.create_delegation(expected_total=1)
        with self.assertRaises(FrozenError):
            self.svc.report_fragment(
                TENANT, did, source_id="s", source_seq=9, content={}, actor_id="a"
            )
        self.svc.release_family(TENANT, FAMILY, actor_id="op-1")
        d = self.svc.create_delegation(
            TENANT, FAMILY, ROOT, "task-child-new", {"cmd": "新任务"},
            expected_total=1, actor_id="op-1",
        )
        self.assertFalse(d["deduplicated"])

    def test_export_lists_fragment_composition_and_verifies(self) -> None:
        did = self._sealed_family()
        inv_export = self.svc.export_family(TENANT, FAMILY, reader_id="inv-1", role="investigator")
        sec_export = self.svc.export_family(TENANT, FAMILY, reader_id="sec-1",
                                            role="security_administrator")
        # 同一家族、不同角色投影 -> 摘要不同，但逐片段的原始摘要一致。
        self.assertNotEqual(inv_export["export_digest"], sec_export["export_digest"])
        inv_d = inv_export["manifest"]["delegations"][0]
        sec_d = sec_export["manifest"]["delegations"][0]
        self.assertEqual(
            [f["raw_content_hash"] for f in inv_d["timeline"]],
            [f["raw_content_hash"] for f in sec_d["timeline"]],
        )
        # 导出清单逐片段给出组成，并保留接收顺序链证明。
        self.assertEqual([f["source_seq"] for f in inv_d["timeline"]], [1, 2])
        self.assertEqual(len(inv_d["received_order_entries"]), 2)
        self.assertTrue(inv_d["complete"])
        self.assertIsNotNone(inv_d["seal_root_hash"])

        verify = self.svc.verify_export(TENANT, inv_export["export_id"],
                                        reader_id="aud-1", role="auditor")
        self.assertTrue(verify["digest_ok"])
        self.assertTrue(verify["delegation_checks"][0]["seal_ok"])

    def test_export_requires_frozen_family(self) -> None:
        with self.assertRaises(StateError):
            self.svc.export_family(TENANT, FAMILY, reader_id="inv-1", role="investigator")

    def test_unsealed_delegation_in_export_is_not_marked_complete(self) -> None:
        d1 = self.create_delegation(expected_total=1)
        self.report(d1["delegation_id"], 1, {"v": 1})
        self.svc.seal_delegation(TENANT, d1["delegation_id"], actor_id="op-1")
        d2 = self.svc.create_delegation(
            TENANT, FAMILY, ROOT, "task-child-2", {"cmd": "y"},
            expected_total=2, actor_id="op-1",
        )
        self.report(d2["delegation_id"], 1, {"v": 1})  # 缺口 seq2
        self.svc.freeze_family(TENANT, FAMILY, actor_id="op-1")
        export = self.svc.export_family(TENANT, FAMILY, reader_id="i", role="investigator")
        statuses = {d["delegation_id"]: d for d in export["manifest"]["delegations"]}
        self.assertTrue(statuses[d1["delegation_id"]]["complete"])
        incomplete = statuses[d2["delegation_id"]]
        self.assertFalse(incomplete["complete"])
        self.assertTrue(any("open_gaps" in b for b in incomplete["blockers"]))


class AuditTest(ServiceTestBase):
    def test_every_read_is_recorded(self) -> None:
        d = self.create_delegation(expected_total=1)
        fid = self.report(d["delegation_id"], 1, {"v": 1})["fragment_id"]
        self.svc.get_fragment_projection(TENANT, fid, reader_id="inv-1", role="investigator")
        self.svc.get_timeline(TENANT, d["delegation_id"], reader_id="inv-1", role="investigator")
        rows = self.svc.list_read_audit(TENANT, reader_id="aud-1", role="auditor")
        kinds = {r["access_kind"] for r in rows}
        self.assertIn("fragment_projection", kinds)
        self.assertIn("timeline", kinds)
        # 投影读取同时记录原始摘要与投影摘要。
        proj_rows = [r for r in rows if r["access_kind"] == "fragment_projection"]
        self.assertIsNotNone(proj_rows[0]["raw_content_hash"])
        self.assertIsNotNone(proj_rows[0]["projection_hash"])
        # 审计行为本身也留痕（上一次 list 产生的 audit_log 行此时可查）。
        rows2 = self.svc.list_read_audit(TENANT, reader_id="aud-2", role="auditor")
        self.assertTrue(any(r["access_kind"] == "audit_log" for r in rows2))


class RecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "trace.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _service(self):
        return TraceEvidenceService(self.db_path)

    def test_pending_forks_and_gaps_survive_restart(self) -> None:
        svc = self._service()
        svc.create_family(TENANT, FAMILY, ROOT, actor_id="op-1")
        d = svc.create_delegation(TENANT, FAMILY, ROOT, CHILD, {"cmd": "x"},
                                  expected_total=3, actor_id="op-1")
        did = d["delegation_id"]
        svc.report_fragment(TENANT, did, source_id="a1", source_seq=1,
                            content={"v": "a"}, actor_id="a1")
        fork = svc.report_fragment(TENANT, did, source_id="a2", source_seq=1,
                                   content={"v": "b"}, actor_id="a2")
        svc.report_fragment(TENANT, did, source_id="a1", source_seq=2,
                            content={"v": 2}, actor_id="a1")  # seq3 缺失
        svc.close()

        svc2 = self._service()
        report = svc2.recovery_report
        self.assertEqual(report["open_gaps"], 1)
        self.assertEqual(report["unresolved_forks"], 1)
        state = svc2.get_delegation(TENANT, did, reader_id="r", role="auditor")
        self.assertEqual(state["status"], "forked")
        self.assertFalse(state["complete"])

        # 重启后继续处理未决分叉与缺口。
        svc2.claim_fork(TENANT, fork["fork_id"], actor_id="judge")
        import sqlite3
        winner = svc2.conn.execute(
            "select fragment_id from fragments where delegation_id=? and source_seq=1 "
            "order by received_at limit 1", (did,)
        ).fetchone()["fragment_id"]
        svc2.adjudicate_fork(TENANT, fork["fork_id"], action="choose_winner",
                             winner_fragment_id=winner, actor_id="judge")
        svc2.report_fragment(TENANT, did, source_id="a1", source_seq=3,
                             content={"v": 3}, actor_id="a1")
        sealed = svc2.seal_delegation(TENANT, did, actor_id="op-1")
        self.assertEqual(sealed["status"], "sealed")
        svc2.close()

        # 再次重启：封存状态与封存根继续可验证，未被重标。
        svc3 = self._service()
        self.assertEqual(svc3.recovery_report["sealed"], 1)
        check = svc3.verify_delegation(TENANT, did, reader_id="r", role="auditor")
        self.assertTrue(check["seal_ok"])
        svc3.close()

    def test_tampered_event_log_is_rejected_on_recovery(self) -> None:
        svc = self._service()
        svc.create_family(TENANT, FAMILY, ROOT, actor_id="op-1")
        d = svc.create_delegation(TENANT, FAMILY, ROOT, CHILD, {"cmd": "x"},
                                  expected_total=1, actor_id="op-1")
        svc.report_fragment(TENANT, d["delegation_id"], source_id="a", source_seq=1,
                            content={"v": 1}, actor_id="a")
        svc.close()

        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("update events set actor_id='forger' where event_seq=1")
        conn.commit()
        conn.close()
        with self.assertRaises(StateError):
            TraceEvidenceService(self.db_path)

    def test_tampered_event_payload_is_rejected_on_recovery(self) -> None:
        svc = self._service()
        svc.create_family(TENANT, FAMILY, ROOT, actor_id="op-1")
        svc.close()

        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("update events set payload_text=payload_text||' ' where event_seq=1")
        conn.commit()
        conn.close()
        with self.assertRaises(StateError):
            TraceEvidenceService(self.db_path)

    def test_tampered_fragment_content_is_rejected_on_recovery(self) -> None:
        svc = self._service()
        svc.create_family(TENANT, FAMILY, ROOT, actor_id="op-1")
        d = svc.create_delegation(TENANT, FAMILY, ROOT, CHILD, {"cmd": "x"},
                                  expected_total=1, actor_id="op-1")
        svc.report_fragment(TENANT, d["delegation_id"], source_id="a", source_seq=1,
                            content={"v": 1}, actor_id="a")
        svc.close()

        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("update fragments set content_hash=? where source_seq=1",
                     ("0" * 64,))
        conn.commit()
        conn.close()
        with self.assertRaises(StateError):
            TraceEvidenceService(self.db_path)


class PolicyFileTest(unittest.TestCase):
    def test_shipped_policy_loads(self) -> None:
        policy = load_projection_policy()
        for role in ("security_administrator", "investigator", "auditor", "analyst"):
            self.assertIn(role, policy.roles)


if __name__ == "__main__":
    unittest.main()
