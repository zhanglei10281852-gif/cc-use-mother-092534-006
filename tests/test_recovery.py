"""服务重启后的状态恢复：未决分叉、缺口、封存与补充段全部从事件日志重建。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracechain.errors import ConflictingReport
from tracechain.service import TraceEvidenceService

TENANT = "tenant-a"


class RecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "trace.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_unresolved_forks_and_gaps_survive_restart(self) -> None:
        svc = TraceEvidenceService(self.db_path)
        fam = svc.create_family(TENANT, "case-restart", actor_id="op")
        did = svc.register_delegation(
            TENANT, fam, "parent", "指令", actor_id="op"
        ).view.delegation_id
        svc.report_fragment(TENANT, did, "s", 1, {"v": 1},
                            occurred_at="2026-09-25T10:00:00+08:00", reporter_id="r")
        svc.report_fragment(TENANT, did, "s", 2, {"v": "A"},
                            occurred_at="2026-09-25T10:01:00+08:00", reporter_id="r")
        try:
            svc.report_fragment(TENANT, did, "s", 2, {"v": "B"},
                                occurred_at="2026-09-25T10:02:00+08:00", reporter_id="r2")
        except ConflictingReport:
            pass
        # 第二个来源有缺口（只到 2，缺 1）
        svc.report_fragment(TENANT, did, "t", 2, {"v": 2},
                            occurred_at="2026-09-25T10:03:00+08:00", reporter_id="r")
        svc.close()

        # —— 重启 ——
        svc = TraceEvidenceService(self.db_path)
        pending = svc.pending_work(fam)
        self.assertEqual(len(pending.open_forks), 1)
        fork = pending.open_forks[0]
        self.assertEqual((fork.source, fork.seq), ("s", 2))
        self.assertEqual(len(fork.candidate_digests), 2)
        gapped = dict(pending.gapped_delegations)
        self.assertIn(did, gapped)
        self.assertEqual([(g.source, g.missing_seq) for g in gapped[did]], [("t", 1)])

        # 重启后继续裁决并封存：处理流程跨重启可延续
        svc.resolve_fork(fork.fork_id, resolution="accepted",
                         chosen_digest=fork.candidate_digests[0],
                         actor_id="judge", reason="重启后继续裁决")
        svc.report_fragment(TENANT, did, "t", 1, {"v": 1},
                            occurred_at="2026-09-25T09:59:00+08:00", reporter_id="r")
        seal = svc.seal_chain(did, sealed_by="op", declare_complete=True)
        self.assertTrue(svc._load().verify_chain(did))
        self.assertEqual(seal.fragment_count, 4)
        svc.close()

        # —— 再次重启，封存与裁决依旧成立 ——
        svc = TraceEvidenceService(self.db_path)
        status = svc.delegation_status(did)
        self.assertTrue(status["complete"])
        self.assertTrue(status["chain_valid"])
        self.assertEqual(svc.pending_work(fam).open_forks, ())
        svc.close()

    def test_overturned_seal_survives_restart(self) -> None:
        from tracechain.errors import ConflictingReport
        svc = TraceEvidenceService(self.db_path)
        fam = svc.create_family(TENANT, "case-overturn", actor_id="op")
        did = svc.register_delegation(
            TENANT, fam, "p", "i", actor_id="op", expected_count=1
        ).view.delegation_id
        svc.report_fragment(TENANT, did, "s", 1, {"v": "A"},
                            occurred_at="2026-09-25T10:00:00+08:00", reporter_id="r")
        svc.seal_chain(did, sealed_by="op")
        try:
            svc.report_fragment(TENANT, did, "s", 1, {"v": "B"},
                                occurred_at="2026-09-25T11:00:00+08:00", reporter_id="r2")
        except ConflictingReport as exc:
            svc.resolve_fork(exc.result.fork_id, resolution="accepted",
                             chosen_digest=exc.incoming_digest,
                             actor_id="judge", reason="新证据成立")
        svc.close()

        svc = TraceEvidenceService(self.db_path)
        pending = svc.pending_work(fam)
        self.assertEqual(len(pending.overturned_seals), 1)
        overturned_id, reason = pending.overturned_seals[0]
        self.assertEqual(overturned_id, did)
        self.assertIn("封存后", reason)
        svc.close()

    def test_replay_is_deterministic(self) -> None:
        svc = TraceEvidenceService(self.db_path)
        fam = svc.create_family(TENANT, "case-det", actor_id="op")
        did = svc.register_delegation(
            TENANT, fam, "p", "i", actor_id="op", expected_count=2
        ).view.delegation_id
        svc.report_fragment(TENANT, did, "s", 1, {"a": 1},
                            occurred_at="2026-09-25T10:00:00+08:00", reporter_id="r")
        svc.report_fragment(TENANT, did, "s", 2, {"a": 2},
                            occurred_at="2026-09-25T10:01:00+08:00", reporter_id="r")
        svc.seal_chain(did, sealed_by="op")
        head_1 = svc._load().seals[did].head_hash
        svc.close()

        svc = TraceEvidenceService(self.db_path)
        head_2 = svc._load().seals[did].head_hash
        self.assertEqual(head_1, head_2)
        svc.close()


if __name__ == "__main__":
    unittest.main()
