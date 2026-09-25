"""裁决之后的接收语义：被否决内容禁入、补送填补、挑战重开新案。"""
from __future__ import annotations

from tests._support import ServiceCase
from tracechain.errors import (
    ConflictingReport,
    DisavowedContent,
)


class PostAdjudicationTest(ServiceCase):
    def _two_way_fork(self, did, seq=2):
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.send(did, "s1", seq, {"v": "A"}, hour=11)
        try:
            self.svc.report_fragment(
                "tenant-a", did, "s1", seq, {"v": "B"},
                occurred_at="2026-09-25T11:30:00+08:00", reporter_id="r2",
            )
        except ConflictingReport as exc:
            return exc
        self.fail("应当产生分叉")

    def test_rejected_content_cannot_reenter_chain(self) -> None:
        did = self.register()
        exc = self._two_way_fork(did)
        self.svc.resolve_fork(
            exc.result.fork_id, resolution="rejected", actor_id="judge",
            reason="两个候选均不可信",
        )
        # 原封不动重发被否决的 A：明确拒绝，而不是当作新片段或重复
        with self.assertRaises(DisavowedContent):
            self.send(did, "s1", 2, {"v": "A"}, hour=12)

    def test_new_content_after_rejection_fills_gap_and_allows_seal(self) -> None:
        did = self.register()
        exc = self._two_way_fork(did)
        self.svc.resolve_fork(
            exc.result.fork_id, resolution="rejected", actor_id="judge",
            reason="两个候选均不可信",
        )
        self.assertEqual(
            [(g.source, g.missing_seq) for g in self.svc.delegation_status(did)["gaps"]],
            [("s1", 2)],
        )
        # 补送全新内容 C：正常接收，填补缺口
        result = self.svc.report_fragment(
            "tenant-a", did, "s1", 2, {"v": "C"},
            occurred_at="2026-09-25T12:00:00+08:00", reporter_id="r3",
        )
        self.assertEqual(result.status, "accepted")
        self.assertEqual(self.svc.delegation_status(did)["gaps"], ())
        seal = self.svc.seal_chain(did, sealed_by="op", declare_complete=True)
        accepted = [
            self.svc._load().fragments[fid] for _, fid in seal.entries
        ]
        self.assertEqual([f.seq for f in accepted], [1, 2])
        self.assertEqual(accepted[1].payload, {"v": "C"})
        # 败诉候选 A、B 仍保留在接收台账中可审计（seq1 + A + B + C）
        ledger = self.svc._load().fragments_for_delegation(did)
        digests = {f.digest for f in ledger}
        self.assertEqual(len(digests), 4)

    def test_challenge_to_accepted_ruling_opens_new_fork_case(self) -> None:
        did = self.register()
        exc = self._two_way_fork(did)
        winner = exc.existing_digest  # A
        self.svc.resolve_fork(
            exc.result.fork_id, resolution="accepted", chosen_digest=winner,
            actor_id="judge", reason="A 可印证",
        )
        # 当选摘要再次上报：重复确认
        dup = self.send(did, "s1", 2, {"v": "A"}, hour=12)
        self.assertEqual(dup.status, "duplicate_confirmed")
        # 全新内容 D 挑战已生效裁决：必须新开分叉案，绝不静默替换
        with self.assertRaises(ConflictingReport) as caught:
            self.svc.report_fragment(
                "tenant-a", did, "s1", 2, {"v": "D"},
                occurred_at="2026-09-25T12:30:00+08:00", reporter_id="r4",
            )
        new_fork_id = caught.exception.result.fork_id
        self.assertNotEqual(new_fork_id, exc.result.fork_id)
        forks = self.svc.list_forks(self.family)
        self.assertEqual(len(forks), 2)
        # 旧裁决保持 resolved 不被改写
        old = self.svc._load().forks[exc.result.fork_id]
        self.assertEqual(old.status, "resolved")
        self.assertEqual(old.chosen_digest, winner)
        # 新案未决期间禁止封存
        from tracechain.errors import UnresolvedFork
        with self.assertRaises(UnresolvedFork):
            self.svc.seal_chain(did, sealed_by="op", declare_complete=True)

    def test_accept_new_challenger_disavows_former_winner(self) -> None:
        did = self.register()
        exc = self._two_way_fork(did)
        self.svc.resolve_fork(
            exc.result.fork_id, resolution="accepted",
            chosen_digest=exc.existing_digest, actor_id="judge", reason="r",
        )
        with self.assertRaises(ConflictingReport) as caught:
            self.svc.report_fragment(
                "tenant-a", did, "s1", 2, {"v": "D"},
                occurred_at="2026-09-25T12:30:00+08:00", reporter_id="r4",
            )
        new_fork = caught.exception.result
        from tracechain.hashing import content_digest
        d_digest = content_digest({"v": "D"})
        self.svc.resolve_fork(
            new_fork.fork_id, resolution="accepted", chosen_digest=d_digest,
            actor_id="judge2", reason="新证据 D 成立",
        )
        seal = self.svc.seal_chain(did, sealed_by="op", declare_complete=True)
        sealed_payloads = [
            self.svc._load().fragments[fid].payload for _, fid in seal.entries
        ]
        self.assertIn({"v": "D"}, sealed_payloads)
        self.assertNotIn({"v": "A"}, sealed_payloads)
        # 前当选者 A 已被新裁决否决，重发被拒
        with self.assertRaises(DisavowedContent):
            self.send(did, "s1", 2, {"v": "A"}, hour=13)
