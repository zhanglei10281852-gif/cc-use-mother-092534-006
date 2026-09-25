"""分叉开立、裁决队列与裁决规则。"""
from __future__ import annotations

from tests._support import ServiceCase
from tracechain.errors import AdjudicationError, ConflictingReport, UnresolvedFork


class ForkTest(ServiceCase):
    def _conflict(self, did, source="s1", seq=2):
        self.send(did, source, 1, {"n": 1}, hour=10)
        self.send(did, source, seq, {"n": 2, "v": "A"}, hour=11)
        try:
            self.svc.report_fragment(
                "tenant-a", did, source, seq, {"n": 2, "v": "B"},
                occurred_at="2026-09-25T11:30:00+08:00", reporter_id="reporter-2",
            )
            self.fail("冲突上报必须抛出 ConflictingReport")
        except ConflictingReport as exc:
            return exc

    def test_conflict_opens_fork_and_keeps_both_candidates(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        self.assertEqual(exc.result.status, "forked")
        forks = self.svc.list_forks(self.family)
        self.assertEqual(len(forks), 1)
        fork = forks[0]
        self.assertEqual(fork.status, "open")
        self.assertEqual(len(fork.candidate_digests), 2)
        self.assertEqual((fork.source, fork.seq), ("s1", 2))

    def test_open_fork_blocks_seal(self) -> None:
        did = self.register()
        self._conflict(did)
        with self.assertRaises(UnresolvedFork):
            self.svc.seal_chain(did, sealed_by="op-1", declare_complete=True)

    def test_adjudication_flow_accept_one_candidate(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        fork_id = exc.result.fork_id
        self.svc.start_adjudication(fork_id, adjudicator="judge", reason="比对来源")
        adjudicating = self.svc.list_forks(self.family)[0]
        self.assertEqual(adjudicating.status, "adjudicating")
        # 裁决中仍属未决，依旧禁止封存
        with self.assertRaises(UnresolvedFork):
            self.svc.seal_chain(did, sealed_by="op-1", declare_complete=True)
        winner = exc.existing_digest
        resolved = self.svc.resolve_fork(
            fork_id, resolution="accepted", chosen_digest=winner,
            actor_id="judge", reason="原始来源可印证",
        )
        self.assertEqual(resolved.status, "resolved")
        self.assertEqual(resolved.chosen_digest, winner)
        # 裁决后链可封存；败诉候选仍保留在接收台账中
        seal = self.svc.seal_chain(did, sealed_by="op-1", declare_complete=True)
        state = self.svc._load()
        accepted_ids = {fid for _, fid in seal.entries}
        self.assertIn(exc.result.existing.fragment_id, accepted_ids)
        self.assertNotIn(exc.result.fragment.fragment_id, accepted_ids)
        self.assertIn(exc.result.fragment.fragment_id,
                      {f.fragment_id for f in state.fragments_for_delegation(did)})

    def test_rejected_resolution_recreates_gap(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        self.svc.resolve_fork(
            exc.result.fork_id, resolution="rejected", actor_id="judge",
            reason="两个候选都无法印证",
        )
        gaps = self.svc.delegation_status(did)["gaps"]
        self.assertIn(("s1", 2), [(g.source, g.missing_seq) for g in gaps])

    def test_resolution_must_choose_known_candidate(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        with self.assertRaises(AdjudicationError):
            self.svc.resolve_fork(
                exc.result.fork_id, resolution="accepted",
                chosen_digest="sha256:deadbeef",
                actor_id="judge", reason="x",
            )

    def test_resolution_is_immutable(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        fid = exc.result.fork_id
        self.svc.resolve_fork(
            fid, resolution="rejected", actor_id="judge", reason="r1",
        )
        with self.assertRaises(AdjudicationError):
            self.svc.resolve_fork(
                fid, resolution="accepted", chosen_digest=exc.existing_digest,
                actor_id="judge2", reason="r2",
            )

    def test_third_distinct_candidate_merges_into_same_fork(self) -> None:
        did = self.register()
        exc = self._conflict(did)
        try:
            self.svc.report_fragment(
                "tenant-a", did, "s1", 2, {"n": 2, "v": "C"},
                occurred_at="2026-09-25T11:45:00+08:00", reporter_id="reporter-3",
            )
        except ConflictingReport:
            pass
        fork = self.svc.list_forks(self.family)[0]
        self.assertEqual(fork.fork_id, exc.result.fork_id)
        self.assertEqual(len(fork.candidate_digests), 3)

    def test_same_content_is_duplicate_not_fork(self) -> None:
        did = self.register()
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        result = self.svc.report_fragment(
            "tenant-a", did, "s1", 1, {"n": 1},
            occurred_at="2026-09-25T12:00:00+08:00", reporter_id="reporter-9",
        )
        self.assertEqual(result.status, "duplicate_confirmed")
        self.assertEqual(self.svc.list_forks(self.family), ())
