"""哈希链、接收顺序封存、迟到片段与缺口。"""
from __future__ import annotations

from tests._support import ServiceCase
from tracechain.errors import ChainNotComplete, ChainSealed
from tracechain.hashing import hash_entry


class ChainTest(ServiceCase):
    def test_hash_chain_links_in_reception_order(self) -> None:
        did = self.register(expected_count=3)
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.send(did, "s1", 3, {"n": 3}, hour=11)
        # 迟到 seq=2：逻辑时间线缺它，接收顺序上它排最后
        self.send(did, "s1", 2, {"n": 2}, hour=9)  # 业务时间更早
        seal = self.svc.seal_chain(did, sealed_by="op-1")

        state = self.svc._load()
        head = None
        order = []
        for entry_hash, fid in seal.entries:
            f = state.fragments[fid]
            self.assertEqual(entry_hash, hash_entry(head, f.source, f.seq, f.digest))
            head = entry_hash
            order.append(f.seq)
        self.assertEqual(head, seal.head_hash)
        # 封存顺序 = 接收顺序 [1,3,2]，不是逻辑序号顺序
        self.assertEqual(order, [1, 3, 2])
        self.assertTrue(state.verify_chain(did))

    def test_gap_blocks_seal(self) -> None:
        did = self.register()
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.send(did, "s1", 3, {"n": 3}, hour=11)
        gaps = self.svc.delegation_status(did)["gaps"]
        self.assertEqual([(g.source, g.missing_seq) for g in gaps], [("s1", 2)])
        with self.assertRaises(ChainNotComplete):
            self.svc.seal_chain(did, sealed_by="op-1")

    def test_expected_count_blocks_premature_seal(self) -> None:
        did = self.register(expected_count=3)
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.send(did, "s1", 2, {"n": 2}, hour=11)
        with self.assertRaises(ChainNotComplete):
            self.svc.seal_chain(did, sealed_by="op-1")

    def test_seal_is_idempotent_rejection(self) -> None:
        did = self.register(expected_count=1)
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.svc.seal_chain(did, sealed_by="op-1")
        with self.assertRaises(ChainSealed):
            self.svc.seal_chain(did, sealed_by="op-1")

    def test_late_new_sequence_goes_to_supplement_without_touching_seal(self) -> None:
        did = self.register(expected_count=2)
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.send(did, "s1", 2, {"n": 2}, hour=11)
        seal = self.svc.seal_chain(did, sealed_by="op-1")

        result = self.send(did, "s1", 3, {"n": 3}, hour=12)
        self.assertTrue(result.supplement)
        state = self.svc._load()
        # 封存快照头与条目数不变
        self.assertEqual(state.seals[did].head_hash, seal.head_hash)
        self.assertEqual(state.seals[did].fragment_count, 2)
        sup = state.supplement_segment(did)
        self.assertIsNotNone(sup)
        self.assertEqual(sup.anchor_head, seal.head_hash)
        self.assertEqual(len(sup.entries), 1)
        # 声明过完整后又出现迟到片段：不得再标完整
        complete, reason = state.delegation_complete(did)
        self.assertFalse(complete)
        self.assertIn("迟到", reason)

    def test_supplement_gap_is_detected(self) -> None:
        did = self.register(expected_count=1)
        self.send(did, "s1", 1, {"n": 1}, hour=10)
        self.svc.seal_chain(did, sealed_by="op-1")
        self.send(did, "s1", 3, {"n": 3}, hour=12)  # 跳过补充段序号 2
        state = self.svc._load()
        # 主链无缺口；补充段相对封存边界缺 2
        self.assertEqual(state.gaps(did), [])
        self.assertEqual([g.missing_seq for g in state.supplement_gaps(did)], [2])
        merged = self.svc.delegation_status(did)["gaps"]
        self.assertIn(("s1", 2), [(g.source, g.missing_seq) for g in merged])

    def test_multi_source_timelines_are_independent(self) -> None:
        did = self.register(expected_count=4)
        self.send(did, "agent-A", 1, {"a": 1}, hour=10)
        self.send(did, "agent-A", 2, {"a": 2}, hour=10)
        self.send(did, "agent-B", 1, {"b": 1}, hour=10)
        self.send(did, "agent-B", 2, {"b": 2}, hour=10)
        seal = self.svc.seal_chain(did, sealed_by="op-1")
        self.assertEqual(seal.fragment_count, 4)
        self.assertEqual(dict(seal.max_seq_by_source), {"agent-A": 2, "agent-B": 2})

    def test_empty_chain_cannot_be_sealed(self) -> None:
        did = self.register()
        with self.assertRaises(ChainNotComplete):
            self.svc.seal_chain(did, sealed_by="op-1", declare_complete=True)
