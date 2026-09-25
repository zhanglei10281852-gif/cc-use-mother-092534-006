"""稳定关联标识与幂等登记。"""
from __future__ import annotations

from tests._support import ServiceCase, TENANT
from tracechain.errors import FamilyFrozen
from tracechain.hashing import content_digest, stable_delegation_id, stable_family_id


class IdentifierTest(ServiceCase):
    def test_family_id_is_deterministic(self) -> None:
        a = self.svc.create_family("tenant-z", "case-77", actor_id="x")
        b = self.svc.create_family("tenant-z", "case-77", actor_id="x")
        expected = stable_family_id("tenant-z", "case-77")
        self.assertEqual(a, expected)
        self.assertEqual(a, b)

    def test_delegation_id_depends_on_instruction_and_parent(self) -> None:
        d1 = self.register("指令A", parent="p1")
        d2 = self.register("指令A", parent="p2")
        d3 = self.register("指令B", parent="p1")
        self.assertNotEqual(d1, d2)
        self.assertNotEqual(d1, d3)
        digest_same_parent = stable_delegation_id(
            TENANT, self.family, "p1", content_digest("指令A")
        )
        self.assertEqual(d1, digest_same_parent)

    def test_duplicate_delegation_confirms_without_new_event_chain(self) -> None:
        d1 = self.register("指令A")
        before = self.svc.store.count()
        reg = self.svc.register_delegation(
            TENANT, self.family, "parent-1", "指令A", actor_id="op-9",
        )
        after = self.svc.store.count()
        self.assertTrue(reg.confirmed)
        self.assertEqual(reg.view.delegation_id, d1)
        self.assertEqual(before, after)

    def test_frozen_family_rejects_delegation_and_fragment(self) -> None:
        did = self.register("指令A", expected_count=1)
        self.send(did, "s", 1, {"x": 1}, hour=10)
        self.svc.seal_chain(did, sealed_by="op-1")
        self.svc.freeze_family(self.family, actor_id="lead", reason="r")
        with self.assertRaises(FamilyFrozen):
            self.register("指令B")
        with self.assertRaises(FamilyFrozen):
            self.send(did, "s", 2, {"x": 2}, hour=11)
