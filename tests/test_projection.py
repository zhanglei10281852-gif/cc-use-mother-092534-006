"""角色投影与读取审计。"""
from __future__ import annotations

from tests._support import ServiceCase
from tracechain.errors import AccessDenied

SENSITIVE = {
    "action": "http_post",
    "api_key": "sk-secret-1234567890",
    "user_email": "victim@example.com",
    "user_phone": "13800138000",
    "headers": {"authorization": "Bearer abc.def.ghi"},
    "tenant_id": "tenant-b",
}


class ProjectionTest(ServiceCase):
    def _sealed(self):
        did = self.register(expected_count=1)
        self.send(did, "agent-A", 1, SENSITIVE, hour=10)
        self.svc.seal_chain(did, sealed_by="op-1")
        return did

    def test_all_roles_share_same_original_digest(self) -> None:
        self._sealed()
        digests = set()
        for role in ("investigator", "auditor", "admin", "cross_tenant_reviewer"):
            entries, _ = self.svc.read_family(
                self.family, actor_id="u", role=role,
                viewer_tenant="tenant-a", purpose="p",
            )
            digests.add(entries[0].projection.original_digest)
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests.pop(), entries[0].fragment.digest)

    def test_investigator_sees_masked_pii_but_never_credentials(self) -> None:
        self._sealed()
        entries, _ = self.svc.read_family(
            self.family, actor_id="u", role="investigator",
            viewer_tenant="tenant-a", purpose="p",
        )
        content = entries[0].projection.content
        self.assertNotIn("sk-secret", str(content))
        self.assertTrue(content["api_key"].startswith("⟨redacted:credential"))
        self.assertTrue(content["user_email"].endswith("@example.com"))
        self.assertIn("***", content["user_email"])
        self.assertNotIn("victim", content["user_email"])
        self.assertNotIn("Bearer", str(content))
        self.assertNotIn("tenant_id", content)  # 跨租户字段剔除

    def test_auditor_sees_only_tags(self) -> None:
        self._sealed()
        entries, _ = self.svc.read_family(
            self.family, actor_id="u", role="auditor",
            viewer_tenant="tenant-a", purpose="p",
        )
        content = entries[0].projection.content
        self.assertNotIn("sk-secret", str(content))
        self.assertNotIn("victim", str(content))
        self.assertEqual(content["user_email"], "⟨redacted:pii⟩")

    def test_admin_sees_plaintext_but_not_cross_tenant_field(self) -> None:
        self._sealed()
        entries, _ = self.svc.read_family(
            self.family, actor_id="u", role="admin",
            viewer_tenant="tenant-a", purpose="p",
        )
        content = entries[0].projection.content
        self.assertEqual(content["api_key"], "sk-secret-1234567890")
        self.assertEqual(content["user_email"], "victim@example.com")
        self.assertNotIn("tenant_id", content)

    def test_cross_tenant_receiver_role_sees_tagged_other_tenant(self) -> None:
        self._sealed()
        entries, _ = self.svc.read_family(
            self.family, actor_id="u", role="cross_tenant_reviewer",
            viewer_tenant="tenant-a", purpose="p",
        )
        content = entries[0].projection.content
        self.assertEqual(content["tenant_id"], "⟨cross-tenant:tenant-b⟩")
        self.assertNotIn("Bearer", str(content))

    def test_family_level_tenant_isolation(self) -> None:
        self._sealed()
        with self.assertRaises(AccessDenied):
            self.svc.read_family(
                self.family, actor_id="u", role="admin",
                viewer_tenant="tenant-b", purpose="p",
            )

    def test_every_read_is_audited_with_fingerprint_and_digest(self) -> None:
        self._sealed()
        _, audit1 = self.svc.read_family(
            self.family, actor_id="u1", role="auditor",
            viewer_tenant="tenant-a", purpose="检查A",
        )
        _, audit2 = self.svc.read_family(
            self.family, actor_id="u2", role="admin",
            viewer_tenant="tenant-a", purpose="检查B",
        )
        audits = self.svc.list_audits(self.family)
        self.assertEqual(len(audits), 2)
        self.assertEqual({a.actor_id for a in audits}, {"u1", "u2"})
        self.assertNotEqual(audit1.fingerprint, audit2.fingerprint)
        self.assertTrue(all(a.projection_policy_version for a in audits))
        self.assertTrue(all(a.result_digest.startswith("sha256:") for a in audits))

    def test_export_manifest_proves_composition(self) -> None:
        did = self._sealed()
        bundle = self.svc.export_family(
            self.family, actor_id="lead", role="auditor",
            viewer_tenant="tenant-a", purpose="移交",
        )
        self.assertTrue(bundle.record.complete)
        self.assertEqual(len(bundle.manifest["fragment_evidence"]), 1)
        evidence = bundle.manifest["fragment_evidence"][0]
        self.assertEqual(evidence["original_digest"], bundle.entries[0].fragment.digest)
        self.assertTrue(bundle.manifest["seal_heads"])
        self.assertTrue(self.svc.verify_export(bundle.record.export_id))
        # 导出本身也是一次被审计的读取
        actions = {a.action for a in self.svc.list_audits(self.family)}
        self.assertIn("export.create", actions)

    def test_incomplete_export_is_never_marked_complete(self) -> None:
        did = self.register(expected_count=3)
        self.send(did, "s", 1, {"x": 1}, hour=10)
        self.send(did, "s", 2, {"x": 2}, hour=11)
        bundle = self.svc.export_family(
            self.family, actor_id="lead", role="auditor",
            viewer_tenant="tenant-a", purpose="阶段性导出",
        )
        self.assertFalse(bundle.record.complete)
        self.assertTrue(bundle.manifest["notes"])
