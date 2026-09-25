"""封存后争议：封存不可变，但裁决必须影响导出构成与完整性标志。"""
from __future__ import annotations

from tests._support import ServiceCase
from tracechain.errors import ConflictingReport


class PostSealForkTest(ServiceCase):
    def test_post_seal_conflict_resolution_is_visible_in_export(self) -> None:
        did = self.register(expected_count=2)
        self.send(did, "s1", 1, {"v": 1}, hour=10)
        original = self.send(did, "s1", 2, {"v": "A"}, hour=11)
        self.svc.seal_chain(did, sealed_by="op")

        # 封存后对 seq2 的冲突内容
        with self.assertRaises(ConflictingReport) as caught:
            self.svc.report_fragment(
                "tenant-a", did, "s1", 2, {"v": "B-new"},
                occurred_at="2026-09-25T13:00:00+08:00", reporter_id="r2",
            )
        result = caught.exception.result
        fork = self.svc.list_forks(self.family)[0]
        self.assertTrue(fork.after_seal)

        # 未裁决时：封存哈希自洽，但争议未消，导出不得标完整
        pending = self.svc.export_family(
            self.family, actor_id="op", role="auditor",
            viewer_tenant="tenant-a", purpose="p",
        )
        self.assertTrue(self.svc._load().verify_chain(did))
        self.assertFalse(pending.record.complete)
        self.assertTrue(any("未裁决分叉" in n for n in pending.manifest["notes"]))

        # 裁决接受新内容 B-new（先走"进入裁决"，验证状态流转不丢 after_seal 标记）
        from tracechain.hashing import content_digest
        self.svc.start_adjudication(fork.fork_id, adjudicator="judge", reason="比对封存后新证据")
        self.svc.resolve_fork(
            fork.fork_id, resolution="accepted",
            chosen_digest=content_digest({"v": "B-new"}),
            actor_id="judge", reason="新证据成立",
        )

        # 链的哈希自洽性仍成立（封存没被动过）
        self.assertTrue(self.svc._load().verify_chain(did))
        # 但完整性必须降级：封存构成与现行规范不一致
        complete, reason = self.svc._load().delegation_complete(did)
        self.assertFalse(complete)
        self.assertIn("封存后", reason)

        bundle = self.svc.export_family(
            self.family, actor_id="legal", role="auditor",
            viewer_tenant="tenant-a", purpose="法务",
        )
        self.assertFalse(bundle.record.complete)
        # 新当选片段出现在导出组成中，封存后发现被显式列出
        self.assertIn(result.fragment.fragment_id, bundle.record.fragment_ids)
        findings = bundle.manifest["post_seal_findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fork_id"], fork.fork_id)
        self.assertIn(original.fragment.fragment_id, findings[0]["sealed_fragments_disavowed"])
        # 封存头保持不变
        self.assertEqual(
            bundle.manifest["seal_heads"][did]["seal_head"],
            self.svc._load().seals[did].head_hash,
        )
