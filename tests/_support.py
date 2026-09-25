"""测试公共夹具。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tracechain.service import TraceEvidenceService  # noqa: E402

TENANT = "tenant-a"
TZ = "+08:00"


def ts(hour: int, minute: int = 0, day: int = 25) -> str:
    return f"2026-09-{day:02d}T{hour:02d}:{minute:02d}:00{TZ}"


class ServiceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TraceEvidenceService(":memory:")
        self.family = self.svc.create_family(TENANT, f"case-{self._testMethodName}", actor_id="op-1")

    def tearDown(self) -> None:
        self.svc.close()

    def register(self, instruction: str = "调查指令", *, expected_count=None, parent="parent-1"):
        reg = self.svc.register_delegation(
            TENANT, self.family, parent, instruction,
            actor_id="op-1", expected_count=expected_count,
        )
        return reg.view.delegation_id

    def send(self, did: str, source: str, seq: int, payload, *, hour: int):
        return self.svc.report_fragment(
            TENANT, did, source, seq, payload,
            occurred_at=ts(hour), reporter_id="reporter-1",
        )
