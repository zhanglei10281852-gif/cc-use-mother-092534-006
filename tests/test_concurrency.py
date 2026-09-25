"""并发接收：同序号竞争必须被串行化为“一条接收 + 一条分叉”。"""
from __future__ import annotations

import threading

from tests._support import ServiceCase
from tracechain.errors import ConflictingReport


class ConcurrencyTest(ServiceCase):
    def test_concurrent_same_seq_different_content_becomes_fork(self) -> None:
        did = self.register(expected_count=2)
        self.send(did, "s1", 1, {"n": 1}, hour=10)

        results: list[Exception | str] = []

        def send(value: str) -> None:
            try:
                r = self.svc.report_fragment(
                    "tenant-a", did, "s1", 2, {"v": value},
                    occurred_at="2026-09-25T11:00:00+08:00",
                    reporter_id=f"reporter-{value}",
                )
                results.append(r.status)
            except ConflictingReport:
                results.append("__conflict__")
            except Exception as exc:  # noqa: BLE001
                results.append(exc)

        threads = [
            threading.Thread(target=send, args=("X",)),
            threading.Thread(target=send, args=("Y",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(results), ["__conflict__", "accepted"])
        forks = self.svc.list_forks(self.family)
        self.assertEqual(len(forks), 1)
        self.assertEqual(len(forks[0].candidate_digests), 2)
