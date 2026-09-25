"""篡改检测：改写事件存储中的载荷或顺序必须被核验发现。"""
from __future__ import annotations

import json

from tests._support import ServiceCase


class TamperDetectionTest(ServiceCase):
    def _sealed_chain(self):
        did = self.register(expected_count=2)
        self.send(did, "s1", 1, {"v": "a"}, hour=10)
        self.send(did, "s1", 2, {"v": "b"}, hour=11)
        seal = self.svc.seal_chain(did, sealed_by="op")
        return did, seal

    def test_payload_tampering_is_detected(self) -> None:
        did, seal = self._sealed_chain()
        self.assertTrue(self.svc._load().verify_chain(did))

        # 直接篡改 SQLite 中片段事件的载荷（绕过服务层）
        conn = self.svc.store._conn
        row = conn.execute(
            "select payload from event_log where event_type='fragment.accepted' limit 1"
        ).fetchone()
        body = json.loads(row[0])
        body["payload"] = {"v": "TAMPERED"}
        conn.execute(
            "update event_log set payload=? where event_type='fragment.accepted' limit 1",
            (json.dumps(body, ensure_ascii=False),),
        )
        conn.commit()
        self.assertFalse(self.svc._load().verify_chain(did))

    def test_reordering_is_detected(self) -> None:
        did, seal = self._sealed_chain()
        # 封存条目顺序被调换：哈希链应当断裂
        conn = self.svc.store._conn
        row = conn.execute(
            "select payload from event_log where event_type='chain.sealed'"
        ).fetchone()
        body = json.loads(row[0])
        body["entries"] = list(reversed(body["entries"]))
        conn.execute(
            "update event_log set payload=? where event_type='chain.sealed'",
            (json.dumps(body, ensure_ascii=False),),
        )
        conn.commit()
        self.assertFalse(self.svc._load().verify_chain(did))
