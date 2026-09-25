"""仅追加事件存储（SQLite）。

事件日志是唯一的持久化事实来源：

- 任何状态变化都在一个事务里追加事件，从不更新、不删除历史行。
- 服务重启后 :mod:`tracechain.state` 完整重放日志，重建链头、缺口、
  未决分叉与封存记录——未决分叉和缺口因此天然跨重启存续。
- ``seq_no`` 是存储层单调序号，``event_id`` 为业务幂等键（重放按
  ``event_id`` 去重，保证同一条事件不会因重试被登记两次）。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
create table if not exists event_log (
    event_id     text primary key,
    tenant       text not null,
    event_type   text not null,
    aggregate_id text not null,
    delegation_id text,
    seq_no       integer not null,
    occurred_at  text not null,
    actor_id     text not null,
    payload      text not null
);
create index if not exists idx_event_log_aggregate
    on event_log(tenant, aggregate_id, seq_no);
"""


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event_id: str
    tenant: str
    event_type: str
    aggregate_id: str
    delegation_id: str | None
    seq_no: int
    occurred_at: str
    actor_id: str
    payload: dict[str, Any]


class EventStore:
    """线程安全的 SQLite 追加事件存储。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        # check_same_thread=False + 自带写锁：所有写操作串行化。
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            row = self._conn.execute("select coalesce(max(seq_no), 0) from event_log").fetchone()
            self._next_seq: int = row[0] + 1

    def append(
        self,
        *,
        event_id: str,
        tenant: str,
        event_type: str,
        aggregate_id: str,
        occurred_at: str,
        actor_id: str,
        payload: dict[str, Any],
        delegation_id: str | None = None,
    ) -> StoredEvent:
        """追加一条事件；相同 ``event_id`` 重放时返回已存在事件（幂等）。"""
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        with self._lock:
            existing = self._conn.execute(
                "select event_id from event_log where event_id = ?", (event_id,)
            ).fetchone()
            if existing is not None:
                raise _EventExists(event_id)
            seq_no = self._next_seq
            self._conn.execute(
                "insert into event_log values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    tenant,
                    event_type,
                    aggregate_id,
                    delegation_id,
                    seq_no,
                    occurred_at,
                    actor_id,
                    body,
                ),
            )
            self._conn.commit()
            self._next_seq += 1
        return StoredEvent(
            event_id=event_id,
            tenant=tenant,
            event_type=event_type,
            aggregate_id=aggregate_id,
            delegation_id=delegation_id,
            seq_no=seq_no,
            occurred_at=occurred_at,
            actor_id=actor_id,
            payload=payload,
        )

    def append_many(self, events: list[dict[str, Any]]) -> list[StoredEvent]:
        """原子地成批追加（一次接收触发多条事件时使用，例如分叉）。

        任一 event_id 已存在则整批回滚——调用方负责先做业务幂等判断。
        """
        with self._lock, self._conn:
            stored: list[StoredEvent] = []
            for raw in events:
                event_id = raw["event_id"]
                if self._conn.execute(
                    "select 1 from event_log where event_id = ?", (event_id,)
                ).fetchone():
                    raise _EventExists(event_id)
                seq_no = self._next_seq
                self._conn.execute(
                    "insert into event_log values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        raw["tenant"],
                        raw["event_type"],
                        raw["aggregate_id"],
                        raw.get("delegation_id"),
                        seq_no,
                        raw["occurred_at"],
                        raw["actor_id"],
                        json.dumps(raw["payload"], ensure_ascii=False, sort_keys=True, default=str),
                    ),
                )
                self._next_seq += 1
                stored.append(
                    StoredEvent(
                        event_id=event_id,
                        tenant=raw["tenant"],
                        event_type=raw["event_type"],
                        aggregate_id=raw["aggregate_id"],
                        delegation_id=raw.get("delegation_id"),
                        seq_no=seq_no,
                        occurred_at=raw["occurred_at"],
                        actor_id=raw["actor_id"],
                        payload=raw["payload"],
                    )
                )
            return stored

    def replay(self, tenant: str | None = None) -> Iterator[StoredEvent]:
        """按存储序号重放全部（或指定租户）事件。"""
        with self._lock:
            if tenant is None:
                rows = self._conn.execute(
                    "select * from event_log order by seq_no"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "select * from event_log where tenant = ? order by seq_no", (tenant,)
                ).fetchall()
        for row in rows:
            yield StoredEvent(
                event_id=row["event_id"],
                tenant=row["tenant"],
                event_type=row["event_type"],
                aggregate_id=row["aggregate_id"],
                delegation_id=row["delegation_id"],
                seq_no=row["seq_no"],
                occurred_at=row["occurred_at"],
                actor_id=row["actor_id"],
                payload=json.loads(row["payload"]),
            )

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("select count(*) from event_log").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _EventExists(Exception):
    """内部异常：事件 ID 已存在（成批追加时触发回滚）。"""
