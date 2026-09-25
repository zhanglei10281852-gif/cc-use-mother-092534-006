"""追踪证据服务。

一个 :class:`TraceEvidenceService` 实例绑定一个 SQLite 数据库文件；
所有写操作在单事务内落库并同时追加全局哈希事件日志。
重启后构造实例会自动执行 :meth:`recover` 校验。

两条时间线严格分离：

- **接收顺序**（``chain_entries``）：片段到达即追加的哈希链，WORM，
  封存后新证据仍可追加到链尾，但封存快照指向当时的链头；
- **逻辑时间线**（按 ``source_seq`` 重组）：迟到片段补入对应位置，
  分叉以裁决记录确定胜出片段。封存时把时间线快照写入 ``chain.sealed``
  事件，之后任何重算都不能改变该快照。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .crypto import (
    CHAIN_ALGORITHM_VERSION,
    chain_entry_hash,
    event_hash,
    hash_content,
    seal_root_hash,
    sha256_hex,
)
from .errors import (
    AccessDeniedError,
    ChainSealedError,
    FrozenError,
    NotFoundError,
    StateError,
    ValidationError,
)
from .projections import (
    ProjectionPolicy,
    extract_labels,
    load_projection_policy,
    make_projection,
    strip_label_annotations,
)
from .store import TraceStore

GENESIS_HASH = sha256_hex(["GENESIS", CHAIN_ALGORITHM_VERSION])

# 默认仅安全管理员可读取未投影的原始证据。
DEFAULT_RAW_ROLES = frozenset({"security_administrator"})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class TraceEvidenceService:
    def __init__(
        self,
        store: str | Path | TraceStore,
        *,
        policy: ProjectionPolicy | None = None,
        clock: Callable[[], str] | None = None,
        raw_reader_roles: Iterable[str] = DEFAULT_RAW_ROLES,
    ):
        if isinstance(store, TraceStore):
            self.store = store
            self._owns_store = False
        else:
            self.store = TraceStore(store)
            self._owns_store = True
        self.conn = self.store.conn
        self.policy = policy or load_projection_policy()
        self.clock = clock or _utc_now_iso
        self.raw_reader_roles = frozenset(raw_reader_roles)
        self.recovery_report = self.recover()

    def close(self) -> None:
        if self._owns_store:
            self.store.close()

    def __enter__(self) -> "TraceEvidenceService":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ 内部

    def _now(self) -> str:
        return self.clock()

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        event_type: str,
        aggregate_kind: str,
        aggregate_id: str,
        actor_id: str,
        payload: dict[str, Any],
        occurred_at: str | None = None,
    ) -> int:
        payload_text = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        payload_hash = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        last = conn.execute("select event_seq, entry_hash from events order by event_seq desc limit 1").fetchone()
        prev_hash = last["entry_hash"] if last else GENESIS_HASH
        event_id = "evt-" + uuid.uuid4().hex[:18]
        ts = occurred_at or self._now()
        fields = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "aggregate_kind": aggregate_kind,
            "aggregate_id": aggregate_id,
            "occurred_at": ts,
            "actor_id": actor_id,
            "payload_hash": payload_hash,
        }
        entry_hash = event_hash(prev_hash, fields)
        cur = conn.execute(
            "insert into events(event_id, tenant_id, event_type, aggregate_kind, aggregate_id, "
            "occurred_at, actor_id, payload_text, payload_hash, prev_hash, entry_hash) "
            "values (:event_id, :tenant_id, :event_type, :aggregate_kind, :aggregate_id, "
            ":occurred_at, :actor_id, :payload_text, :payload_hash, :prev_hash, :entry_hash)",
            {**fields, "payload_text": payload_text, "prev_hash": prev_hash, "entry_hash": entry_hash},
        )
        return int(cur.lastrowid)

    def _family(self, conn: sqlite3.Connection, tenant_id: str, family_id: str) -> sqlite3.Row:
        row = conn.execute(
            "select * from task_families where tenant_id=? and family_id=?",
            (tenant_id, family_id),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"任务族不存在：{family_id}")
        return row

    def _delegation(self, conn: sqlite3.Connection, tenant_id: str, delegation_id: str) -> sqlite3.Row:
        row = conn.execute(
            "select * from delegations where tenant_id=? and delegation_id=?",
            (tenant_id, delegation_id),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"委派不存在：{delegation_id}")
        return row

    def _ensure_writable_family(self, family: sqlite3.Row) -> None:
        if family["status"] == "frozen":
            raise FrozenError(f"任务族已冻结：{family['family_id']}")

    def _fragment_payload(self, fragment: sqlite3.Row | dict[str, Any]) -> Any:
        return json.loads(fragment["content_text"])

    def _fragment_labels(self, fragment: sqlite3.Row | dict[str, Any]) -> dict[str, list[str]]:
        raw = fragment["labels_text"]
        return json.loads(raw) if raw else {}

    def _seal_snapshot(
        self, conn: sqlite3.Connection, delegation_id: str
    ) -> dict[str, Any] | None:
        """封存时刻写入 chain.sealed 事件的快照，封存后永不重算。"""
        row = conn.execute(
            "select payload_text from events where aggregate_kind='delegation' "
            "and aggregate_id=? and event_type='chain.sealed' order by event_seq limit 1",
            (delegation_id,),
        ).fetchone()
        return json.loads(row["payload_text"]) if row else None

    def _recompute_state(self, conn: sqlite3.Connection, delegation: sqlite3.Row) -> str:
        """根据缺口与分叉重新派生收集状态。封存是终态，不参与重算。"""
        if delegation["status"] == "sealed":
            return "sealed"
        forks = conn.execute(
            "select status from fork_cases where delegation_id=? and status in ('open','adjudicating')",
            (delegation["delegation_id"],),
        ).fetchall()
        if forks:
            state = "adjudicating" if any(f["status"] == "adjudicating" for f in forks) else "forked"
        else:
            gaps = conn.execute(
                "select count(*) as c from gaps where delegation_id=? and status='open'",
                (delegation["delegation_id"],),
            ).fetchone()["c"]
            state = "gapped" if gaps else "collecting"
        conn.execute(
            "update delegations set status=? where delegation_id=?",
            (state, delegation["delegation_id"]),
        )
        return state

    def _refresh_gaps(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        delegation: sqlite3.Row,
        actor_id: str,
    ) -> list[str]:
        """对 1..expected_total 全量协调缺口，返回本次状态迁移事件列表。

        - 序列号可用（存在已接收/胜出片段且无活跃分叉）-> open 缺口记 filled；
        - 序列号不可用（从未到达，或曾补齐后被 reject_all）-> open，缺位重开也记事件；
        - 活跃分叉期间维持缺口原状，由分叉本身阻塞封存。
        """
        delegation_id = delegation["delegation_id"]
        usable_seqs = {
            r["source_seq"]
            for r in conn.execute(
                "select distinct source_seq from fragments "
                "where delegation_id=? and status not in ('rejected', 'candidate')",
                (delegation_id,),
            )
        }
        contested = {
            r["source_seq"]
            for r in conn.execute(
                "select source_seq from fork_cases where delegation_id=? "
                "and status in ('open','adjudicating')",
                (delegation_id,),
            )
        }
        upper = delegation["expected_total"]
        if upper is None:
            return []
        emitted: list[str] = []
        for missing in range(1, upper + 1):
            row = conn.execute(
                "select status from gaps where delegation_id=? and missing_seq=?",
                (delegation_id, missing),
            ).fetchone()
            if missing in usable_seqs and missing not in contested:
                if row is not None and row["status"] == "open":
                    filler = conn.execute(
                        "select fragment_id from fragments where delegation_id=? and source_seq=? "
                        "and status not in ('rejected', 'candidate') order by received_at limit 1",
                        (delegation_id, missing),
                    ).fetchone()
                    conn.execute(
                        "update gaps set status='filled', filled_fragment_id=coalesce(filled_fragment_id, ?), "
                        "filled_at=? where delegation_id=? and missing_seq=?",
                        (filler["fragment_id"] if filler else None, self._now(),
                         delegation_id, missing),
                    )
                    self._append_event(
                        conn,
                        tenant_id=tenant_id,
                        event_type="gap.filled",
                        aggregate_kind="delegation",
                        aggregate_id=delegation_id,
                        actor_id=actor_id,
                        payload={"missing_seq": missing,
                                 "fragment_id": filler["fragment_id"] if filler else None},
                    )
                    emitted.append("gap.filled")
            elif missing not in contested:
                if row is None or row["status"] == "filled":
                    # 从未登记 -> 新缺口；曾补齐但又失效（reject_all）-> 缺口重开。
                    seq = self._append_event(
                        conn,
                        tenant_id=tenant_id,
                        event_type="gap.detected",
                        aggregate_kind="delegation",
                        aggregate_id=delegation_id,
                        actor_id=actor_id,
                        payload={"missing_seq": missing, "reopened": row is not None},
                    )
                    if row is None:
                        conn.execute(
                            "insert into gaps(tenant_id, delegation_id, missing_seq, status, "
                            "detected_event_seq, detected_at) values (?, ?, ?, 'open', ?, ?)",
                            (tenant_id, delegation_id, missing, seq, self._now()),
                        )
                    else:
                        conn.execute(
                            "update gaps set status='open', detected_event_seq=?, detected_at=?, "
                            "filled_fragment_id=NULL, filled_at=NULL "
                            "where delegation_id=? and missing_seq=?",
                            (seq, self._now(), delegation_id, missing),
                        )
                    emitted.append("gap.detected")
        return emitted

    # ---------------------------------------------------------- 任务族 / 委派

    def create_family(
        self,
        tenant_id: str,
        family_id: str,
        root_task_id: str,
        *,
        title: str | None = None,
        actor_id: str,
    ) -> dict[str, Any]:
        with self.conn:
            existing = self.conn.execute(
                "select 1 from task_families where tenant_id=? and family_id=?",
                (tenant_id, family_id),
            ).fetchone()
            if existing:
                raise ValidationError(f"任务族标识已存在：{family_id}")
            ts = self._now()
            self.conn.execute(
                "insert into task_families(tenant_id, family_id, root_task_id, title, status, "
                "created_at, created_by) values (?, ?, ?, ?, 'open', ?, ?)",
                (tenant_id, family_id, root_task_id, title, ts, actor_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="family.created",
                aggregate_kind="family",
                aggregate_id=family_id,
                actor_id=actor_id,
                payload={"root_task_id": root_task_id, "title": title},
                occurred_at=ts,
            )
        return self.get_family(tenant_id, family_id, reader_id=actor_id, role="system")

    def freeze_family(
        self, tenant_id: str, family_id: str, *, actor_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        with self.conn:
            family = self._family(self.conn, tenant_id, family_id)
            if family["status"] == "frozen":
                raise StateError("任务族已处于冻结状态")
            ts = self._now()
            self.conn.execute(
                "update task_families set status='frozen', frozen_at=?, frozen_by=? "
                "where tenant_id=? and family_id=?",
                (ts, actor_id, tenant_id, family_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="family.frozen",
                aggregate_kind="family",
                aggregate_id=family_id,
                actor_id=actor_id,
                payload={"reason": reason},
                occurred_at=ts,
            )
        return _row(self._family(self.conn, tenant_id, family_id))  # type: ignore[return-value]

    def release_family(
        self, tenant_id: str, family_id: str, *, actor_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        with self.conn:
            family = self._family(self.conn, tenant_id, family_id)
            if family["status"] != "frozen":
                raise StateError("仅冻结状态的任务族可以解冻")
            ts = self._now()
            self.conn.execute(
                "update task_families set status='released', released_at=?, released_by=? "
                "where tenant_id=? and family_id=?",
                (ts, actor_id, tenant_id, family_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="family.released",
                aggregate_kind="family",
                aggregate_id=family_id,
                actor_id=actor_id,
                payload={"reason": reason},
                occurred_at=ts,
            )
        return _row(self._family(self.conn, tenant_id, family_id))  # type: ignore[return-value]

    def create_delegation(
        self,
        tenant_id: str,
        family_id: str,
        parent_task_id: str,
        child_task_id: str,
        instruction: Any,
        *,
        expected_total: int | None = None,
        actor_id: str,
        delegation_id: str | None = None,
    ) -> dict[str, Any]:
        """登记一次委派。

        委派关联标识由 ``租户+任务族+父子任务+指令摘要`` 确定性派生：
        同一委派的重复上报拿到同一标识，只确认已有记录（``deduplicated=True``）。
        """
        if expected_total is not None and expected_total < 1:
            raise ValidationError("expected_total 必须为正整数")
        clean_instruction = strip_label_annotations(instruction)
        instruction_hash = hash_content(clean_instruction)
        correlation_key = sha256_hex(
            [tenant_id, family_id, parent_task_id, child_task_id, instruction_hash]
        )[:16]
        resolved_id = delegation_id or f"dlg-{correlation_key}"
        instruction_text = instruction if isinstance(instruction, str) else json.dumps(
            clean_instruction, sort_keys=True, ensure_ascii=False
        )
        with self.conn:
            family = self._family(self.conn, tenant_id, family_id)
            self._ensure_writable_family(family)
            existing = self.conn.execute(
                "select * from delegations where tenant_id=? and family_id=? and correlation_key=?",
                (tenant_id, family_id, correlation_key),
            ).fetchone()
            if existing is not None:
                if expected_total is not None and existing["expected_total"] is not None \
                        and expected_total != existing["expected_total"]:
                    raise ValidationError(
                        "同一委派重复上报但期望片段总数不一致："
                        f"{existing['expected_total']} != {expected_total}"
                    )
                result = _row(existing)
                result["deduplicated"] = True
                return result
            ts = self._now()
            event_seq = self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="delegation.created",
                aggregate_kind="delegation",
                aggregate_id=resolved_id,
                actor_id=actor_id,
                payload={
                    "family_id": family_id,
                    "parent_task_id": parent_task_id,
                    "child_task_id": child_task_id,
                    "instruction_hash": instruction_hash,
                    "expected_total": expected_total,
                    "correlation_key": correlation_key,
                },
                occurred_at=ts,
            )
            self.conn.execute(
                "insert into delegations(tenant_id, delegation_id, family_id, parent_task_id, "
                "child_task_id, instruction_hash, instruction_text, correlation_key, expected_total, "
                "status, created_event_seq, created_at, created_by) "
                "values (?, ?, ?, ?, ?, ?, ?, ?, ?, 'collecting', ?, ?, ?)",
                (tenant_id, resolved_id, family_id, parent_task_id, child_task_id, instruction_hash,
                 instruction_text, correlation_key, expected_total, event_seq, ts, actor_id),
            )
        row = self._delegation(self.conn, tenant_id, resolved_id)
        result = _row(row)
        result["deduplicated"] = False
        return result

    # ------------------------------------------------------------------ 片段

    def report_fragment(
        self,
        tenant_id: str,
        delegation_id: str,
        *,
        source_id: str,
        source_seq: int,
        content: Any,
        actor_id: str,
        labels: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """接收一个追踪片段。

        返回 ``outcome``：

        - ``duplicated``：来源序列号与内容摘要完全一致，仅确认（confirmations+1）；
        - ``candidate``：同序列号出现不同内容，已进入分叉案件等待裁决；
        - ``received``：新片段，已按接收顺序链接。

        封存后到达的冲突片段仍然入链留证并进入裁决，但封存快照不变。
        """
        if not isinstance(source_seq, int) or source_seq < 1:
            raise ValidationError("source_seq 必须为 >=1 的整数")
        # 安全标注是元数据：哈希与存储内容都基于剥离标注后的业务内容，
        # 否则同一证据仅因标注位置不同就会被当成不同片段。
        merged_labels = extract_labels(content, labels)
        clean_content = strip_label_annotations(content)
        content_hash = hash_content(clean_content)
        content_text = json.dumps(clean_content, sort_keys=True, ensure_ascii=False)
        fragment_id = "frag-" + sha256_hex([delegation_id, source_id, source_seq, content_hash])[:20]

        with self.conn:
            delegation = self._delegation(self.conn, tenant_id, delegation_id)
            family = self._family(self.conn, tenant_id, delegation["family_id"])
            self._ensure_writable_family(family)
            ts = self._now()

            duplicate = self.conn.execute(
                "select * from fragments where fragment_id=?",
                (fragment_id,),
            ).fetchone()
            if duplicate is None:
                duplicate = self.conn.execute(
                    "select * from fragments where delegation_id=? and source_seq=? and content_hash=?",
                    (delegation_id, source_seq, content_hash),
                ).fetchone()
            if duplicate is not None:
                # 重复上报：只确认已有记录，绝不新增链条目或改变顺序。
                self.conn.execute(
                    "update fragments set confirmations = confirmations + 1 where fragment_id=?",
                    (duplicate["fragment_id"],),
                )
                self._append_event(
                    self.conn,
                    tenant_id=tenant_id,
                    event_type="fragment.duplicated",
                    aggregate_kind="fragment",
                    aggregate_id=duplicate["fragment_id"],
                    actor_id=actor_id,
                    payload={"delegation_id": delegation_id, "source_seq": source_seq,
                             "confirmations": duplicate["confirmations"] + 1},
                )
                outcome = "duplicated"
                result_fragment_id = duplicate["fragment_id"]
                fork_id: str | None = None
            else:
                labels_text = json.dumps(merged_labels, sort_keys=True, ensure_ascii=False)
                # 仅当存在未被裁决否决的同序列片段时才算分叉；
                # reject_all 之后补来的新内容是新证据，按正常片段接收。
                prior = self.conn.execute(
                    "select fragment_id from fragments where delegation_id=? and source_seq=? "
                    "and status != 'rejected'",
                    (delegation_id, source_seq),
                ).fetchall()
                fork_id = None
                if prior:
                    # 同序列号不同内容即分叉；不会自动选择任何一条。
                    open_fork = self.conn.execute(
                        "select * from fork_cases where delegation_id=? and source_seq=? "
                        "and status in ('open','adjudicating')",
                        (delegation_id, source_seq),
                    ).fetchone()
                    if open_fork is None:
                        fork_id = "fork-" + uuid.uuid4().hex[:16]
                        candidates = sorted({p["fragment_id"] for p in prior} | {fragment_id})
                        fseq = self._append_event(
                            self.conn,
                            tenant_id=tenant_id,
                            event_type="fork.opened",
                            aggregate_kind="fork",
                            aggregate_id=fork_id,
                            actor_id=actor_id,
                            payload={"delegation_id": delegation_id, "source_seq": source_seq,
                                     "source_id": source_id, "candidates": candidates,
                                     "chain_sealed": delegation["status"] == "sealed"},
                        )
                        self.conn.execute(
                            "insert into fork_cases(tenant_id, fork_id, delegation_id, source_seq, "
                            "source_id, status, candidate_ids, opened_event_seq, opened_at, opened_by) "
                            "values (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
                            (tenant_id, fork_id, delegation_id, source_seq, source_id,
                             json.dumps(candidates, ensure_ascii=False), fseq, ts, actor_id),
                        )
                    else:
                        fork_id = open_fork["fork_id"]
                        candidates = sorted(
                            set(json.loads(open_fork["candidate_ids"])) | {fragment_id}
                        )
                        self.conn.execute(
                            "update fork_cases set candidate_ids=? where fork_id=?",
                            (json.dumps(candidates, ensure_ascii=False), fork_id),
                        )
                    self.conn.execute(
                        "update fragments set status='candidate' where delegation_id=? and source_seq=?",
                        (delegation_id, source_seq),
                    )
                    fragment_status = "candidate"
                    outcome = "candidate"
                else:
                    fragment_status = "received"
                    outcome = "received"

                self.conn.execute(
                    "insert into fragments(tenant_id, fragment_id, delegation_id, source_id, source_seq, "
                    "content_text, content_hash, labels_text, status, confirmations, received_at) "
                    "values (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, fragment_id, delegation_id, source_id, source_seq, content_text,
                     content_hash, labels_text, fragment_status, ts),
                )

                # 哈希链严格按接收顺序追加；候选片段同样入链，原始接收证据不可回避。
                last = self.conn.execute(
                    "select received_order, entry_hash from chain_entries "
                    "where delegation_id=? order by received_order desc limit 1",
                    (delegation_id,),
                ).fetchone()
                received_order = (last["received_order"] + 1) if last else 1
                prev_hash = last["entry_hash"] if last else GENESIS_HASH
                entry_hash = chain_entry_hash(
                    prev_hash,
                    fragment_id=fragment_id,
                    source_seq=source_seq,
                    content_hash=content_hash,
                    entry_kind=fragment_status,
                    fork_id=fork_id,
                )
                self.conn.execute(
                    "insert into chain_entries(delegation_id, received_order, fragment_id, entry_kind, "
                    "fork_id, prev_hash, entry_hash, appended_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
                    (delegation_id, received_order, fragment_id, fragment_status, fork_id,
                     prev_hash, entry_hash, ts),
                )
                # 链头随追加推进；封存链头单独保存在 sealed_head_hash，不被覆盖语义影响。
                self.conn.execute(
                    "update delegations set head_hash=? where delegation_id=?",
                    (entry_hash, delegation_id),
                )
                self._append_event(
                    self.conn,
                    tenant_id=tenant_id,
                    event_type="fragment.accepted",
                    aggregate_kind="fragment",
                    aggregate_id=fragment_id,
                    actor_id=actor_id,
                    payload={"delegation_id": delegation_id, "source_seq": source_seq,
                             "source_id": source_id, "content_hash": content_hash,
                             "received_order": received_order, "entry_hash": entry_hash,
                             "fork_id": fork_id, "chained": True},
                )
                result_fragment_id = fragment_id
                if delegation["status"] != "sealed":
                    self._refresh_gaps(
                        self.conn, tenant_id,
                        self._delegation(self.conn, tenant_id, delegation_id), actor_id,
                    )
                    self._recompute_state(
                        self.conn, self._delegation(self.conn, tenant_id, delegation_id)
                    )
            status_after = self.conn.execute(
                "select status from delegations where delegation_id=?", (delegation_id,)
            ).fetchone()["status"]
        return {
            "fragment_id": result_fragment_id,
            "outcome": outcome,
            "fork_id": fork_id,
            "delegation_status": status_after,
        }

    # ------------------------------------------------------------------ 分叉

    def claim_fork(self, tenant_id: str, fork_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.conn:
            fork = self.conn.execute(
                "select * from fork_cases where tenant_id=? and fork_id=?",
                (tenant_id, fork_id),
            ).fetchone()
            if fork is None:
                raise NotFoundError(f"分叉案件不存在：{fork_id}")
            delegation = self._delegation(self.conn, tenant_id, fork["delegation_id"])
            family = self._family(self.conn, tenant_id, delegation["family_id"])
            self._ensure_writable_family(family)
            if fork["status"] != "open":
                raise StateError(f"分叉当前状态为 {fork['status']}，无需认领")
            self.conn.execute(
                "update fork_cases set status='adjudicating', claimed_by=? where fork_id=?",
                (actor_id, fork_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="fork.adjudicating",
                aggregate_kind="fork",
                aggregate_id=fork_id,
                actor_id=actor_id,
                payload={"delegation_id": fork["delegation_id"], "source_seq": fork["source_seq"]},
            )
            if delegation["status"] != "sealed":
                self._recompute_state(self.conn, delegation)
        return _row(self.conn.execute(
            "select * from fork_cases where fork_id=?", (fork_id,)
        ).fetchone())  # type: ignore[return-value]

    def adjudicate_fork(
        self,
        tenant_id: str,
        fork_id: str,
        *,
        action: str,
        actor_id: str,
        winner_fragment_id: str | None = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        """裁决分叉。``action`` 为 ``choose_winner`` 或 ``reject_all``。

        裁决只追加决议记录与片段状态；封存链的封存快照不受影响。
        """
        if action not in ("choose_winner", "reject_all"):
            raise ValidationError("action 必须是 choose_winner 或 reject_all")
        with self.conn:
            fork = self.conn.execute(
                "select * from fork_cases where tenant_id=? and fork_id=?",
                (tenant_id, fork_id),
            ).fetchone()
            if fork is None:
                raise NotFoundError(f"分叉案件不存在：{fork_id}")
            delegation = self._delegation(self.conn, tenant_id, fork["delegation_id"])
            family = self._family(self.conn, tenant_id, delegation["family_id"])
            self._ensure_writable_family(family)
            if fork["status"] not in ("open", "adjudicating"):
                raise StateError(f"分叉已完结：{fork['status']}")
            candidates = json.loads(fork["candidate_ids"])
            if action == "choose_winner":
                if not winner_fragment_id or winner_fragment_id not in candidates:
                    raise ValidationError("winner_fragment_id 必须是候选片段之一")
                winner_id = winner_fragment_id
                self.conn.execute(
                    "update fragments set status='winner' where fragment_id=?", (winner_id,)
                )
                self.conn.execute(
                    "update fragments set status='rejected' where delegation_id=? and source_seq=? "
                    "and fragment_id != ?",
                    (fork["delegation_id"], fork["source_seq"], winner_id),
                )
            else:
                winner_id = None
                self.conn.execute(
                    "update fragments set status='rejected' where delegation_id=? and source_seq=?",
                    (fork["delegation_id"], fork["source_seq"]),
                )
            ts = self._now()
            history = json.loads(fork["resolution_history"] or "[]")
            record = {
                "fork_id": fork_id,
                "source_seq": fork["source_seq"],
                "action": action,
                "winner_fragment_id": winner_id,
                "rejected_fragment_ids": sorted(c for c in candidates if c != winner_id),
                "resolved_by": actor_id,
                "resolved_at": ts,
                "rationale": rationale,
            }
            history.append(record)
            self.conn.execute(
                "update fork_cases set status='resolved', resolution_action=?, "
                "resolution_fragment_id=?, resolution_history=?, resolved_by=?, resolved_at=?, "
                "rationale=? where fork_id=?",
                (action, winner_id, json.dumps(history, ensure_ascii=False), actor_id, ts,
                 rationale, fork_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="fork.resolved",
                aggregate_kind="fork",
                aggregate_id=fork_id,
                actor_id=actor_id,
                payload=record,
                occurred_at=ts,
            )
            if delegation["status"] != "sealed":
                self._refresh_gaps(
                    self.conn, tenant_id,
                    self._delegation(self.conn, tenant_id, fork["delegation_id"]), actor_id,
                )
                self._recompute_state(
                    self.conn, self._delegation(self.conn, tenant_id, fork["delegation_id"])
                )
        return _row(self.conn.execute(
            "select * from fork_cases where fork_id=?", (fork_id,)
        ).fetchone())  # type: ignore[return-value]

    # ------------------------------------------------------------------ 封存

    def _effective_timeline(
        self, conn: sqlite3.Connection, delegation_id: str
    ) -> tuple[list[tuple[int, str]], list[dict[str, Any]], list[str]]:
        """返回 (当前逻辑时间线 seq->fragment_id, 裁决记录展开, 阻塞原因)。"""
        blockers: list[str] = []
        unresolved = conn.execute(
            "select fork_id from fork_cases where delegation_id=? "
            "and status in ('open','adjudicating')",
            (delegation_id,),
        ).fetchall()
        if unresolved:
            blockers.append("unresolved_forks:" + ",".join(r["fork_id"] for r in unresolved))
        open_gaps = conn.execute(
            "select missing_seq from gaps where delegation_id=? and status='open' order by missing_seq",
            (delegation_id,),
        ).fetchall()
        if open_gaps:
            blockers.append("open_gaps:" + ",".join(str(r["missing_seq"]) for r in open_gaps))

        winner_by_seq: dict[int, str] = {}
        resolutions: list[dict[str, Any]] = []
        for fork in conn.execute(
            "select * from fork_cases where delegation_id=? order by source_seq, resolved_at",
            (delegation_id,),
        ).fetchall():
            for record in json.loads(fork["resolution_history"] or "[]"):
                resolutions.append(record)
                if record["action"] == "choose_winner" and record["winner_fragment_id"]:
                    winner_by_seq[record["source_seq"]] = record["winner_fragment_id"]

        seen: dict[int, str] = {}
        fragments = conn.execute(
            "select fragment_id, source_seq from fragments where delegation_id=? "
            "and status not in ('rejected', 'candidate')",
            (delegation_id,),
        ).fetchall()
        for fragment in fragments:
            seq = fragment["source_seq"]
            chosen = winner_by_seq.get(seq)
            if chosen is not None:
                if fragment["fragment_id"] == chosen:
                    seen[seq] = fragment["fragment_id"]
            elif seq not in seen:
                seen[seq] = fragment["fragment_id"]
        timeline = [(seq, seen[seq]) for seq in sorted(seen)]
        return timeline, resolutions, blockers

    def seal_delegation(
        self,
        tenant_id: str,
        delegation_id: str,
        *,
        actor_id: str,
        expected_total: int | None = None,
    ) -> dict[str, Any]:
        with self.conn:
            delegation = self._delegation(self.conn, tenant_id, delegation_id)
            family = self._family(self.conn, tenant_id, delegation["family_id"])
            self._ensure_writable_family(family)
            if delegation["status"] == "sealed":
                raise StateError("链已封存")
            if expected_total is not None:
                if delegation["expected_total"] is not None and expected_total != delegation["expected_total"]:
                    raise ValidationError("期望片段总数与登记值不一致")
                if delegation["expected_total"] is None:
                    self.conn.execute(
                        "update delegations set expected_total=? where delegation_id=?",
                        (expected_total, delegation_id),
                    )
                delegation = self._delegation(self.conn, tenant_id, delegation_id)
                self._refresh_gaps(self.conn, tenant_id, delegation, actor_id)
                delegation = self._delegation(self.conn, tenant_id, delegation_id)
            if delegation["expected_total"] is None:
                raise StateError("未登记期望片段总数，无法判定链是否收齐")
            timeline, resolutions, blockers = self._effective_timeline(self.conn, delegation_id)
            if blockers:
                raise StateError("链未收齐，禁止封存：" + ";".join(blockers))
            if {seq for seq, _ in timeline} != set(range(1, delegation["expected_total"] + 1)):
                raise StateError(
                    f"链未收齐：期望 {delegation['expected_total']} 个连续序列号，"
                    f"当前时间线为 {[seq for seq, _ in timeline]}"
                )
            final_head = self.conn.execute(
                "select entry_hash from chain_entries where delegation_id=? "
                "order by received_order desc limit 1",
                (delegation_id,),
            ).fetchone()["entry_hash"]
            root = seal_root_hash(final_head, timeline, resolutions)
            ts = self._now()
            self.conn.execute(
                "update delegations set status='sealed', sealed_at=?, sealed_by=?, "
                "seal_root_hash=?, sealed_head_hash=? where delegation_id=?",
                (ts, actor_id, root, final_head, delegation_id),
            )
            self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="chain.sealed",
                aggregate_kind="delegation",
                aggregate_id=delegation_id,
                actor_id=actor_id,
                payload={"seal_root_hash": root, "final_head": final_head,
                         "timeline": [{"source_seq": s, "fragment_id": f} for s, f in timeline],
                         "fork_resolutions": sorted(resolutions, key=lambda r: r["fork_id"]),
                         "expected_total": delegation["expected_total"]},
                occurred_at=ts,
            )
        return self.get_delegation(tenant_id, delegation_id, reader_id=actor_id, role="system")

    def _verify_chain(self, conn: sqlite3.Connection, delegation_id: str) -> dict[str, Any]:
        """重放整条接收哈希链；封存链另用封存快照复核封存根。"""
        entries = conn.execute(
            "select * from chain_entries where delegation_id=? order by received_order",
            (delegation_id,),
        ).fetchall()
        prev = GENESIS_HASH
        entry_results = []
        for entry in entries:
            if entry["prev_hash"] != prev:
                raise StateError(f"链条目前序哈希断裂：{delegation_id} #{entry['received_order']}")
            fragment = conn.execute(
                "select source_seq, content_hash, content_text from fragments where fragment_id=?",
                (entry["fragment_id"],),
            ).fetchone()
            if fragment is None:
                raise StateError(f"链条目引用了不存在的片段：{entry['fragment_id']}")
            # 绑定原文：只改 content_text 而不改哈希列也必须被发现。
            if hash_content(json.loads(fragment["content_text"])) != fragment["content_hash"]:
                raise StateError(f"片段内容与摘要不匹配：{entry['fragment_id']}")
            recomputed = chain_entry_hash(
                prev,
                fragment_id=entry["fragment_id"],
                source_seq=fragment["source_seq"],
                content_hash=fragment["content_hash"],
                entry_kind=entry["entry_kind"],
                fork_id=entry["fork_id"],
            )
            if recomputed != entry["entry_hash"]:
                raise StateError(f"链条目摘要不匹配：{delegation_id} #{entry['received_order']}")
            prev = entry["entry_hash"]
            entry_results.append({"received_order": entry["received_order"],
                                  "fragment_id": entry["fragment_id"],
                                  "entry_kind": entry["entry_kind"],
                                  "entry_hash": entry["entry_hash"]})
        delegation = conn.execute(
            "select * from delegations where delegation_id=?", (delegation_id,)
        ).fetchone()
        seal_ok: bool | None = None
        if delegation is not None and delegation["status"] == "sealed":
            snapshot = self._seal_snapshot(conn, delegation_id)
            if snapshot is None:
                raise StateError(f"封存链缺少封存快照：{delegation_id}")
            seal_ok = (
                seal_root_hash(
                    snapshot["final_head"],
                    ((t["source_seq"], t["fragment_id"]) for t in snapshot["timeline"]),
                    snapshot["fork_resolutions"],
                ) == delegation["seal_root_hash"]
                and delegation["sealed_head_hash"] == snapshot["final_head"]
                and any(e["entry_hash"] == snapshot["final_head"] for e in entry_results)
            )
        return {
            "delegation_id": delegation_id,
            "entries": entry_results,
            "head_hash": prev if entries else GENESIS_HASH,
            "sealed": delegation["status"] == "sealed" if delegation else False,
            "seal_root_hash": delegation["seal_root_hash"] if delegation else None,
            "seal_ok": seal_ok,
        }

    def verify_delegation(self, tenant_id: str, delegation_id: str, *, reader_id: str, role: str) -> dict[str, Any]:
        with self.conn:
            delegation = self._delegation(self.conn, tenant_id, delegation_id)
            result = self._verify_chain(self.conn, delegation_id)
            self._record_read(
                self.conn,
                tenant_id=tenant_id,
                reader_id=reader_id,
                reader_role=role,
                access_kind="verify_chain",
                family_id=delegation["family_id"],
                delegation_id=delegation_id,
                raw_content_hash=result["seal_root_hash"],
                result_count=len(result["entries"]),
            )
        return result

    # ------------------------------------------------------------------ 读取

    def _record_read(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        reader_id: str,
        reader_role: str,
        access_kind: str,
        family_id: str | None = None,
        delegation_id: str | None = None,
        fragment_id: str | None = None,
        export_id: str | None = None,
        raw_content_hash: str | None = None,
        projection_hash: str | None = None,
        result_count: int | None = None,
    ) -> int:
        audit_id = "read-" + uuid.uuid4().hex[:16]
        ts = self._now()
        if delegation_id:
            aggregate_kind, aggregate_id = "delegation", delegation_id
        elif family_id:
            aggregate_kind, aggregate_id = "family", family_id
        else:
            aggregate_kind, aggregate_id = "system", audit_id
        event_seq = self._append_event(
            conn,
            tenant_id=tenant_id,
            event_type="read.recorded",
            aggregate_kind=aggregate_kind,
            aggregate_id=aggregate_id,
            actor_id=reader_id,
            payload={"audit_id": audit_id, "access_kind": access_kind, "reader_role": reader_role,
                     "family_id": family_id, "fragment_id": fragment_id, "export_id": export_id,
                     "raw_content_hash": raw_content_hash, "projection_hash": projection_hash,
                     "result_count": result_count},
            occurred_at=ts,
        )
        conn.execute(
            "insert into read_audit(audit_id, tenant_id, reader_id, reader_role, access_kind, "
            "family_id, delegation_id, fragment_id, export_id, raw_content_hash, projection_hash, "
            "result_count, recorded_event_seq, read_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (audit_id, tenant_id, reader_id, reader_role, access_kind, family_id, delegation_id,
             fragment_id, export_id, raw_content_hash, projection_hash, result_count, event_seq, ts),
        )
        return event_seq

    def get_family(self, tenant_id: str, family_id: str, *, reader_id: str, role: str) -> dict[str, Any]:
        with self.conn:
            family = self._family(self.conn, tenant_id, family_id)
            result = _row(family)
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="family_view", family_id=family_id, result_count=1,
            )
        return result  # type: ignore[return-value]

    def list_delegations(self, tenant_id: str, family_id: str, *, reader_id: str, role: str) -> list[dict[str, Any]]:
        with self.conn:
            self._family(self.conn, tenant_id, family_id)
            rows = [
                _row(r)
                for r in self.conn.execute(
                    "select delegation_id, parent_task_id, child_task_id, status, expected_total, "
                    "head_hash, sealed_head_hash, seal_root_hash, sealed_at, created_at "
                    "from delegations where tenant_id=? and family_id=? order by created_at",
                    (tenant_id, family_id),
                ).fetchall()
            ]
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="delegation_list", family_id=family_id, result_count=len(rows),
            )
        return rows

    def get_delegation(self, tenant_id: str, delegation_id: str, *, reader_id: str, role: str) -> dict[str, Any]:
        with self.conn:
            delegation = self._delegation(self.conn, tenant_id, delegation_id)
            timeline, _resolutions, raw_blockers = self._effective_timeline(self.conn, delegation_id)
            sealed = delegation["status"] == "sealed"
            expected = delegation["expected_total"]
            if sealed:
                # 封存即终局完整；封存后到达的争议另行列出，不算阻塞。
                complete = True
                blockers: list[str] = []
            else:
                complete = (
                    expected is not None
                    and not raw_blockers
                    and {s for s, _ in timeline} == set(range(1, expected + 1))
                )
                blockers = raw_blockers
            result = _row(delegation)
            result["complete"] = bool(complete)
            result["blockers"] = blockers
            result["post_seal_pending_forks"] = [
                r["fork_id"]
                for r in self.conn.execute(
                    "select fork_id from fork_cases where delegation_id=? "
                    "and status in ('open','adjudicating')",
                    (delegation_id,),
                ).fetchall()
            ] if sealed else []
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="delegation_view", family_id=delegation["family_id"],
                delegation_id=delegation_id, result_count=1,
            )
        return result  # type: ignore[return-value]

    def get_fragment_raw(
        self, tenant_id: str, fragment_id: str, *, reader_id: str, role: str
    ) -> dict[str, Any]:
        if role not in self.raw_reader_roles:
            self._deny_audit(tenant_id, fragment_id, reader_id, role, "fragment_raw")
            raise AccessDeniedError(f"角色 {role} 无权读取原始证据")
        with self.conn:
            fragment = self.conn.execute(
                "select * from fragments where tenant_id=? and fragment_id=?",
                (tenant_id, fragment_id),
            ).fetchone()
            if fragment is None:
                raise NotFoundError(f"片段不存在：{fragment_id}")
            delegation = self._delegation(self.conn, tenant_id, fragment["delegation_id"])
            result = {
                "fragment_id": fragment_id,
                "content": self._fragment_payload(fragment),
                "content_hash": fragment["content_hash"],
            }
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="fragment_raw", family_id=delegation["family_id"],
                delegation_id=fragment["delegation_id"], fragment_id=fragment_id,
                raw_content_hash=fragment["content_hash"], result_count=1,
            )
        return result

    def _deny_audit(self, tenant_id: str, fragment_id: str, reader_id: str, role: str, kind: str) -> None:
        with self.conn:
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="denied:" + kind, fragment_id=fragment_id, result_count=0,
            )

    def get_fragment_projection(
        self, tenant_id: str, fragment_id: str, *, reader_id: str, role: str
    ) -> dict[str, Any]:
        with self.conn:
            fragment = self.conn.execute(
                "select * from fragments where tenant_id=? and fragment_id=?",
                (tenant_id, fragment_id),
            ).fetchone()
            if fragment is None:
                raise NotFoundError(f"片段不存在：{fragment_id}")
            delegation = self._delegation(self.conn, tenant_id, fragment["delegation_id"])
            projection = make_projection(
                self._fragment_payload(fragment),
                role,
                self.policy,
                labels=self._fragment_labels(fragment),
            )
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="fragment_projection", family_id=delegation["family_id"],
                delegation_id=fragment["delegation_id"], fragment_id=fragment_id,
                raw_content_hash=projection["raw_content_hash"],
                projection_hash=projection["projection_hash"], result_count=1,
            )
        return projection

    def get_timeline(
        self, tenant_id: str, delegation_id: str, *, reader_id: str, role: str
    ) -> dict[str, Any]:
        """逻辑时间线（按来源序列号）。迟到片段已补入，但封存原始顺序由接收链单独保留。"""
        with self.conn:
            delegation = self._delegation(self.conn, tenant_id, delegation_id)
            rows = self.conn.execute(
                "select * from fragments where delegation_id=? order by source_seq, received_at",
                (delegation_id,),
            ).fetchall()
            items: list[dict[str, Any]] = []
            for fragment in rows:
                projection = make_projection(
                    self._fragment_payload(fragment), role, self.policy,
                    labels=self._fragment_labels(fragment),
                )
                items.append({
                    "source_seq": fragment["source_seq"],
                    "fragment_id": fragment["fragment_id"],
                    "status": fragment["status"],
                    "received_order": self.conn.execute(
                        "select received_order from chain_entries where fragment_id=?",
                        (fragment["fragment_id"],),
                    ).fetchone()["received_order"],
                    "content": projection["content"],
                    "raw_content_hash": projection["raw_content_hash"],
                })
            timeline_pairs, _resolutions, raw_blockers = self._effective_timeline(self.conn, delegation_id)
            snapshot = self._seal_snapshot(self.conn, delegation_id)
            sealed = delegation["status"] == "sealed"
            pending_forks: list[str] = []
            if sealed:
                pending_forks = [
                    r["fork_id"]
                    for r in self.conn.execute(
                        "select fork_id from fork_cases where delegation_id=? "
                        "and status in ('open','adjudicating')",
                        (delegation_id,),
                    ).fetchall()
                ]
                blockers = []
            else:
                blockers = raw_blockers
            body = {
                "delegation_id": delegation_id,
                "status": delegation["status"],
                "sealed": sealed,
                "expected_total": delegation["expected_total"],
                "blockers": blockers,
                "post_seal_pending_forks": pending_forks,
                "items": items,
                "effective_timeline": [
                    {"source_seq": seq, "fragment_id": fid} for seq, fid in timeline_pairs
                ],
                "sealed_timeline": snapshot["timeline"] if snapshot else None,
            }
            body_hash = sha256_hex({
                "delegation_id": delegation_id,
                "status": body["status"],
                "sealed": body["sealed"],
                "blockers": blockers,
                "items": [
                    {"source_seq": i["source_seq"], "fragment_id": i["fragment_id"],
                     "status": i["status"], "received_order": i["received_order"],
                     "raw_content_hash": i["raw_content_hash"]}
                    for i in items
                ],
            })
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="timeline", family_id=delegation["family_id"],
                delegation_id=delegation_id, projection_hash=body_hash, result_count=len(items),
            )
        return body

    def list_read_audit(
        self,
        tenant_id: str,
        *,
        reader_id: str,
        role: str,
        family_id: str | None = None,
        delegation_id: str | None = None,
        target_reader_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = "select * from read_audit where tenant_id=?"
        params: list[Any] = [tenant_id]
        if family_id:
            query += " and family_id=?"
            params.append(family_id)
        if delegation_id:
            query += " and delegation_id=?"
            params.append(delegation_id)
        if target_reader_id:
            query += " and reader_id=?"
            params.append(target_reader_id)
        query += " order by read_at desc limit ?"
        params.append(limit)
        with self.conn:
            rows = [_row(r) for r in self.conn.execute(query, params).fetchall()]
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="audit_log", family_id=family_id, delegation_id=delegation_id,
                result_count=len(rows),
            )
        return rows

    # ------------------------------------------------------------------ 导出

    def _build_export_manifest(
        self, conn: sqlite3.Connection, family: sqlite3.Row, role: str
    ) -> dict[str, Any]:
        delegations = []
        for d in conn.execute(
            "select * from delegations where tenant_id=? and family_id=? order by created_at",
            (family["tenant_id"], family["family_id"]),
        ).fetchall():
            entries = [
                dict(r)
                for r in conn.execute(
                    "select received_order, fragment_id, entry_kind, fork_id, prev_hash, "
                    "entry_hash, appended_at from chain_entries where delegation_id=? "
                    "order by received_order",
                    (d["delegation_id"],),
                ).fetchall()
            ]
            timeline_pairs, _resolutions, blockers = self._effective_timeline(conn, d["delegation_id"])
            snapshot = self._seal_snapshot(conn, d["delegation_id"])
            sealed = d["status"] == "sealed"
            chosen_timeline = (
                [(t["source_seq"], t["fragment_id"]) for t in snapshot["timeline"]]
                if sealed and snapshot else timeline_pairs
            )
            projected_timeline = []
            for seq, fragment_id in chosen_timeline:
                fragment = conn.execute(
                    "select * from fragments where fragment_id=?", (fragment_id,)
                ).fetchone()
                projection = make_projection(
                    self._fragment_payload(fragment), role, self.policy,
                    labels=self._fragment_labels(fragment),
                )
                projected_timeline.append({
                    "source_seq": seq,
                    "fragment_id": fragment_id,
                    "content_hash": fragment["content_hash"],
                    "content": projection["content"],
                    "raw_content_hash": projection["raw_content_hash"],
                })
            forks = [
                dict(r)
                for r in conn.execute(
                    "select fork_id, source_seq, status, candidate_ids, resolution_action, "
                    "resolution_fragment_id, resolution_history, resolved_by, resolved_at "
                    "from fork_cases where delegation_id=? order by opened_at",
                    (d["delegation_id"],),
                ).fetchall()
            ]
            for fork in forks:
                fork["candidate_ids"] = json.loads(fork["candidate_ids"])
                fork["resolution_history"] = json.loads(fork["resolution_history"] or "[]")
            expected = d["expected_total"]
            if sealed:
                complete = True
                export_blockers: list[str] = []
            else:
                complete = (
                    expected is not None and not blockers
                    and {s for s, _ in timeline_pairs} == set(range(1, expected + 1))
                )
                export_blockers = blockers
            delegations.append({
                "delegation_id": d["delegation_id"],
                "parent_task_id": d["parent_task_id"],
                "child_task_id": d["child_task_id"],
                "instruction_hash": d["instruction_hash"],
                "status": d["status"],
                "expected_total": expected,
                "complete": bool(complete),
                "blockers": export_blockers,
                "seal_root_hash": d["seal_root_hash"],
                "sealed_head_hash": d["sealed_head_hash"],
                "sealed_at": d["sealed_at"],
                "received_order_entries": entries,
                "timeline": projected_timeline,
                "forks": forks,
            })
        return {
            "manifest_version": "trace-export-v1",
            "chain_algorithm": CHAIN_ALGORITHM_VERSION,
            "projection_policy_version": self.policy.version,
            "role": role,
            "tenant_id": family["tenant_id"],
            "family_id": family["family_id"],
            "root_task_id": family["root_task_id"],
            "family_status": family["status"],
            "frozen_at": family["frozen_at"],
            "generated_at": self._now(),
            "delegations": delegations,
        }

    def export_family(
        self, tenant_id: str, family_id: str, *, reader_id: str, role: str
    ) -> dict[str, Any]:
        """导出冻结任务族；清单逐片段列出组成并给出整体摘要。

        未封存/未收齐的委派也会出现在清单中，但 ``complete=false`` 且
        ``blockers`` 非空，不会被误标成完整证据。
        """
        with self.conn:
            family = self._family(self.conn, tenant_id, family_id)
            if family["status"] != "frozen":
                raise StateError("仅冻结状态的任务族可以导出证据包")
            manifest = self._build_export_manifest(self.conn, family, role)
            export_digest = sha256_hex(manifest)
            export_id = "export-" + uuid.uuid4().hex[:16]
            scope = {
                "delegation_ids": [d["delegation_id"] for d in manifest["delegations"]],
                "fragment_count": sum(len(d["timeline"]) for d in manifest["delegations"]),
            }
            seq = self._append_event(
                self.conn,
                tenant_id=tenant_id,
                event_type="export.attested",
                aggregate_kind="family",
                aggregate_id=family_id,
                actor_id=reader_id,
                payload={"export_id": export_id, "export_digest": export_digest,
                         "role": role, "scope": scope},
            )
            self.conn.execute(
                "insert into exports(tenant_id, export_id, family_id, scope_text, manifest_text, "
                "export_digest, created_by, created_role, created_event_seq, created_at) "
                "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, export_id, family_id, json.dumps(scope, ensure_ascii=False),
                 json.dumps(manifest, sort_keys=True, ensure_ascii=False), export_digest,
                 reader_id, role, seq, manifest["generated_at"]),
            )
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="export", family_id=family_id, export_id=export_id,
                projection_hash=export_digest, result_count=scope["fragment_count"],
            )
        return {"export_id": export_id, "export_digest": export_digest, "manifest": manifest}

    def verify_export(self, tenant_id: str, export_id: str, *, reader_id: str, role: str) -> dict[str, Any]:
        """复核导出：重算清单摘要，并对每条封存链重放哈希与封存根。"""
        with self.conn:
            row = self.conn.execute(
                "select * from exports where tenant_id=? and export_id=?",
                (tenant_id, export_id),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"导出不存在：{export_id}")
            manifest = json.loads(row["manifest_text"])
            digest_ok = sha256_hex(manifest) == row["export_digest"]
            delegation_checks = []
            for d in manifest["delegations"]:
                if d["status"] == "sealed":
                    check = self._verify_chain(self.conn, d["delegation_id"])
                    delegation_checks.append({
                        "delegation_id": d["delegation_id"],
                        "entries": len(check["entries"]),
                        "seal_ok": check["seal_ok"],
                    })
                else:
                    delegation_checks.append({
                        "delegation_id": d["delegation_id"],
                        "sealed": False,
                        "complete": d["complete"],
                        "blockers": d["blockers"],
                    })
            result = {
                "export_id": export_id,
                "digest_ok": digest_ok,
                "export_digest": row["export_digest"],
                "delegation_checks": delegation_checks,
            }
            self._record_read(
                self.conn, tenant_id=tenant_id, reader_id=reader_id, reader_role=role,
                access_kind="export_verify", family_id=row["family_id"], export_id=export_id,
                projection_hash=row["export_digest"], result_count=len(delegation_checks),
            )
        return result

    # ------------------------------------------------------------------ 恢复

    def recover(self) -> dict[str, Any]:
        """重启恢复：校验事件日志哈希链与全部接收链，重算未封存链状态。

        - 未决分叉与开放缺口保持原状，重启后可继续裁决与补片段；
        - 已封存链保持 ``sealed``，封存根按封存快照复核，绝不重标；
        - 任何哈希断裂、封存根失配都抛 :class:`StateError`，拒绝带伤服务。
        """
        report: dict[str, Any] = {
            "events_verified": 0, "delegations_checked": 0, "open_gaps": 0,
            "unresolved_forks": 0, "sealed": 0, "recomputed": [],
        }
        with self.conn:
            prev = GENESIS_HASH
            for event in self.conn.execute("select * from events order by event_seq").fetchall():
                if event["prev_hash"] != prev:
                    raise StateError(f"事件日志前序哈希断裂：{event['event_id']}")
                recomputed_payload_hash = hashlib.sha256(
                    event["payload_text"].encode("utf-8")
                ).hexdigest()
                if recomputed_payload_hash != event["payload_hash"]:
                    raise StateError(f"事件载荷被篡改：{event['event_id']}")
                fields = {
                    "event_id": event["event_id"],
                    "tenant_id": event["tenant_id"],
                    "event_type": event["event_type"],
                    "aggregate_kind": event["aggregate_kind"],
                    "aggregate_id": event["aggregate_id"],
                    "occurred_at": event["occurred_at"],
                    "actor_id": event["actor_id"],
                    "payload_hash": event["payload_hash"],
                }
                if event_hash(prev, fields) != event["entry_hash"]:
                    raise StateError(f"事件日志摘要不匹配：{event['event_id']}")
                prev = event["entry_hash"]
                report["events_verified"] += 1

            delegations = self.conn.execute("select * from delegations").fetchall()
            for delegation in delegations:
                check = self._verify_chain(self.conn, delegation["delegation_id"])
                if check["sealed"] and check["seal_ok"] is False:
                    raise StateError(f"封存根校验失败：{delegation['delegation_id']}")
                report["delegations_checked"] += 1
                if delegation["status"] == "sealed":
                    report["sealed"] += 1
                    continue
                new_state = self._recompute_state(self.conn, delegation)
                report["recomputed"].append(
                    {"delegation_id": delegation["delegation_id"], "status": new_state}
                )
            report["open_gaps"] = self.conn.execute(
                "select count(*) as c from gaps where status='open'"
            ).fetchone()["c"]
            report["unresolved_forks"] = self.conn.execute(
                "select count(*) as c from fork_cases where status in ('open','adjudicating')"
            ).fetchone()["c"]
        return report
