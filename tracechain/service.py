"""追踪证据服务：用例编排层。

所有写操作只做一件事：校验当前重放状态，然后向事件存储原子追加事件。
所有读操作都先重放状态，再生成角色投影，并留下不可变的读取审计。
"""
from __future__ import annotations

import functools
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import clock
from .errors import (
    AccessDenied,
    AdjudicationError,
    ChainNotComplete,
    ChainSealed,
    ConflictingReport,
    DisavowedContent,
    FamilyFrozen,
    UnresolvedFork,
)
from .hashing import content_digest, hash_entry, stable_delegation_id, stable_family_id
from .models import (
    DelegationView,
    ExportRecord,
    FamilyState,
    Fork,
    Fragment,
    Gap,
    ReadAuditRecord,
    SealRecord,
)
from .projection import Projection, ProjectionEngine
from .state import ReplayedState
from .store import EventStore


@dataclass(frozen=True, slots=True)
class FragmentReportResult:
    status: str  # accepted | duplicate_confirmed | forked
    fragment: Fragment
    existing: Fragment | None
    fork_id: str | None
    gaps: tuple[Gap, ...]
    supplement: bool = False


@dataclass(frozen=True, slots=True)
class DelegationRegistration:
    view: DelegationView
    confirmed: bool  # True 表示重复上报，仅确认已有委派


@dataclass(frozen=True, slots=True)
class ProjectedEntry:
    fragment: Fragment
    projection: Projection


@dataclass(frozen=True, slots=True)
class ExportBundle:
    record: ExportRecord
    entries: tuple[ProjectedEntry, ...]
    manifest: dict[str, Any]
    audit: ReadAuditRecord


@dataclass(frozen=True, slots=True)
class PendingWork:
    """重启后恢复出的未决事项：待裁决分叉与有缺口的委派。"""

    open_forks: tuple[Fork, ...]
    gapped_delegations: tuple[tuple[str, tuple[Gap, ...]], ...]
    unsealed_delegations: tuple[str, ...]
    overturned_seals: tuple[tuple[str, str], ...]  # (delegation_id, 原因)


def _guarded(method):
    """用服务级可重入锁串行化 check-then-act 写操作。"""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._guard:
            return method(self, *args, **kwargs)

    return wrapper


class TraceEvidenceService:
    def __init__(self, store_path: str | Path = ":memory:", policy_path: str | Path | None = None) -> None:
        self.store = EventStore(store_path)
        self.projections = ProjectionEngine(policy_path)
        # check-then-act 串行化：SQLite 写锁只保护单条语句，
        # 业务判定（查重/分叉/封存）必须整体互斥。
        import threading
        self._guard = threading.RLock()

    def close(self) -> None:
        self.store.close()

    # ============================================================ 重放

    def _load(self) -> ReplayedState:
        state = ReplayedState()
        for event in self.store.replay():
            state.apply(event.event_type, event.payload)
        return state

    def _tenant_of_family(self, state: ReplayedState, family_id: str) -> str:
        try:
            return state.tenant_by_family[family_id]
        except KeyError:
            raise LookupError(f"任务族不存在：{family_id}") from None

    # ============================================================ 登记

    def create_family(self, tenant: str, external_case_id: str, *, actor_id: str) -> str:
        """登记任务族；标识由外部案件号确定性派生。"""
        family_id = stable_family_id(tenant, external_case_id)
        with self._guard:
            state = self._load()
            if family_id in state.families:
                return family_id
            self.store.append(
                event_id=f"ev-fam-{family_id}",
                tenant=tenant,
                event_type="family.created",
                aggregate_id=family_id,
                occurred_at=clock.now_iso(),
                actor_id=actor_id,
                payload={
                    "tenant": tenant,
                    "family_id": family_id,
                    "external_case_id": external_case_id,
                    "occurred_at": clock.now_iso(),
                },
            )
        return family_id

    def register_delegation(
        self,
        tenant: str,
        family_id: str,
        parent_task_id: str,
        instruction: str,
        *,
        actor_id: str,
        expected_count: int | None = None,
        occurred_at: str | None = None,
    ) -> DelegationRegistration:
        """登记委派；同一 (父任务, 指令) 重复上报得到同一稳定标识，仅确认。"""
        if expected_count is not None and expected_count <= 0:
            raise ValueError("expected_count 必须为正整数")
        when = clock.normalize(occurred_at) if occurred_at else clock.now_iso()
        instruction_digest = content_digest(instruction)
        delegation_id = stable_delegation_id(tenant, family_id, parent_task_id, instruction_digest)

        with self._guard:
            state = self._load()
            if family_id not in state.families:
                raise LookupError(f"任务族不存在：{family_id}")
            if state.families[family_id].frozen:
                raise FamilyFrozen(f"任务族 {family_id} 已冻结，拒绝登记新委派")
            existing = state.delegations.get(delegation_id)
            if existing is not None:
                return DelegationRegistration(view=state.delegation_view(delegation_id), confirmed=True)

            self.store.append(
                event_id=f"ev-del-{delegation_id}",
                tenant=tenant,
                event_type="delegation.created",
                aggregate_id=family_id,
                delegation_id=delegation_id,
                occurred_at=when,
                actor_id=actor_id,
                payload={
                    "tenant": tenant,
                    "family_id": family_id,
                    "delegation_id": delegation_id,
                    "parent_task_id": parent_task_id,
                    "instruction": instruction,
                    "instruction_digest": instruction_digest,
                    "expected_count": expected_count,
                    "created_at": when,
                    "created_by": actor_id,
                },
            )
        return DelegationRegistration(view=self._load().delegation_view(delegation_id), confirmed=False)

    # ============================================================ 片段接收

    def report_fragment(
        self,
        tenant: str,
        delegation_id: str,
        source: str,
        seq: int,
        payload: Any,
        *,
        occurred_at: str,
        reporter_id: str,
    ) -> FragmentReportResult:
        """接收一个追踪片段。

        - 相同 (来源, 序号, 内容摘要)：重复上报，只确认已有记录。
        - 相同 (来源, 序号) 不同摘要：登记候选并开立分叉案，等待裁决。
        - 封存后到达的新序号：进入锚定封存头的补充段，不改写封存顺序。
        """
        if not source:
            raise ValueError("source 不能为空")
        if seq < 1:
            raise ValueError("来源序列号必须从 1 开始")
        when_occurred = clock.normalize(occurred_at)
        received_at = clock.now_iso()
        digest = content_digest(payload)

        with self._guard:
            return self._report_locked(
                tenant, delegation_id, source, seq, payload,
                when_occurred=when_occurred, received_at=received_at,
                digest=digest, reporter_id=reporter_id,
            )

    def _report_locked(
        self, tenant, delegation_id, source, seq, payload, *,
        when_occurred, received_at, digest, reporter_id,
    ):
        state = self._load()
        d = state.delegations.get(delegation_id)
        if d is None or d.tenant != tenant:
            raise LookupError(f"委派不存在：{delegation_id}")
        if state.families[d.family_id].frozen:
            raise FamilyFrozen(f"任务族 {d.family_id} 已冻结，拒绝接收片段 {source}#{seq}")

        slot = state.slots.get((delegation_id, source, seq), [])
        candidates = [state.fragments[fid] for fid in slot]
        active, latest, disavowed = state.slot_history(delegation_id, source, seq)
        sealed = state.seals.get(delegation_id)
        boundary = dict(sealed.max_seq_by_source) if sealed is not None else {}
        is_late_new = sealed is not None and seq > boundary.get(source, 0)

        # 1) 已被裁决否决的摘要：禁止重新进入规范链。
        if digest in disavowed:
            raise DisavowedContent(source, seq, latest.fork_id)

        # 2) 未决分叉案进行中：相同摘要算重复确认，新摘要并入候选。
        if active is not None:
            same = next((c for c in candidates if c.digest == digest), None)
            if same is not None:
                return self._confirm_duplicate(
                    tenant, d, same, source, seq, digest, received_at, reporter_id,
                )
            return self._merge_fork_candidate(
                state, d, candidates, source, seq, payload, digest,
                when_occurred, received_at, reporter_id, active, sealed, is_late_new,
            )

        # 3) 该位置已有裁决结论。
        if latest is not None:
            if latest.resolution == "accepted" and digest == latest.chosen_digest:
                same = next(c for c in candidates if c.digest == digest)
                return self._confirm_duplicate(
                    tenant, d, same, source, seq, digest, received_at, reporter_id,
                )
            if latest.resolution == "rejected":
                # 裁决否决全部旧候选后，补送的是新内容：填补缺口，正常接收。
                pass
            else:
                # 挑战已生效的裁决：新开一案，而不是静默替换。
                return self._open_new_fork_after_resolution(
                    state, d, candidates, source, seq, payload, digest,
                    when_occurred, received_at, reporter_id, latest, sealed, is_late_new,
                )

        # 4) 无分叉历史：相同摘要=重复；与存活候选冲突=新分叉；否则正常接收。
        same = next((c for c in candidates if c.digest == digest), None)
        if same is not None:
            return self._confirm_duplicate(
                tenant, d, same, source, seq, digest, received_at, reporter_id,
            )

        events, fragment_id, conflict = self._accept_events(
            state, d, candidates, source, seq, payload, digest,
            when_occurred, received_at, reporter_id, sealed, is_late_new,
            disavowed=disavowed,
        )
        self.store.append_many(events)
        state = self._load()
        new_gaps = self._emit_gap_events(state, delegation_id, reporter_id)
        fragment = state.fragments[fragment_id]
        result = FragmentReportResult(
            status="forked" if conflict else "accepted",
            fragment=fragment,
            existing=conflict,
            fork_id=(events[-1]["payload"]["fork_id"] if conflict else None),
            gaps=tuple(new_gaps),
            supplement=is_late_new,
        )
        if conflict:
            error = ConflictingReport(source, seq, conflict.digest, digest)
            error.result = result
            raise error
        return result

    # -- 接收辅助 ---------------------------------------------------------

    def _confirm_duplicate(self, tenant, d, same, source, seq, digest, received_at, reporter_id):
        self.store.append(
            event_id=f"ev-dup-{uuid.uuid4().hex}",
            tenant=tenant,
            event_type="fragment.duplicated",
            aggregate_id=d.family_id,
            delegation_id=d.delegation_id,
            occurred_at=received_at,
            actor_id=reporter_id,
            payload={
                "tenant": tenant,
                "family_id": d.family_id,
                "delegation_id": d.delegation_id,
                "fragment_id": same.fragment_id,
                "source": source,
                "seq": seq,
                "digest": digest,
                "received_at": received_at,
                "reporter_id": reporter_id,
            },
        )
        return FragmentReportResult(
            status="duplicate_confirmed", fragment=same, existing=same,
            fork_id=None, gaps=(),
        )

    def _fragment_event(
        self, tenant, d, fragment_id, source, seq, payload, digest,
        when_occurred, received_at, reporter_id, recv_index, sealed, is_late_new,
    ) -> dict[str, Any]:
        return {
            "event_id": f"ev-frag-{fragment_id}",
            "tenant": tenant,
            "event_type": "fragment.accepted",
            "aggregate_id": d.family_id,
            "delegation_id": d.delegation_id,
            "occurred_at": received_at,
            "actor_id": reporter_id,
            "payload": {
                "tenant": tenant,
                "family_id": d.family_id,
                "delegation_id": d.delegation_id,
                "fragment_id": fragment_id,
                "source": source,
                "seq": seq,
                "payload": payload,
                "digest": digest,
                "occurred_at": when_occurred,
                "received_at": received_at,
                "reporter_id": reporter_id,
                "recv_index": recv_index,
                "segment": "main" if not is_late_new else f"sup-{sealed.seal_id}",
                "supplement": is_late_new,
                **self._supplement_hash(d, sealed, source, seq, digest, is_late_new),
            },
        }

    def _accept_events(
        self, state, d, candidates, source, seq, payload, digest,
        when_occurred, received_at, reporter_id, sealed, is_late_new,
        disavowed=frozenset(),
    ):
        fragment_id = f"frg-{uuid.uuid4().hex}"
        events = [self._fragment_event(
            d.tenant, d, fragment_id, source, seq, payload, digest,
            when_occurred, received_at, reporter_id,
            len(d.ledger) + 1, sealed, is_late_new,
        )]
        # 冲突只看存活候选；已被否决的旧候选占据槽位但不构成新分叉。
        live = [c for c in candidates if c.digest not in disavowed]
        conflict = next((c for c in live if c.digest != digest), None)
        if conflict is not None:
            fork_id = f"fork-{uuid.uuid4().hex[:16]}"
            events.append({
                "event_id": f"ev-fork-{fork_id}",
                "tenant": d.tenant,
                "event_type": "fork.opened",
                "aggregate_id": d.family_id,
                "delegation_id": d.delegation_id,
                "occurred_at": received_at,
                "actor_id": reporter_id,
                "payload": {
                    "tenant": d.tenant,
                    "family_id": d.family_id,
                    "delegation_id": d.delegation_id,
                    "fork_id": fork_id,
                    "source": source,
                    "seq": seq,
                    "candidate_digests": sorted({c.digest for c in live} | {digest}),
                    "candidate_fragment_ids": [c.fragment_id for c in live] + [fragment_id],
                    "opened_at": received_at,
                    "after_seal": sealed is not None and not is_late_new,
                },
            })
        return events, fragment_id, conflict

    def _merge_fork_candidate(
        self, state, d, candidates, source, seq, payload, digest,
        when_occurred, received_at, reporter_id, active, sealed, is_late_new,
    ):
        fragment_id = f"frg-{uuid.uuid4().hex}"
        events = [self._fragment_event(
            d.tenant, d, fragment_id, source, seq, payload, digest,
            when_occurred, received_at, reporter_id,
            len(d.ledger) + 1, sealed, is_late_new,
        ), {
            "event_id": f"ev-fork-add-{uuid.uuid4().hex[:16]}",
            "tenant": d.tenant,
            "event_type": "fork.candidate_added",
            "aggregate_id": d.family_id,
            "delegation_id": d.delegation_id,
            "occurred_at": received_at,
            "actor_id": reporter_id,
            "payload": {
                "tenant": d.tenant,
                "family_id": d.family_id,
                "delegation_id": d.delegation_id,
                "fork_id": active.fork_id,
                "candidate_digests": [digest],
                "candidate_fragment_id": fragment_id,
                "added_at": received_at,
            },
        }]
        self.store.append_many(events)
        state = self._load()
        self._emit_gap_events(state, d.delegation_id, reporter_id)
        result = FragmentReportResult(
            status="forked", fragment=state.fragments[fragment_id],
            existing=candidates[0], fork_id=active.fork_id, gaps=(),
            supplement=is_late_new,
        )
        error = ConflictingReport(source, seq, candidates[0].digest, digest)
        error.result = result
        raise error

    def _open_new_fork_after_resolution(
        self, state, d, candidates, source, seq, payload, digest,
        when_occurred, received_at, reporter_id, latest, sealed, is_late_new,
    ):
        """对已 accepted 裁决的挑战：新候选与当选候选组成新的分叉案。"""
        winner = next(
            (c for c in candidates if c.digest == latest.chosen_digest), None
        )
        fragment_id = f"frg-{uuid.uuid4().hex}"
        fork_id = f"fork-{uuid.uuid4().hex[:16]}"
        events = [self._fragment_event(
            d.tenant, d, fragment_id, source, seq, payload, digest,
            when_occurred, received_at, reporter_id,
            len(d.ledger) + 1, sealed, is_late_new,
        ), {
            "event_id": f"ev-fork-{fork_id}",
            "tenant": d.tenant,
            "event_type": "fork.opened",
            "aggregate_id": d.family_id,
            "delegation_id": d.delegation_id,
            "occurred_at": received_at,
            "actor_id": reporter_id,
            "payload": {
                "tenant": d.tenant,
                "family_id": d.family_id,
                "delegation_id": d.delegation_id,
                "fork_id": fork_id,
                "source": source,
                "seq": seq,
                "candidate_digests": sorted({latest.chosen_digest, digest}),
                "candidate_fragment_ids": [winner.fragment_id if winner else None, fragment_id],
                "opened_at": received_at,
                "after_seal": sealed is not None and not is_late_new,
                "reopens_resolved_fork": latest.fork_id,
            },
        }]
        self.store.append_many(events)
        state = self._load()
        self._emit_gap_events(state, d.delegation_id, reporter_id)
        result = FragmentReportResult(
            status="forked", fragment=state.fragments[fragment_id],
            existing=winner, fork_id=fork_id, gaps=(), supplement=is_late_new,
        )
        error = ConflictingReport(source, seq, latest.chosen_digest, digest)
        error.result = result
        raise error

    @staticmethod
    def _supplement_hash(d, sealed, source, seq, digest, is_late_new) -> dict[str, str]:
        if not is_late_new:
            return {}
        prev = d.sup_hashes[-1] if d.sup_hashes else sealed.head_hash
        return {"sup_hash": hash_entry(prev, source, seq, digest)}

    def _emit_gap_events(self, state: ReplayedState, delegation_id: str, actor_id: str) -> list[Gap]:
        """把新发现的缺口（此前未宣告过）写入 gap.detected 事件。"""
        current = state.gaps(delegation_id)
        fresh = [
            g for g in current
            if (delegation_id, g.source, g.missing_seq) not in state.detected_gaps
        ]
        if not fresh:
            return []
        d = state.delegations[delegation_id]
        self.store.append(
            event_id=f"ev-gap-{delegation_id}-"
                     + uuid.uuid4().hex[:12],
            tenant=d.tenant,
            event_type="gap.detected",
            aggregate_id=d.family_id,
            delegation_id=delegation_id,
            occurred_at=clock.now_iso(),
            actor_id=actor_id,
            payload={
                "tenant": d.tenant,
                "family_id": d.family_id,
                "delegation_id": delegation_id,
                "missing": [[g.source, g.missing_seq] for g in fresh],
                "detected_at": clock.now_iso(),
            },
        )
        return fresh

    # ============================================================ 分叉裁决

    def list_forks(self, family_id: str) -> tuple[Fork, ...]:
        state = self._load()
        self._tenant_of_family(state, family_id)
        return tuple(sorted(
            (f for f in state.forks.values() if f.family_id == family_id),
            key=lambda f: f.opened_at,
        ))

    @_guarded
    def start_adjudication(self, fork_id: str, *, adjudicator: str, reason: str | None = None) -> Fork:
        state = self._load()
        fork = state.forks.get(fork_id)
        if fork is None:
            raise AdjudicationError(f"分叉案不存在：{fork_id}")
        if fork.status != "open":
            raise AdjudicationError(f"分叉案 {fork_id} 当前状态 {fork.status}，无需再进入裁决")
        at = clock.now_iso()
        self.store.append(
            event_id=f"ev-fork-adj-{fork_id}",
            tenant=fork.tenant,
            event_type="fork.adjudication_started",
            aggregate_id=fork.family_id,
            delegation_id=fork.delegation_id,
            occurred_at=at,
            actor_id=adjudicator,
            payload={
                "fork_id": fork_id,
                "adjudicator": adjudicator,
                "at": at,
                "reason": reason,
            },
        )
        return self._load().forks[fork_id]

    @_guarded
    def resolve_fork(
        self,
        fork_id: str,
        *,
        resolution: str,
        actor_id: str,
        chosen_digest: str | None = None,
        reason: str,
    ) -> Fork:
        """对分叉做出明确裁决。

        resolution="accepted"：选定一个候选摘要（其余候选败诉，保留在台账中）。
        resolution="rejected"：否决全部候选，该序号位置空出，链重新出现缺口。
        """
        if resolution not in ("accepted", "rejected"):
            raise AdjudicationError("resolution 必须是 accepted 或 rejected")
        state = self._load()
        fork = state.forks.get(fork_id)
        if fork is None:
            raise AdjudicationError(f"分叉案不存在：{fork_id}")
        if fork.status == "resolved":
            raise AdjudicationError(f"分叉案 {fork_id} 已裁决，禁止覆盖历史裁决")
        if state.families[fork.family_id].frozen:
            raise FamilyFrozen("任务族已冻结，裁决须先解除冻结")
        if resolution == "accepted":
            if chosen_digest is None or chosen_digest not in fork.candidate_digests:
                raise AdjudicationError("accepted 裁决必须选择一个在册候选摘要")
        at = clock.now_iso()
        self.store.append(
            event_id=f"ev-fork-res-{fork_id}",
            tenant=fork.tenant,
            event_type="fork.resolved",
            aggregate_id=fork.family_id,
            delegation_id=fork.delegation_id,
            occurred_at=at,
            actor_id=actor_id,
            payload={
                "fork_id": fork_id,
                "chosen_digest": chosen_digest,
                "resolution": resolution,
                "resolved_by": actor_id,
                "resolved_at": at,
                "reason": reason,
            },
        )
        state = self._load()
        # rejected 会让序号位置空出，立即登记新缺口。
        self._emit_gap_events(state, fork.delegation_id, actor_id)
        return self._load().forks[fork_id]

    # ============================================================ 封存

    @_guarded
    def seal_chain(
        self,
        delegation_id: str,
        *,
        sealed_by: str,
        declare_complete: bool = False,
    ) -> SealRecord:
        """封存委派链的接收顺序快照。

        必要条件（任一不满足都拒绝，而不是近似封存）：
        无未决分叉、无缺口；且要么登记过预期片段数且已收齐，
        要么封存人显式 declare_complete。
        """
        state = self._load()
        d = state.delegations.get(delegation_id)
        if d is None:
            raise LookupError(f"委派不存在：{delegation_id}")
        if state.families[d.family_id].frozen:
            raise FamilyFrozen("任务族已冻结，禁止封存")
        if delegation_id in state.seals:
            raise ChainSealed(f"委派 {delegation_id} 已封存，原始顺序不可改写")
        if state.open_forks(d.family_id, delegation_id):
            raise UnresolvedFork("存在未裁决分叉，必须裁决后才能封存")
        gaps = state.gaps(delegation_id)
        if gaps:
            raise ChainNotComplete(f"链存在缺口，禁止封存：{gaps[0].source}#{gaps[0].missing_seq}")

        canonical = state.canonical_fragments(delegation_id)
        if not canonical:
            raise ChainNotComplete("没有任何片段，禁止封存空链")
        if d.expected_count is not None:
            if len(canonical) < d.expected_count:
                raise ChainNotComplete(
                    f"已收 {len(canonical)} 片段，预期 {d.expected_count}，链未收齐"
                )
            if len(canonical) > d.expected_count:
                raise ChainNotComplete(
                    f"已收 {len(canonical)} 片段，超出预期 {d.expected_count}"
                )
        elif not declare_complete:
            raise ChainNotComplete(
                "未登记预期片段数；封存人必须显式 declare_complete 才能宣告封账"
            )

        # 封存快照严格按*接收顺序*（recv_index）——逻辑时间线另行提供。
        ordered = sorted(canonical, key=lambda f: f.recv_index)
        entries: list[tuple[str, str]] = []
        head: str | None = None
        max_seq_by_source: dict[str, int] = {}
        for f in ordered:
            head = hash_entry(head, f.source, f.seq, f.digest)
            entries.append((head, f.fragment_id))
            max_seq_by_source[f.source] = max(max_seq_by_source.get(f.source, 0), f.seq)

        adjudications = [
            (fk.fork_id, fk.chosen_digest or "")
            for fk in state.forks.values()
            if fk.delegation_id == delegation_id and fk.status == "resolved"
        ]
        seal_id = f"seal-{uuid.uuid4().hex[:16]}"
        at = clock.now_iso()
        self.store.append(
            event_id=f"ev-seal-{delegation_id}",
            tenant=d.tenant,
            event_type="chain.sealed",
            aggregate_id=d.family_id,
            delegation_id=delegation_id,
            occurred_at=at,
            actor_id=sealed_by,
            payload={
                "tenant": d.tenant,
                "family_id": d.family_id,
                "delegation_id": delegation_id,
                "seal_id": seal_id,
                "sealed_at": at,
                "sealed_by": sealed_by,
                "entries": entries,
                "head_hash": head,
                "fragment_count": len(entries),
                "expected_count": d.expected_count,
                "max_seq_by_source": max_seq_by_source,
                "declared_complete": declare_complete or d.expected_count is not None,
                "adjudications": adjudications,
            },
        )
        return self._load().seals[delegation_id]

    # ============================================================ 冻结

    @_guarded
    def freeze_family(self, family_id: str, *, actor_id: str, reason: str) -> FamilyState:
        state = self._load()
        self._tenant_of_family(state, family_id)
        at = clock.now_iso()
        self.store.append(
            event_id=f"ev-freeze-{family_id}-{uuid.uuid4().hex[:8]}",
            tenant=state.tenant_by_family[family_id],
            event_type="family.frozen",
            aggregate_id=family_id,
            occurred_at=at,
            actor_id=actor_id,
            payload={
                "tenant": state.tenant_by_family[family_id],
                "family_id": family_id,
                "occurred_at": at,
                "frozen_by": actor_id,
                "reason": reason,
            },
        )
        return self._load().family_state(family_id)

    @_guarded
    def release_family(self, family_id: str, *, actor_id: str, reason: str) -> FamilyState:
        state = self._load()
        self._tenant_of_family(state, family_id)
        at = clock.now_iso()
        self.store.append(
            event_id=f"ev-release-{family_id}-{uuid.uuid4().hex[:8]}",
            tenant=state.tenant_by_family[family_id],
            event_type="family.released",
            aggregate_id=family_id,
            occurred_at=at,
            actor_id=actor_id,
            payload={
                "tenant": state.tenant_by_family[family_id],
                "family_id": family_id,
                "occurred_at": at,
                "released_by": actor_id,
                "reason": reason,
            },
        )
        return self._load().family_state(family_id)

    # ============================================================ 查询/投影/审计

    def family_status(self, family_id: str) -> dict[str, Any]:
        state = self._load()
        self._tenant_of_family(state, family_id)
        delegations = [
            state.delegation_view(d_id)
            for d_id in sorted(state.family_delegations.get(family_id, ()))
        ]
        return {
            "family_id": family_id,
            "state": state.family_state(family_id).value,
            "frozen": state.families[family_id].frozen,
            "delegations": delegations,
            "open_forks": state.open_forks(family_id),
        }

    def delegation_status(self, delegation_id: str) -> dict[str, Any]:
        state = self._load()
        if delegation_id not in state.delegations:
            raise LookupError(f"委派不存在：{delegation_id}")
        d = state.delegations[delegation_id]
        complete, reason = state.delegation_complete(delegation_id)
        seal = state.seals.get(delegation_id)
        return {
            "view": state.delegation_view(delegation_id),
            "gaps": tuple(state.gaps(delegation_id)) + tuple(state.supplement_gaps(delegation_id)),
            "open_forks": state.open_forks(d.family_id, delegation_id),
            "seal": seal,
            "supplement": state.supplement_segment(delegation_id),
            "complete": complete,
            "completeness_reason": reason,
            "chain_valid": state.verify_chain(delegation_id) if seal else None,
        }

    def _authorize_tenant(self, state: ReplayedState, family_id: str, viewer_tenant: str) -> None:
        owner = self._tenant_of_family(state, family_id)
        if viewer_tenant != owner:
            # 租户隔离在入口处强制执行；证据内部嵌入的跨租户字段由投影策略处理。
            raise AccessDenied(
                f"租户 {viewer_tenant} 无权读取任务族 {family_id}（属主 {owner}）"
            )

    def _project_entries(
        self, state: ReplayedState, fragments: list[Fragment], role: str, viewer_tenant: str
    ) -> list[ProjectedEntry]:
        entries: list[ProjectedEntry] = []
        for f in fragments:
            projection = self.projections.project(
                f.payload,
                original_digest=f.digest,
                fragment_id=f.fragment_id,
                role=role,
                viewer_tenant=viewer_tenant,
                owner_tenant=f.tenant,
            )
            entries.append(ProjectedEntry(fragment=f, projection=projection))
        return entries

    @staticmethod
    def _rationale(entries: list[ProjectedEntry], role: str) -> str:
        dropped = sum(
            1 for e in entries for r in e.projection.redactions if r.action == "dropped"
        )
        masked = sum(
            1 for e in entries for r in e.projection.redactions if r.action in ("masked", "tagged")
        )
        return f"角色 {role} 投影：脱敏/标记 {masked} 处，剔除 {dropped} 处；原始摘要保持可验证"

    def _audit_read(
        self,
        *,
        state: ReplayedState,
        family_id: str,
        actor_id: str,
        role: str,
        action: str,
        entries: list[ProjectedEntry],
        purpose: str,
        export_id: str | None = None,
    ) -> ReadAuditRecord:
        tenant = state.tenant_by_family[family_id]
        fragment_ids = tuple(sorted(e.fragment.fragment_id for e in entries))
        at = clock.now_iso()
        result_body = [
            {
                "fragment_id": e.fragment.fragment_id,
                "original_digest": e.projection.original_digest,
                "redactions": [
                    {"path": r.path, "classifier": r.classifier, "action": r.action}
                    for r in e.projection.redactions
                ],
                "content": e.projection.content,
            }
            for e in entries
        ]
        result_digest = content_digest(result_body)
        fingerprint = content_digest(
            [actor_id, role, purpose, tenant, sorted(fragment_ids), at]
        )
        audit_id = f"aud-{uuid.uuid4().hex[:16]}"
        self.store.append(
            event_id=f"ev-aud-{audit_id}",
            tenant=tenant,
            event_type="read.audited",
            aggregate_id=family_id,
            occurred_at=at,
            actor_id=actor_id,
            payload={
                "tenant": tenant,
                "family_id": family_id,
                "audit_id": audit_id,
                "actor_id": actor_id,
                "role": role,
                "action": action,
                "fingerprint": fingerprint,
                "projection_policy_version": self.projections.version,
                "result_digest": result_digest,
                "fragment_ids": list(fragment_ids),
                "rationale": self._rationale(entries, role),
                "accessed_at": at,
                "purpose": purpose,
                "export_id": export_id,
            },
        )
        return ReadAuditRecord(
            audit_id=audit_id,
            tenant=tenant,
            family_id=family_id,
            actor_id=actor_id,
            role=role,
            action=action,
            fingerprint=fingerprint,
            projection_policy_version=self.projections.version,
            result_digest=result_digest,
            fragment_ids=fragment_ids,
            rationale=self._rationale(entries, role),
            accessed_at=at,
            purpose=purpose,
            export_id=export_id,
        )

    @_guarded
    def read_family(
        self,
        family_id: str,
        *,
        actor_id: str,
        role: str,
        viewer_tenant: str,
        purpose: str,
    ) -> tuple[tuple[ProjectedEntry, ...], ReadAuditRecord]:
        """读取任务族全部片段的角色投影；每次读取都留下审计。"""
        state = self._load()
        self._authorize_tenant(state, family_id, viewer_tenant)
        fragments = sorted(state.fragments_for_family(family_id), key=lambda f: f.received_at)
        entries = self._project_entries(state, fragments, role, viewer_tenant)
        audit = self._audit_read(
            state=state, family_id=family_id, actor_id=actor_id, role=role,
            action="family.read", entries=entries, purpose=purpose,
        )
        return tuple(entries), audit

    @_guarded
    def export_family(
        self,
        family_id: str,
        *,
        actor_id: str,
        role: str,
        viewer_tenant: str,
        purpose: str,
    ) -> ExportBundle:
        """出具任务族导出：证明导出由哪些封存片段组成（含角色投影）。

        完整性标志严格来自重放判定——未封存、有缺口、有未决分叉时
        ``complete=False`` 并在 manifest 中列明原因，绝不默认完整。
        """
        state = self._load()
        self._authorize_tenant(state, family_id, viewer_tenant)
        root, fragment_ids, complete, notes = state.export_root(family_id)
        fragments = [
            state.fragments[fid]
            for fid in sorted(fragment_ids, key=lambda x: state.fragments[x].recv_index)
        ]
        entries = self._project_entries(state, fragments, role, viewer_tenant)
        export_id = f"exp-{uuid.uuid4().hex[:16]}"
        at = clock.now_iso()
        seal_heads = {
            d_id: {
                "seal_head": state.seals[d_id].head_hash,
                "sealed_at": state.seals[d_id].sealed_at,
                "supplement_head": (
                    state.supplement_segment(d_id).head_hash
                    if state.supplement_segment(d_id) else None
                ),
            }
            for d_id in state.family_delegations.get(family_id, set())
            if d_id in state.seals
        }
        # 封存后又产生裁决结果的分叉：封存事实不可变，但必须标注其证据地位变化。
        post_seal_findings = []
        for fk in state.forks.values():
            if fk.family_id != family_id or fk.status != "resolved":
                continue
            seal = state.seals.get(fk.delegation_id)
            if seal is None:
                continue
            sealed_ids = {fid for _, fid in seal.entries}
            candidates = state.candidate_fragments(fk.delegation_id, fk.source, fk.seq)
            losing_in_seal = [
                c.fragment_id for c in candidates
                if c.fragment_id in sealed_ids and c.digest != fk.chosen_digest
            ]
            chosen_outside_seal = [
                c.fragment_id for c in candidates
                if c.fragment_id not in sealed_ids and c.digest == fk.chosen_digest
            ]
            if losing_in_seal or chosen_outside_seal or fk.resolution == "rejected":
                post_seal_findings.append({
                    "fork_id": fk.fork_id,
                    "delegation_id": fk.delegation_id,
                    "source": fk.source,
                    "seq": fk.seq,
                    "resolution": fk.resolution,
                    "chosen_digest": fk.chosen_digest,
                    "sealed_fragments_disavowed": losing_in_seal,
                    "chosen_fragment_outside_seal": chosen_outside_seal,
                })
        manifest = {
            "export_id": export_id,
            "family_id": family_id,
            "tenant": viewer_tenant,
            "created_at": at,
            "role": role,
            "policy_version": self.projections.version,
            "root_digest": root,
            "fragment_ids": sorted(fragment_ids),
            "fragment_evidence": [
                {
                    "fragment_id": e.fragment.fragment_id,
                    "source": e.fragment.source,
                    "seq": e.fragment.seq,
                    "original_digest": e.projection.original_digest,
                    "segment": e.fragment.segment,
                }
                for e in entries
            ],
            "seal_heads": seal_heads,
            "post_seal_findings": post_seal_findings,
            "complete": complete,
            "notes": notes,
        }
        record = ExportRecord(
            export_id=export_id,
            tenant=viewer_tenant,
            family_id=family_id,
            requested_by=actor_id,
            role=role,
            created_at=at,
            fragment_ids=tuple(sorted(fragment_ids)),
            seal_head=root,
            root_digest=root,
            policy_version=self.projections.version,
            complete=complete,
            note="; ".join(notes) if notes else None,
        )
        self.store.append(
            event_id=f"ev-exp-{export_id}",
            tenant=viewer_tenant,
            event_type="export.created",
            aggregate_id=family_id,
            occurred_at=at,
            actor_id=actor_id,
            payload={
                "tenant": viewer_tenant,
                "family_id": family_id,
                "export_id": export_id,
                "requested_by": actor_id,
                "role": role,
                "created_at": at,
                "fragment_ids": sorted(fragment_ids),
                "seal_head": root,
                "root_digest": root,
                "policy_version": self.projections.version,
                "complete": complete,
                "note": "; ".join(notes) if notes else None,
            },
        )
        audit = self._audit_read(
            state=state, family_id=family_id, actor_id=actor_id, role=role,
            action="export.create", entries=entries, purpose=purpose, export_id=export_id,
        )
        return ExportBundle(record=record, entries=tuple(entries), manifest=manifest, audit=audit)

    def verify_export(self, export_id: str) -> bool:
        """根据当前事件日志重新归集根摘要，核验导出组成证明。"""
        state = self._load()
        for records in state.exports.values():
            for record in records:
                if record.export_id == export_id:
                    return state.verify_export(record)
        raise LookupError(f"导出不存在：{export_id}")

    def list_audits(self, family_id: str) -> tuple[ReadAuditRecord, ...]:
        state = self._load()
        self._tenant_of_family(state, family_id)
        return tuple(state.audits.get(family_id, ()))

    # ============================================================ 恢复

    def pending_work(self, family_id: str | None = None) -> PendingWork:
        """重启后调用：列出全部未决分叉、有缺口和未封存的委派。"""
        state = self._load()
        families = [family_id] if family_id else list(state.families)
        open_forks: list[Fork] = []
        gapped: list[tuple[str, tuple[Gap, ...]]] = []
        unsealed: list[str] = []
        overturned: list[tuple[str, str]] = []
        for fam_id in families:
            if fam_id not in state.families:
                continue
            open_forks.extend(state.open_forks(fam_id))
            for d_id in sorted(state.family_delegations.get(fam_id, ())):
                gaps = state.gaps(d_id)
                if gaps:
                    gapped.append((d_id, tuple(gaps)))
                elif d_id not in state.seals:
                    unsealed.append(d_id)
                else:
                    complete, reason = state.delegation_complete(d_id)
                    if not complete:
                        overturned.append((d_id, reason or "完整性不成立"))
        return PendingWork(
            open_forks=tuple(sorted(open_forks, key=lambda f: f.opened_at)),
            gapped_delegations=tuple(gapped),
            unsealed_delegations=tuple(unsealed),
            overturned_seals=tuple(overturned),
        )
