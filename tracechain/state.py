"""事件重放聚合。

进程内不保存任何“权威状态”：每次需要判定时都从事件日志重放得到本对象。
因此重启之后，链头、缺口、未决分叉、封存快照、补充段、审计与导出记录
全部自动恢复——不会因为进程退出而丢失裁决队列，也不会把未收齐的链
误认为完整。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .hashing import content_digest, hash_concat, hash_entry
from .models import (
    DelegationView,
    ExportRecord,
    FamilyState,
    Fork,
    Fragment,
    Gap,
    ReadAuditRecord,
    SealRecord,
    SupplementSegment,
)

# ---- 服务使用的事件类型（contract.json 列出的为领域基线，这里做只追加扩展） ----
EVENT_TYPES = (
    "family.created",
    "delegation.created",
    "fragment.accepted",
    "fragment.duplicated",
    "gap.detected",
    "fork.opened",
    "fork.candidate_added",
    "fork.adjudication_started",
    "fork.resolved",
    "chain.sealed",
    "family.frozen",
    "family.released",
    "read.audited",
    "export.created",
)


@dataclass
class _Delegation:
    delegation_id: str
    tenant: str
    family_id: str
    parent_task_id: str
    instruction: str
    instruction_digest: str
    created_at: str
    created_by: str
    expected_count: int | None
    declared_complete: bool = False
    ledger: list[str] = field(default_factory=list)          # 接收顺序 fragment_id
    supplement: list[str] = field(default_factory=list)      # 封存后迟到片段
    sup_hashes: list[str] = field(default_factory=list)      # 与 supplement 对齐
    sup_seg_id: str | None = None
    late_after_closure: bool = False


@dataclass
class _Family:
    family_id: str
    tenant: str
    created_at: str
    frozen: bool = False
    frozen_at: str | None = None
    frozen_by: str | None = None
    freeze_reason: str | None = None


class ReplayedState:
    """重放后的只读状态视图（由 :class:`tracechain.store.EventStore` 重建）。"""

    def __init__(self) -> None:
        self.families: dict[str, _Family] = {}
        self.delegations: dict[str, _Delegation] = {}
        self.fragments: dict[str, Fragment] = {}
        # (delegation_id, source, seq) -> 按接收顺序的候选 fragment_id
        self.slots: dict[tuple[str, str, int], list[str]] = {}
        self.forks: dict[str, Fork] = {}
        self.fork_index: dict[tuple[str, str, int], str] = {}
        self.fork_history: dict[tuple[str, str, int], list[str]] = {}
        self.detected_gaps: set[tuple[str, str, int]] = set()
        self.seals: dict[str, SealRecord] = {}
        self.audits: dict[str, list[ReadAuditRecord]] = {}
        self.exports: dict[str, list[ExportRecord]] = {}
        self.tenant_by_family: dict[str, str] = {}
        self.family_delegations: dict[str, set[str]] = {}

    # ------------------------------------------------------------------ 应用

    def apply(self, event_type: str, payload: dict[str, Any]) -> None:
        handler = getattr(self, f"_on_{event_type.replace('.', '_')}", None)
        if handler is not None:
            handler(payload)

    def _ensure_family(self, family_id: str, tenant: str, when: str) -> _Family:
        fam = self.families.get(family_id)
        if fam is None:
            fam = _Family(family_id=family_id, tenant=tenant, created_at=when)
            self.families[family_id] = fam
            self.tenant_by_family[family_id] = tenant
            self.family_delegations[family_id] = set()
        return fam

    def _on_family_created(self, p: dict[str, Any]) -> None:
        self._ensure_family(p["family_id"], p["tenant"], p["occurred_at"])

    def _on_delegation_created(self, p: dict[str, Any]) -> None:
        fam = self._ensure_family(p["family_id"], p["tenant"], p["created_at"])
        self.family_delegations[fam.family_id].add(p["delegation_id"])
        if p["delegation_id"] not in self.delegations:
            self.delegations[p["delegation_id"]] = _Delegation(
                delegation_id=p["delegation_id"],
                tenant=p["tenant"],
                family_id=p["family_id"],
                parent_task_id=p["parent_task_id"],
                instruction=p.get("instruction", ""),
                instruction_digest=p["instruction_digest"],
                created_at=p["created_at"],
                created_by=p.get("created_by", "system"),
                expected_count=p.get("expected_count"),
            )

    def _on_fragment_accepted(self, p: dict[str, Any]) -> None:
        d = self.delegations[p["delegation_id"]]
        fragment = Fragment(
            fragment_id=p["fragment_id"],
            tenant=p["tenant"],
            family_id=p["family_id"],
            delegation_id=p["delegation_id"],
            source=p["source"],
            seq=p["seq"],
            payload=p.get("payload"),
            digest=p["digest"],
            occurred_at=p["occurred_at"],
            received_at=p["received_at"],
            recv_index=p["recv_index"],
            segment=p.get("segment", "main"),
        )
        if fragment.fragment_id in self.fragments:
            return
        self.fragments[fragment.fragment_id] = fragment
        key = (d.delegation_id, p["source"], p["seq"])
        self.slots.setdefault(key, []).append(p["fragment_id"])
        # 主台账按接收顺序记录所有候选（含败诉候选与封存后争议），永不重排。
        d.ledger.append(p["fragment_id"])
        if p.get("supplement"):
            # 封存后迟到的*新序号*片段：补入逻辑时间线，锚定封存头，不入封存快照。
            d.supplement.append(p["fragment_id"])
            d.sup_hashes.append(p["sup_hash"])
            d.sup_seg_id = p.get("segment")
            d.late_after_closure = True

    def _on_fragment_duplicated(self, p: dict[str, Any]) -> None:
        # 重复上报只确认，不改变任何状态。
        return

    def _on_gap_detected(self, p: dict[str, Any]) -> None:
        # 记录系统曾宣告的缺口（审计轨迹）；当前缺口集合另由片段实况派生。
        for source, seq in p.get("missing", ()) if isinstance(p.get("missing"), (list, tuple)) else ():
            self.detected_gaps.add((p["delegation_id"], source, int(seq)))

    def _on_fork_opened(self, p: dict[str, Any]) -> None:
        key = (p["delegation_id"], p["source"], p["seq"])
        active_id = self.fork_index.get(key)
        active = self.forks[active_id] if active_id else None
        if active is not None and active.status in ("open", "adjudicating"):
            # 第三、四个候选继续并入同一未决分叉案。
            merged = tuple(dict.fromkeys(active.candidate_digests + tuple(p["candidate_digests"])))
            self.forks[active.fork_id] = Fork(
                fork_id=active.fork_id,
                tenant=active.tenant,
                family_id=active.family_id,
                delegation_id=active.delegation_id,
                source=active.source,
                seq=active.seq,
                candidate_digests=merged,
                opened_at=active.opened_at,
                after_seal=active.after_seal,
                reopens=active.reopens,
            )
            return
        # 该位置此前无分叉或已裁决过：新开一案（裁决后又出现新候选时）。
        fork = Fork(
            fork_id=p["fork_id"],
            tenant=p["tenant"],
            family_id=p["family_id"],
            delegation_id=p["delegation_id"],
            source=p["source"],
            seq=p["seq"],
            candidate_digests=tuple(p["candidate_digests"]),
            opened_at=p["opened_at"],
            after_seal=bool(p.get("after_seal", False)),
            reopens=p.get("reopens_resolved_fork"),
        )
        self.forks[fork.fork_id] = fork
        self.fork_index[key] = fork.fork_id
        self.fork_history.setdefault(key, []).append(fork.fork_id)

    def _on_fork_candidate_added(self, p: dict[str, Any]) -> None:
        """新的冲突候选并入已开立的未决分叉案。"""
        fork = self.forks[p["fork_id"]]
        merged = tuple(dict.fromkeys(fork.candidate_digests + tuple(p["candidate_digests"])))
        self.forks[fork.fork_id] = Fork(
            fork_id=fork.fork_id,
            tenant=fork.tenant,
            family_id=fork.family_id,
            delegation_id=fork.delegation_id,
            source=fork.source,
            seq=fork.seq,
            candidate_digests=merged,
            opened_at=fork.opened_at,
            status=fork.status,
            adjudicator=fork.adjudicator,
            adjudication_started_at=fork.adjudication_started_at,
            after_seal=fork.after_seal,
            reopens=fork.reopens,
        )

    def _on_fork_adjudication_started(self, p: dict[str, Any]) -> None:
        fork = self.forks[p["fork_id"]]
        self.forks[p["fork_id"]] = Fork(
            fork_id=fork.fork_id,
            tenant=fork.tenant,
            family_id=fork.family_id,
            delegation_id=fork.delegation_id,
            source=fork.source,
            seq=fork.seq,
            candidate_digests=fork.candidate_digests,
            opened_at=fork.opened_at,
            status="adjudicating",
            adjudicator=p.get("adjudicator"),
            adjudication_started_at=p["at"],
            after_seal=fork.after_seal,
            reopens=fork.reopens,
        )

    def _on_fork_resolved(self, p: dict[str, Any]) -> None:
        fork = self.forks[p["fork_id"]]
        self.forks[p["fork_id"]] = Fork(
            fork_id=fork.fork_id,
            tenant=fork.tenant,
            family_id=fork.family_id,
            delegation_id=fork.delegation_id,
            source=fork.source,
            seq=fork.seq,
            candidate_digests=fork.candidate_digests,
            opened_at=fork.opened_at,
            status="resolved",
            chosen_digest=p["chosen_digest"],
            resolution=p["resolution"],
            adjudicator=fork.adjudicator,
            adjudication_started_at=fork.adjudication_started_at,
            resolved_by=p.get("resolved_by"),
            resolved_at=p["resolved_at"],
            reason=p.get("reason"),
            after_seal=fork.after_seal,
            reopens=fork.reopens,
        )

    def _on_chain_sealed(self, p: dict[str, Any]) -> None:
        d = self.delegations[p["delegation_id"]]
        d.declared_complete = bool(p.get("declared_complete", False))
        d.sup_seg_id = f"sup-{p['seal_id']}"
        entries = tuple((e[0], e[1]) for e in p["entries"])
        seal = SealRecord(
            seal_id=p["seal_id"],
            tenant=p["tenant"],
            family_id=p["family_id"],
            delegation_id=p["delegation_id"],
            sealed_at=p["sealed_at"],
            sealed_by=p["sealed_by"],
            entries=entries,
            head_hash=p["head_hash"],
            fragment_count=p["fragment_count"],
            expected_count=p.get("expected_count"),
            max_seq_by_source=tuple(
                (s, seq) for s, seq in sorted(p.get("max_seq_by_source", {}).items())
            ),
            adjudications=tuple((a[0], a[1]) for a in p.get("adjudications", [])),
        )
        self.seals[d.delegation_id] = seal

    def _on_family_frozen(self, p: dict[str, Any]) -> None:
        fam = self._ensure_family(p["family_id"], p["tenant"], p["occurred_at"])
        fam.frozen = True
        fam.frozen_at = p["occurred_at"]
        fam.frozen_by = p.get("frozen_by")
        fam.freeze_reason = p.get("reason")

    def _on_family_released(self, p: dict[str, Any]) -> None:
        fam = self.families[p["family_id"]]
        fam.frozen = False
        fam.frozen_at = None
        fam.frozen_by = None
        fam.freeze_reason = None

    def _on_read_audited(self, p: dict[str, Any]) -> None:
        record = ReadAuditRecord(
            audit_id=p["audit_id"],
            tenant=p["tenant"],
            family_id=p["family_id"],
            actor_id=p["actor_id"],
            role=p["role"],
            action=p["action"],
            fingerprint=p["fingerprint"],
            projection_policy_version=p["projection_policy_version"],
            result_digest=p["result_digest"],
            fragment_ids=tuple(p["fragment_ids"]),
            rationale=p["rationale"],
            accessed_at=p["accessed_at"],
            purpose=p.get("purpose"),
            export_id=p.get("export_id"),
        )
        self.audits.setdefault(p["family_id"], []).append(record)

    def _on_export_created(self, p: dict[str, Any]) -> None:
        record = ExportRecord(
            export_id=p["export_id"],
            tenant=p["tenant"],
            family_id=p["family_id"],
            requested_by=p["requested_by"],
            role=p["role"],
            created_at=p["created_at"],
            fragment_ids=tuple(p["fragment_ids"]),
            seal_head=p.get("seal_head"),
            root_digest=p["root_digest"],
            policy_version=p["policy_version"],
            complete=bool(p["complete"]),
            note=p.get("note"),
        )
        self.exports.setdefault(p["family_id"], []).append(record)

    # -------------------------------------------------------------- 派生查询

    def family_state(self, family_id: str) -> FamilyState:
        fam = self.families[family_id]
        if fam.frozen:
            return FamilyState.FROZEN
        pending = self.open_forks(family_id)
        if pending:
            if any(f.status == "open" for f in pending):
                return FamilyState.FORKED
            return FamilyState.ADJUDICATING
        if any(self.gaps(d.delegation_id) for d in self._family_delegations(family_id)):
            return FamilyState.GAPPED
        delegation_ids = self.family_delegations.get(family_id, set())
        if delegation_ids and all(d_id in self.seals for d_id in delegation_ids):
            return FamilyState.SEALED
        if any(self.fragments_for_delegation(d.delegation_id) for d in self._family_delegations(family_id)):
            return FamilyState.COLLECTING
        return FamilyState.OPEN

    def _family_delegations(self, family_id: str) -> list[_Delegation]:
        return [self.delegations[d] for d in self.family_delegations.get(family_id, set())]

    def delegation_view(self, delegation_id: str) -> DelegationView:
        d = self.delegations[delegation_id]
        if delegation_id in self.seals:
            state = FamilyState.SEALED.value
        elif self.open_forks(d.family_id, delegation_id):
            state = FamilyState.FORKED.value
        elif self.gaps(delegation_id):
            state = FamilyState.GAPPED.value
        elif self.fragments_for_delegation(delegation_id):
            state = FamilyState.COLLECTING.value
        else:
            state = FamilyState.OPEN.value
        return DelegationView(
            delegation_id=d.delegation_id,
            tenant=d.tenant,
            family_id=d.family_id,
            parent_task_id=d.parent_task_id,
            instruction=d.instruction,
            instruction_digest=d.instruction_digest,
            created_at=d.created_at,
            expected_count=d.expected_count,
            state=state,
        )

    def fragments_for_delegation(self, delegation_id: str) -> list[Fragment]:
        d = self.delegations[delegation_id]
        return [self.fragments[fid] for fid in d.ledger]

    def fragments_for_family(self, family_id: str) -> list[Fragment]:
        result: list[Fragment] = []
        for d in self._family_delegations(family_id):
            result.extend(self.fragments[fid] for fid in d.ledger)
        return result

    def open_forks(self, family_id: str, delegation_id: str | None = None) -> list[Fork]:
        """尚未裁决的分叉（open 或裁决中 adjudicating 都算未决，禁止封存）。"""
        forks = [
            f for f in self.forks.values()
            if f.family_id == family_id and f.status in ("open", "adjudicating")
            and (delegation_id is None or f.delegation_id == delegation_id)
        ]
        return sorted(forks, key=lambda f: (f.opened_at, f.fork_id))

    # -- 链结构判定 -------------------------------------------------------

    def _occupied_slots(self, delegation_id: str) -> dict[str, dict[int, Fragment]]:
        """返回每个来源上“规范占位”的片段：无争议或裁决 accepted 的候选。

        只统计主段（封存前接收、封存后争议候选）；封存后迟到的补充段
        有独立的边界与链，由 supplement_* 方法核算，避免双重计数。
        """
        result: dict[str, dict[int, Fragment]] = {}
        for (d_id, source, seq), candidate_ids in self.slots.items():
            if d_id != delegation_id:
                continue
            main_candidates = [
                self.fragments[fid] for fid in candidate_ids
                if self.fragments[fid].segment == "main"
            ]
            if not main_candidates:
                continue
            active, latest, disavowed = self.slot_history(d_id, source, seq)
            chosen: Fragment | None = None
            if active is not None:
                # 未裁决：占位但不可封存；放首个未被否决的候选供缺口计算。
                chosen = next(
                    (c for c in main_candidates if c.digest not in disavowed),
                    main_candidates[0],
                )
            elif latest is not None and latest.resolution == "accepted":
                chosen = next(
                    (c for c in main_candidates if c.digest == latest.chosen_digest),
                    None,
                )
            elif latest is not None and latest.resolution == "rejected":
                # 裁决之后补送的、不属于任何被否决摘要的内容填补该位置。
                chosen = next(
                    (c for c in main_candidates
                     if c.digest not in disavowed
                     and c.received_at > (latest.resolved_at or "")),
                    None,
                )
            else:
                chosen = main_candidates[0]
            if chosen is not None:
                result.setdefault(source, {})[seq] = chosen
        return result

    def gaps(self, delegation_id: str) -> list[Gap]:
        """当前缺口：每个来源从 1 到*观察到的最大序号*之间没有规范占位的位置。

        观察上界来自全部主段槽位（含败诉候选）：因此分叉裁决 rejected 后，
        被否决的尾部序号也会重新暴露为缺口，而不会悄悄消失。
        未决分叉位置由首个候选占位，表现为分叉而非缺口。
        """
        occupied = self._occupied_slots(delegation_id)
        observed_max: dict[str, int] = {}
        for (d_id, source, seq), candidate_ids in self.slots.items():
            if d_id != delegation_id:
                continue
            if any(self.fragments[c].segment == "main" for c in candidate_ids):
                observed_max[source] = max(observed_max.get(source, 0), seq)
        gaps: list[Gap] = []
        for source in sorted(observed_max):
            occ = occupied.get(source, {})
            first_seen = min(
                f.received_at for f in self.fragments_for_delegation(delegation_id)
                if f.source == source and f.segment == "main"
            )
            for seq in range(1, observed_max[source] + 1):
                if seq not in occ:
                    gaps.append(Gap(source=source, missing_seq=seq, detected_at=first_seen))
        return gaps

    def canonical_fragments(self, delegation_id: str) -> list[Fragment]:
        """规范链片段：按逻辑时间线 (source, seq) 排序，剔除败诉候选与 rejected 位置。"""
        occupied = self._occupied_slots(delegation_id)
        result: list[Fragment] = []
        for source in sorted(occupied):
            for seq in sorted(occupied[source]):
                fragment = occupied[source][seq]
                fork_id = self.fork_index.get((delegation_id, source, seq))
                if fork_id is not None and self.forks[fork_id].status in ("open", "adjudicating"):
                    continue  # 未决分叉不进入任何规范集合
                result.append(fragment)
        return result

    def candidate_fragments(self, delegation_id: str, source: str, seq: int) -> list[Fragment]:
        return [
            self.fragments[fid]
            for fid in self.slots.get((delegation_id, source, seq), [])
        ]

    def slot_history(
        self, delegation_id: str, source: str, seq: int
    ) -> tuple[Fork | None, Fork | None, frozenset[str]]:
        """返回 (当前未决分叉, 最近一次已裁决分叉, 被否决摘要集合)。

        被否决集合以*最近一次裁决*为准：
        - 最近一次 accepted：除当选摘要外的全部历史候选都被否决；
        - 最近一次 rejected：该位置全部历史候选都被否决。
        """
        key = (delegation_id, source, seq)
        fork_ids = self.fork_history.get(key, [])
        forks = [self.forks[fid] for fid in fork_ids]
        active = next(
            (f for f in reversed(forks) if f.status in ("open", "adjudicating")), None
        )
        resolved = [f for f in forks if f.status == "resolved"]
        latest = resolved[-1] if resolved else None
        all_candidates = {digest for f in forks for digest in f.candidate_digests}
        if latest is None:
            disavowed: frozenset[str] = frozenset()
        elif latest.resolution == "accepted":
            disavowed = frozenset(all_candidates - {latest.chosen_digest})
        else:
            disavowed = frozenset(all_candidates)
        return active, latest, disavowed

    # -- 封存后补充段 -----------------------------------------------------

    def supplement_segment(self, delegation_id: str) -> SupplementSegment | None:
        d = self.delegations[delegation_id]
        seal = self.seals.get(delegation_id)
        if seal is None or not d.supplement:
            return None
        return SupplementSegment(
            segment_id=d.sup_seg_id or f"sup-{seal.seal_id}",
            anchor_head=seal.head_hash,
            entries=tuple(zip(d.sup_hashes, d.supplement)),
            head_hash=d.sup_hashes[-1],
            opened_at=self.fragments[d.supplement[0]].received_at,
        )

    def supplement_gaps(self, delegation_id: str) -> list[Gap]:
        """补充段相对封存边界的缺口（新序号段内不连续时）。"""
        seal = self.seals.get(delegation_id)
        d = self.delegations[delegation_id]
        if seal is None or not d.supplement:
            return []
        sealed_max = dict(seal.max_seq_by_source)
        by_source: dict[str, list[int]] = {}
        for fid in d.supplement:
            f = self.fragments[fid]
            by_source.setdefault(f.source, []).append(f.seq)
        gaps: list[Gap] = []
        for source, seqs in by_source.items():
            start = sealed_max.get(source, 0) + 1
            for seq in range(start, max(seqs) + 1):
                if seq not in seqs:
                    gaps.append(Gap(source=source, missing_seq=seq, detected_at=seal.sealed_at))
        return gaps

    # -- 完整性与导出根摘要 -----------------------------------------------

    def post_seal_forks(self, delegation_id: str) -> list[Fork]:
        """封存后开立、且已裁决的分叉案（封存快照与现行规范可能不一致）。"""
        seal = self.seals.get(delegation_id)
        if seal is None:
            return []
        return [
            f for f in self.forks.values()
            if f.delegation_id == delegation_id and f.status == "resolved" and f.after_seal
        ]

    def delegation_complete(self, delegation_id: str) -> tuple[bool, str | None]:
        """判定委派链是否真正收齐。任何不满足项都给出原因，严禁默认完整。"""
        d = self.delegations[delegation_id]
        seal = self.seals.get(delegation_id)
        if seal is None:
            return False, "链尚未封存"
        if self.open_forks(d.family_id, delegation_id):
            return False, "存在未裁决分叉"
        post_seal = self.post_seal_forks(delegation_id)
        if post_seal:
            fk = post_seal[0]
            return False, (
                f"封存后 {fk.source}#{fk.seq} 的裁决改变了证据构成"
                "（封存快照不可变，需另行封存更正段）"
            )
        live_gaps = self.gaps(delegation_id)
        if live_gaps:
            return False, f"链上存在缺口：{live_gaps[0].source}#{live_gaps[0].missing_seq}"
        sup_gaps = self.supplement_gaps(delegation_id)
        if sup_gaps:
            return False, f"补充段存在缺口：{sup_gaps[0].source}#{sup_gaps[0].missing_seq}"
        if d.expected_count is not None:
            total = seal.fragment_count + len(d.supplement)
            if total < d.expected_count:
                return False, f"片段数 {total} 少于预期 {d.expected_count}"
            if total > d.expected_count:
                return False, f"片段数 {total} 超出预期 {d.expected_count}（可能存在迟到补充）"
            return True, None
        if d.declared_complete:
            if d.supplement:
                return False, "宣告完整后仍有迟到片段，完整性被推翻"
            return True, None
        return False, "未登记预期片段数且未显式宣告完整"

    def export_root(self, family_id: str) -> tuple[str, list[str], bool, list[str]]:
        """计算任务族导出根摘要与组成清单。

        返回 (root_digest, fragment_ids, complete, notes)。
        """
        leaves: list[str] = []
        fragment_ids: list[str] = []
        complete = True
        notes: list[str] = []
        for d in sorted(self._family_delegations(family_id), key=lambda x: x.delegation_id):
            seal = self.seals.get(d.delegation_id)
            if seal is None:
                complete = False
                notes.append(f"委派 {d.delegation_id} 尚未封存")
                canonical = self.canonical_fragments(d.delegation_id)
                fragment_ids.extend(f.fragment_id for f in canonical)
                leaf = "UNSEALED"
                for f in canonical:
                    leaf = hash_concat(leaf, f.digest)
                leaves.append(leaf)
                continue
            fragment_ids.extend(fid for _, fid in seal.entries)
            sup = self.supplement_segment(d.delegation_id)
            head = seal.head_hash
            if sup is not None:
                fragment_ids.extend(fid for _, fid in sup.entries)
                head = hash_concat(seal.head_hash, sup.head_hash)
            # 封存后裁决：不改封存段，但把更正（新当选片段/否决）绑定进导出叶摘要。
            for fk in sorted(self.post_seal_forks(d.delegation_id), key=lambda f: f.resolved_at or ""):
                if fk.resolution == "accepted":
                    winners = [
                        c.fragment_id for c in
                        self.candidate_fragments(d.delegation_id, fk.source, fk.seq)
                        if c.digest == fk.chosen_digest
                    ]
                    fragment_ids.extend(winners)
                    head = hash_concat(head, f"post-accept:{fk.fork_id}:{fk.chosen_digest}")
                else:
                    head = hash_concat(head, f"post-reject:{fk.fork_id}")
            leaves.append(hash_concat(f"seal:{seal.seal_id}", head))
            ok, reason = self.delegation_complete(d.delegation_id)
            if not ok:
                complete = False
                notes.append(f"委派 {d.delegation_id}：{reason}")
        root = "EXPORT"
        for leaf in leaves:
            root = hash_concat(root, leaf)
        return root, sorted(set(fragment_ids)), complete, notes

    def verify_chain(self, delegation_id: str) -> bool:
        """独立核验封存链：内容摘要与载荷一致，且接收顺序哈希链自洽。

        两层校验缺一不可：
        - content_digest(payload) == 存储的 digest（防止只篡改载荷）；
        - hash_entry(prev, source, seq, digest) == 封存 entry_hash（防止调序/换内容）。
        """
        seal = self.seals.get(delegation_id)
        if seal is None:
            return False
        head: str | None = None
        for entry_hash, fragment_id in seal.entries:
            f = self.fragments[fragment_id]
            if content_digest(f.payload) != f.digest:
                return False
            if hash_entry(head, f.source, f.seq, f.digest) != entry_hash:
                return False
            head = entry_hash
        return head == seal.head_hash

    def verify_export(self, export: ExportRecord) -> bool:
        root, fragments, _, _ = self.export_root(export.family_id)
        return root == export.root_digest and tuple(sorted(fragments)) == tuple(sorted(export.fragment_ids))
