"""领域状态与只读数据模型。

状态集合与 domain/contract.json 保持一致；模型对象均为不可变快照，
可变状态集中在 :mod:`tracechain.state` 的重放聚合里。
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class FamilyState(str, enum.Enum):
    OPEN = "open"
    COLLECTING = "collecting"
    GAPPED = "gapped"
    FORKED = "forked"
    ADJUDICATING = "adjudicating"
    SEALED = "sealed"
    FROZEN = "frozen"
    RELEASED = "released"


# 终态：到达后不再接收新片段（frozen 可被显式解冻为 released）。
TERMINAL_STATES = {FamilyState.SEALED, FamilyState.FROZEN, FamilyState.RELEASED}


@dataclass(frozen=True, slots=True)
class Fragment:
    fragment_id: str
    tenant: str
    family_id: str
    delegation_id: str
    source: str
    seq: int
    payload: Any
    digest: str
    occurred_at: str
    received_at: str
    # 接收序号（接收顺序，全链单调，封存快照按它排序）
    recv_index: int
    # 归属链段：main（原始封存段）/ sup-*（封存后迟到补充段）
    segment: str = "main"


@dataclass(frozen=True, slots=True)
class Fork:
    fork_id: str
    tenant: str
    family_id: str
    delegation_id: str
    source: str
    seq: int
    candidate_digests: tuple[str, ...]
    opened_at: str
    status: str = "open"  # open / adjudicating / resolved
    chosen_digest: str | None = None
    resolution: str | None = None  # accepted | rejected
    adjudicator: str | None = None
    adjudication_started_at: str | None = None
    resolved_by: str | None = None
    resolved_at: str | None = None
    reason: str | None = None
    after_seal: bool = False
    reopens: str | None = None  # 挑战已生效裁决时，原分叉案 id


@dataclass(frozen=True, slots=True)
class SealRecord:
    seal_id: str
    tenant: str
    family_id: str
    delegation_id: str
    sealed_at: str
    sealed_by: str
    # 封存快照：按接收顺序排列的 (entry_hash, fragment_id)
    entries: tuple[tuple[str, str], ...]
    head_hash: str
    fragment_count: int
    expected_count: int | None
    # 每个来源在封存时已覆盖到的最大序号（补充段缺口判定的边界）
    max_seq_by_source: tuple[tuple[str, int], ...]
    # 封存时纳入的所有分叉裁决（fork_id -> chosen_digest）
    adjudications: tuple[tuple[str, str], ...] = ()
    # 封存后迟到片段形成的补充段，锚定本封存头
    supplements: tuple["SupplementSegment", ...] = ()


@dataclass(frozen=True, slots=True)
class SupplementSegment:
    """封存后到达的片段形成的补充段。

    不触碰已封存的原始顺序，而是以封存头 ``anchor_head`` 为前缀独立成链，
    与封存段通过归集哈希绑定，保证“补入逻辑时间线但不改写封存”。
    """

    segment_id: str
    anchor_head: str
    entries: tuple[tuple[str, str], ...]
    head_hash: str
    opened_at: str


@dataclass(frozen=True, slots=True)
class Gap:
    source: str
    missing_seq: int
    detected_at: str


@dataclass(frozen=True, slots=True)
class ReadAuditRecord:
    audit_id: str
    tenant: str
    family_id: str
    actor_id: str
    role: str
    action: str
    fingerprint: str
    projection_policy_version: str
    result_digest: str
    fragment_ids: tuple[str, ...]
    rationale: str
    accessed_at: str
    purpose: str | None = None
    export_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExportRecord:
    export_id: str
    tenant: str
    family_id: str
    requested_by: str
    role: str
    created_at: str
    fragment_ids: tuple[str, ...]
    seal_head: str | None
    root_digest: str
    policy_version: str
    complete: bool
    note: str | None = None


@dataclass(frozen=True, slots=True)
class DelegationView:
    delegation_id: str
    tenant: str
    family_id: str
    parent_task_id: str
    instruction: str
    instruction_digest: str
    created_at: str
    expected_count: int | None
    state: str
