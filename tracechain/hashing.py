"""内容寻址与稳定标识。

- 证据只以 SHA-256 摘要进入哈希链，原始载荷留在片段表，投影变换不影响链。
- 委派标识由租户、任务族、父任务与委派指令摘要确定性派生：
  同一委派被重复上报时得到同一标识（幂等），不同指令不会撞标识。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_ALGO = "sha256"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_digest(payload: Any) -> str:
    """计算任意 JSON 可序列化载荷的稳定摘要。

    键排序 + 紧凑分隔，避免 dict 序列化顺序造成摘要漂移。
    """
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return f"{HASH_ALGO}:{_sha256(canonical)}"


def hash_entry(previous_head: str | None, source: str, seq: int, digest: str) -> str:
    """计算链上一个接收登记的哈希。

    哈希输入包含上一封存头（链位置）与来源序列号、内容摘要（唯一性三元组），
    因此调换顺序、替换内容、在中间插入都会破坏链。
    """
    material = "|".join([previous_head or "GENESIS", source, str(seq), digest])
    return f"{HASH_ALGO}:{_sha256(material.encode('utf-8'))}"


def hash_concat(left: str, right: str) -> str:
    """两段哈希的归集摘要（封存补充段锚定、导出归集时使用）。"""
    return f"{HASH_ALGO}:{_sha256(f'{left}|{right}'.encode('utf-8'))}"


def stable_delegation_id(tenant: str, family_id: str, parent_task_id: str, instruction_digest: str) -> str:
    """从业务键确定性派生委派标识。"""
    material = "|".join(["delegation", tenant, family_id, parent_task_id, instruction_digest])
    return f"del-{_sha256(material.encode('utf-8'))[:24]}"


def stable_family_id(tenant: str, external_case_id: str) -> str:
    """从外部案件/调查标识确定性派生任务族标识。"""
    material = "|".join(["family", tenant, external_case_id])
    return f"fam-{_sha256(material.encode('utf-8'))[:24]}"


def short_token(value: str) -> str:
    """从事件载荷派生短事件号，仅用于展示与幂等键。"""
    return _sha256(value.encode("utf-8"))[:16]
