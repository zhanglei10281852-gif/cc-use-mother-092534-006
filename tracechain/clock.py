"""时间策略：ISO 8601 带时区（见 domain/contract.json）。

区分两类时间：

- ``occurred_at``：业务发生时间（逻辑时间线，允许迟到）。
- ``received_at``：服务接收时间（接收顺序，单调，封存后不可改写）。
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

DEFAULT_TZ = ZoneInfo("Asia/Shanghai")


def now_iso() -> str:
    """当前服务时间，带时区的 ISO 8601 字符串。"""
    return datetime.now(tz=DEFAULT_TZ).isoformat(timespec="microseconds")


def normalize(occurred_at: str) -> str:
    """校验并归一化业务时间：必须带时区，返回带偏移量的 ISO 字符串。"""
    dt = datetime.fromisoformat(occurred_at)
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("时间必须包含时区（ISO 8601 with timezone）")
    return dt.isoformat()


def parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return dt


def utc_epoch(ts: str) -> float:
    """转 UTC 纪元秒，用于跨时区排序比较。"""
    return parse(ts).astimezone(timezone.utc).timestamp()
