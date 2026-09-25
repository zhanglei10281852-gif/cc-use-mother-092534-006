"""哈希与规范化原语。

所有跨进程、跨重启需要保持一致的摘要都走 :func:`canonical` ，
禁止依赖 Python ``dict`` 的插入顺序或默认 JSON 空白。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

# 封存算法版本，写入每条哈希记录；算法调整必须新版本追加，旧版本仍可验证。
CHAIN_ALGORITHM_VERSION = "sha256-canon-v1"


def canonical(value: Any) -> bytes:
    """把任意可 JSON 化对象编码为稳定字节序列。"""
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """对规范化后的对象计算 SHA-256 十六进制摘要。"""
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_content(content: Any) -> str:
    """片段原始内容的摘要：只依赖内容本身。"""
    return sha256_hex(content)


def chain_entry_hash(
    prev_hash: str,
    *,
    fragment_id: str,
    source_seq: int,
    content_hash: str,
    entry_kind: str,
    fork_id: str | None,
) -> str:
    """计算一条哈希链条目的链头摘要。

    链条目绑定片段身份、来源序列号、内容摘要、条目性质
    （正常接收或分叉裁决胜出补入）以及上一链头。
    """
    return sha256_hex(
        [
            CHAIN_ALGORITHM_VERSION,
            prev_hash,
            {
                "fragment_id": fragment_id,
                "source_seq": source_seq,
                "content_hash": content_hash,
                "entry_kind": entry_kind,
                "fork_id": fork_id,
            },
        ]
    )


def seal_root_hash(
    final_head: str,
    timeline: Iterable[tuple[int, str]],
    resolutions: Iterable[dict[str, Any]],
) -> str:
    """封存根：最终链头 + 逻辑时间线映射 + 分叉裁决记录。"""
    return sha256_hex(
        {
            "algorithm": CHAIN_ALGORITHM_VERSION,
            "final_head": final_head,
            "timeline": [{"source_seq": seq, "fragment_id": fid} for seq, fid in sorted(timeline)],
            "fork_resolutions": sorted(resolutions, key=lambda r: r["fork_id"]),
        }
    )


def event_hash(prev_hash: str, event_fields: dict[str, Any]) -> str:
    """全局事件日志自身的哈希链摘要。"""
    return sha256_hex([CHAIN_ALGORITHM_VERSION, prev_hash, event_fields])
