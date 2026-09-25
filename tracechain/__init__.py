"""子智能体追踪证据链服务。

领域资料见 ``domain/``；本包在其之上提供持久化服务：

- 稳定委派关联标识与幂等上报
- 按接收顺序追加的哈希链，逻辑时间线按来源序列号重组
- 缺口、迟到片段、分叉裁决的显式状态机
- 按角色生成的敏感投影与读取审计
- 任务族冻结、导出封存证明与重启恢复
"""
from __future__ import annotations

from .errors import (
    AccessDeniedError,
    ChainSealedError,
    FrozenError,
    NotFoundError,
    StateError,
    TraceChainError,
    ValidationError,
)
from .projections import load_projection_policy
from .service import TraceEvidenceService

__all__ = [
    "TraceEvidenceService",
    "load_projection_policy",
    "TraceChainError",
    "ValidationError",
    "NotFoundError",
    "StateError",
    "ChainSealedError",
    "FrozenError",
    "AccessDeniedError",
]
