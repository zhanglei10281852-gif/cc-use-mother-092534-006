"""服务层异常类型。"""
from __future__ import annotations


class TraceChainError(Exception):
    """所有追踪证据服务异常的基类。"""


class ValidationError(TraceChainError):
    """入参不满足合同约束。"""


class NotFoundError(TraceChainError):
    """租户内找不到指定对象。"""


class StateError(TraceChainError):
    """对象当前状态不允许该操作（如未收齐即封存）。"""


class ChainSealedError(StateError):
    """链已封存，原始顺序不可改写。"""


class FrozenError(StateError):
    """任务族已冻结，仅允许读取与解冻。"""


class AccessDeniedError(TraceChainError):
    """角色无权进行该读取（如读取原始证据）。"""
