"""领域错误类型。

所有错误都是显式的状态拒绝，服务层不会通过静默回退来掩盖非法操作
（例如自动选择分叉链、把未收齐的链标记为完整）。
"""
from __future__ import annotations


class TraceChainError(Exception):
    """全部领域错误的基类。"""


class DuplicateReport(TraceChainError):
    """重复上报：片段/委派已存在，仅用于确认已有记录。

    :ivar existing_id: 已存在记录的标识。
    :ivar digest: 已存在记录的内容摘要，供上报方比对。
    """

    def __init__(self, kind: str, existing_id: str, digest: str) -> None:
        super().__init__(f"{kind}已存在，仅确认记录：{existing_id}")
        self.kind = kind
        self.existing_id = existing_id
        self.digest = digest


class ConflictingReport(TraceChainError):
    """同来源同序号但内容摘要不同——分叉必须进入裁决，不能当作重复。"""

    def __init__(self, source: str, seq: int, existing_digest: str, incoming_digest: str) -> None:
        super().__init__(
            f"来源 {source} 序号 {seq} 出现内容冲突，已进入分叉裁决"
        )
        self.source = source
        self.seq = seq
        self.existing_digest = existing_digest
        self.incoming_digest = incoming_digest
        self.result = None  # 由服务层填充 FragmentReportResult


class ChainNotComplete(TraceChainError):
    """链未收齐（有缺口、数量不足或存在未决分叉），禁止封存。"""


class UnresolvedFork(TraceChainError):
    """存在未裁决的分叉，禁止封存/出具完整证明。"""


class ChainSealed(TraceChainError):
    """链已封存，原始顺序不可改写。"""


class FamilyFrozen(TraceChainError):
    """任务族已冻结，拒绝接收新片段。"""


class AdjudicationError(TraceChainError):
    """裁决请求非法（裁决对象不存在/已裁决/选择项无效）。"""


class AccessDenied(TraceChainError):
    """角色无权读取该证据或字段。"""


class DisavowedContent(TraceChainError):
    """上报内容与已被裁决否决的候选摘要完全相同，禁止重新进入规范链。"""

    def __init__(self, source: str, seq: int, fork_id: str) -> None:
        super().__init__(
            f"来源 {source} 序号 {seq} 的内容已被分叉案 {fork_id} 裁决否决，"
            "不能作为新片段重新接收"
        )
        self.source = source
        self.seq = seq
        self.fork_id = fork_id
