"""子智能体追踪证据链服务。

对外主要入口：

- :class:`tracechain.service.TraceEvidenceService`：领域服务（用例编排）。
- :class:`tracechain.store.EventStore`：SQLite 事件存储与状态重放。
- :class:`tracechain.projection.ProjectionEngine`：按角色生成证据投影。
"""

__all__ = ["service", "store", "projection"]
