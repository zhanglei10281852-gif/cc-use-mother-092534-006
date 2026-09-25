"""按角色生成证据投影。

同一份原始证据，对不同角色呈现不同字段形态，但投影信封始终携带
*原始证据摘要*（``original_digest``）——投影只改变可见性，不改变可验证性
（策略 P-06-04：不同角色投影必须对应同一原始证据摘要）。

策略文件：``domain/projection_policy.json``，字段分类规则来自键名分类器
与内容标记（如 ``Bearer ``、``-----BEGIN``），无需各上报方配合标注。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "domain" / "projection_policy.json"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SPLIT_RE = re.compile(r"[_\-.\s]")


@dataclass(frozen=True, slots=True)
class Redaction:
    path: str
    classifier: str
    action: str  # masked / tagged / dropped
    length: int


@dataclass(frozen=True, slots=True)
class Projection:
    original_digest: str
    fragment_id: str
    role: str
    policy_version: str
    content: Any
    redactions: tuple[Redaction, ...]


@dataclass(frozen=True, slots=True)
class _RolePolicy:
    name: str
    allow: frozenset[str]
    mask: frozenset[str]
    redact: frozenset[str]
    drop_cross_tenant: bool


class ProjectionEngine:
    """加载投影策略并把原始载荷变换为角色投影。"""

    def __init__(self, policy_path: str | Path | None = None) -> None:
        path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        policy = json.loads(path.read_text(encoding="utf-8"))
        self.version: str = policy["version"]
        self._key_index: dict[str, str] = {}
        for classifier, keys in policy["field_classifiers"].items():
            for key in keys:
                self._key_index[key.lower()] = classifier
        self._markers: dict[str, tuple[str, ...]] = {
            classifier: tuple(markers)
            for classifier, markers in policy.get("content_markers", {}).items()
        }
        self._roles: dict[str, _RolePolicy] = {}
        for name, spec in policy["roles"].items():
            self._roles[name] = _RolePolicy(
                name=name,
                allow=frozenset(spec.get("allow_classified", [])),
                mask=frozenset(spec.get("mask_classified", [])),
                redact=frozenset(spec.get("redact_classified", [])),
                drop_cross_tenant=bool(spec.get("drop_cross_tenant", True)),
            )
        self.default_role: str = policy.get("default_role", "auditor")

    def roles(self) -> tuple[str, ...]:
        return tuple(self._roles)

    # -- 分类 -------------------------------------------------------------

    def _classify_key(self, key: str) -> str | None:
        normalized = key.lower()
        if normalized in self._key_index:
            return self._key_index[normalized]
        tokens = set(_SPLIT_RE.split(normalized))
        for token in tokens:
            if token in self._key_index:
                return self._key_index[token]
        return None

    def _classify_value(self, value: str) -> str | None:
        for classifier, markers in self._markers.items():
            if any(marker in value for marker in markers):
                if classifier == "pii" and not _EMAIL_RE.match(value.strip()):
                    continue
                return classifier
        return None

    # -- 投影 -------------------------------------------------------------

    def project(
        self,
        payload: Any,
        *,
        original_digest: str,
        fragment_id: str,
        role: str,
        viewer_tenant: str,
        owner_tenant: str,
    ) -> Projection:
        if role not in self._roles:
            raise KeyError(f"未知角色：{role}")
        rp = self._roles[role]
        redactions: list[Redaction] = []

        def visit(node: Any, path: str) -> Any:
            if isinstance(node, dict):
                result: dict[str, Any] = {}
                for key, value in node.items():
                    child_path = f"{path}.{key}" if path else key
                    classifier = self._classify_key(str(key))
                    if classifier is None and isinstance(value, str):
                        classifier = self._classify_value(value)
                    if classifier == "cross_tenant":
                        other = str(value)
                        if other != viewer_tenant:
                            if rp.drop_cross_tenant:
                                redactions.append(
                                    Redaction(child_path, "cross_tenant", "dropped", len(other))
                                )
                                continue
                            redactions.append(
                                Redaction(child_path, "cross_tenant", "tagged", len(other))
                            )
                            result[key] = f"⟨cross-tenant:{other}⟩"
                            continue
                    if classifier in ("credential", "pii"):
                        if classifier in rp.redact:
                            redactions.append(
                                Redaction(child_path, classifier, "tagged", _value_len(value))
                            )
                            result[key] = f"⟨redacted:{classifier}⟩"
                            continue
                        if classifier in rp.mask:
                            projected = self._mask_value(classifier, value)
                            redactions.append(
                                Redaction(child_path, classifier, "masked", _value_len(value))
                            )
                            result[key] = projected
                            continue
                        if classifier not in rp.allow:
                            # 默认关闭：策略未显式放行则按标记剔除，不返回原文。
                            redactions.append(
                                Redaction(child_path, classifier, "tagged", _value_len(value))
                            )
                            result[key] = f"⟨redacted:{classifier}⟩"
                            continue
                    result[key] = visit(value, child_path)
                return result
            if isinstance(node, list):
                return [visit(item, f"{path}[{i}]") for i, item in enumerate(node)]
            return node

        # 跨租户整条访问：只有显式允许跨租户的角色可读到其他租户证据，
        # 字段级 cross_tenant 标记仍按上面的规则处理。
        if viewer_tenant != owner_tenant and rp.drop_cross_tenant:
            content: Any = None
            redactions.append(Redaction("$", "cross_tenant", "dropped", _value_len(payload)))
        else:
            content = visit(payload, "")
        return Projection(
            original_digest=original_digest,
            fragment_id=fragment_id,
            role=rp.name,
            policy_version=self.version,
            content=content,
            redactions=tuple(redactions),
        )

    @staticmethod
    def _mask_value(classifier: str, value: Any) -> Any:
        """掩码：保留少量结构信息（邮箱域、长度），不泄露原文主体。"""
        if isinstance(value, str):
            stripped = value.strip()
            if "@" in stripped and _EMAIL_RE.match(stripped):
                local, _, domain = stripped.partition("@")
                head = local[0] if local else "?"
                return f"{head}***@{domain}"
            if len(value) <= 4:
                return "***"
            return f"{value[0]}***{value[-1]}(len={len(value)})"
        return f"⟨masked:{classifier}⟩"


def _value_len(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))
