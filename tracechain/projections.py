"""按角色生成的敏感投影。

投影规则来自 ``domain/projection_policies.json``：

- ``reveal``：原值保留；
- ``mask``：替换为固定标记 ``"***REDACTED***"``，字段仍可见；
- ``drop``：整个字段移除。

投影在字段标注层面工作：片段内容若为对象，可通过 ``_security_labels``
（或调用参数 ``labels``）声明字段敏感度，键为 ``credentials`` /
``personal_data`` / ``tenant_content``。标注本身不属于业务内容，
不参与内容摘要。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .crypto import canonical, sha256_hex
from .errors import ValidationError

REDACTION_MARKER = "***REDACTED***"
LABELS_KEY = "_security_labels"
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "domain" / "projection_policies.json"


class ProjectionPolicy:
    def __init__(self, spec: dict[str, Any]):
        self.version: str = spec.get("policy_version", "unknown")
        self.labels: set[str] = set(spec.get("labels", []))
        self.roles: dict[str, dict[str, str]] = spec.get("roles", {})
        self.default_treatment: str = spec.get("unknown_role_default", "drop")
        treatments = set(spec.get("treatments", [])) | {"reveal", "mask", "drop"}
        for role, mapping in self.roles.items():
            unknown = set(mapping) - self.labels
            if unknown:
                raise ValidationError(f"角色 {role} 配置了未知敏感度标签：{sorted(unknown)}")
            bad = {v for v in mapping.values() if v not in treatments}
            if bad:
                raise ValidationError(f"角色 {role} 存在未知脱敏处理：{sorted(bad)}")

    def treatment(self, role: str, label: str) -> str:
        mapping = self.roles.get(role)
        if mapping is None:
            return self.default_treatment
        return mapping.get(label, "reveal")

    def visible_labels(self, role: str) -> set[str]:
        """该角色至少能看到字段结构（mask 或 reveal）的标签集合。"""
        return {label for label in self.labels if self.treatment(role, label) != "drop"}


def load_projection_policy(path: str | Path | None = None) -> ProjectionPolicy:
    target = Path(path) if path is not None else DEFAULT_POLICY_PATH
    return ProjectionPolicy(json.loads(target.read_text(encoding="utf-8")))


def _field_labels(field: str, labels_map: dict[str, list[str]]) -> list[str]:
    return labels_map.get(field, [])


def project_value(
    value: Any,
    role: str,
    policy: ProjectionPolicy,
    labels_map: dict[str, list[str]],
    _prefix: str = "",
) -> Any:
    """递归投影。``_prefix`` 是点分字段路径，用于嵌套对象的标签查找。"""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            path = f"{_prefix}.{key}" if _prefix else key
            labels = _field_labels(path, labels_map) or _field_labels(key, labels_map)
            ordered = [label for label in policy.labels if label in labels]
            if ordered:
                treatment = policy.treatment(role, ordered[0])
                if treatment == "drop":
                    continue
                if treatment == "mask":
                    result[key] = REDACTION_MARKER
                    continue
            result[key] = project_value(item, role, policy, labels_map, path)
        return result
    if isinstance(value, list):
        return [project_value(item, role, policy, labels_map, _prefix) for item in value]
    return value


def extract_labels(content: Any, inline_labels: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """合并内联 ``_security_labels`` 与调用方显式标注。"""
    labels: dict[str, list[str]] = {}
    if isinstance(content, dict) and isinstance(content.get(LABELS_KEY), dict):
        for field, tagged in content[LABELS_KEY].items():
            if isinstance(tagged, list):
                labels[field] = list(tagged)
    if inline_labels:
        for field, tagged in inline_labels.items():
            labels.setdefault(field, [])
            for label in tagged:
                if label not in labels[field]:
                    labels[field].append(label)
    return labels


def strip_label_annotations(content: Any) -> Any:
    """投影前移除标注元数据，标注永不进入业务投影。"""
    if isinstance(content, dict):
        return {k: strip_label_annotations(v) for k, v in content.items() if k != LABELS_KEY}
    if isinstance(content, list):
        return [strip_label_annotations(v) for v in content]
    return content


def make_projection(
    content: Any,
    role: str,
    policy: ProjectionPolicy,
    *,
    labels: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """生成一份投影结果。

    返回结构固定包含 ``role``、``policy_version``、``content``、
    ``raw_content_hash``（原始证据摘要）与 ``projection_hash``，
    使不同角色的投影可以被证明对应同一份原始证据。
    """
    labels_map = extract_labels(content, labels)
    clean = strip_label_annotations(content)
    projected = project_value(clean, role, policy, labels_map)
    raw_hash = sha256_hex(clean)
    projection_body = {
        "role": role,
        "policy_version": policy.version,
        "content": projected,
        "raw_content_hash": raw_hash,
    }
    return {**projection_body, "projection_hash": sha256_hex(projection_body)}


def projection_binding(raw_content: Any, roles: Iterable[str], policy: ProjectionPolicy) -> dict[str, str]:
    """角色 -> 投影摘要，全部绑定到同一个原始内容摘要（验证用辅助）。"""
    clean = strip_label_annotations(raw_content)
    raw_hash = sha256_hex(clean)
    bindings: dict[str, str] = {}
    for role in roles:
        projected = make_projection(raw_content, role, policy)
        if projected["raw_content_hash"] != raw_hash:
            raise AssertionError("投影原始摘要不一致")
        bindings[role] = projected["projection_hash"]
    return bindings


def canonical_projection_bytes(projection: dict[str, Any]) -> bytes:
    """投影的规范化字节，供导出等场景复核。"""
    return canonical(projection)
