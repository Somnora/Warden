"""Enterprise operator identity and ordered authorization roles.

Live identities originate from a verified Google OIDC token. Roles are then
resolved from a deployment-owned binding map (or verified custom claims), not
from caller-controlled HTTP headers. Local mock mode deliberately supports a
header to keep the desktop demo usable.
"""

from __future__ import annotations

import json
import os
from enum import Enum
from typing import Any, Iterable


class EnterpriseRole(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    APPROVER = "approver"
    SENIOR_APPROVER = "senior_approver"
    ADMINISTRATOR = "administrator"


_RANK = {
    EnterpriseRole.VIEWER.value: 0,
    EnterpriseRole.OPERATOR.value: 1,
    EnterpriseRole.APPROVER.value: 2,
    EnterpriseRole.SENIOR_APPROVER.value: 3,
    EnterpriseRole.ADMINISTRATOR.value: 4,
}


def normalize_roles(values: Iterable[str]) -> tuple[str, ...]:
    raw = {str(value).strip().lower() for value in values if str(value).strip()}
    invalid = [role for role in raw if role not in _RANK]
    if invalid:
        raise ValueError(f"unknown enterprise role(s): {', '.join(invalid)}")
    roles = tuple(sorted(raw, key=_RANK.__getitem__))
    return roles or (EnterpriseRole.VIEWER.value,)


def effective_role(roles: Iterable[str]) -> str:
    normalized = normalize_roles(roles)
    return max(normalized, key=_RANK.__getitem__)


def role_satisfies(roles: Iterable[str] | str, required: str) -> bool:
    required_value = required.strip().lower()
    if required_value not in _RANK:
        raise ValueError(f"unknown required enterprise role: {required}")
    available = (roles,) if isinstance(roles, str) else roles
    return _RANK[effective_role(available)] >= _RANK[required_value]


def local_roles(header_value: str | None) -> tuple[str, ...]:
    """Local-only role selection; production never calls this helper."""
    return normalize_roles((header_value or EnterpriseRole.ADMINISTRATOR.value).split(","))


def live_roles(principal: str, claims: dict[str, Any]) -> tuple[str, ...]:
    """Resolve roles only from deployment configuration or verified token claims."""
    bindings_raw = os.environ.get("WARDEN_ROLE_BINDINGS", "{}")
    try:
        bindings = json.loads(bindings_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("WARDEN_ROLE_BINDINGS must be valid JSON") from exc
    if not isinstance(bindings, dict):
        raise ValueError("WARDEN_ROLE_BINDINGS must be a principal-to-roles mapping")
    configured = bindings.get(principal)
    if configured is not None:
        if not isinstance(configured, list) or not all(isinstance(role, str) for role in configured):
            raise ValueError("each configured principal role binding must be a string list")
        return normalize_roles(configured)
    claimed = claims.get("warden_roles") or claims.get("roles")
    if isinstance(claimed, list) and all(isinstance(role, str) for role in claimed):
        return normalize_roles(claimed)
    # Least privilege: a verified but unbound identity can inspect, but may
    # not request actions or make governance decisions.
    return (EnterpriseRole.VIEWER.value,)
