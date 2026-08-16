"""RBAC over-permission analysis."""

from __future__ import annotations

from typing import Any, Dict, List

from .misconfig import Finding


def _rules(role: Dict[str, Any]) -> List[Dict[str, Any]]:
    return role.get("rules") or []


def _is_dangerous_rule(rule: Dict[str, Any]) -> bool:
    verbs = set(rule.get("verbs") or [])
    resources = set(rule.get("resources") or [])
    if "*" in verbs:
        return True
    if "secrets" in resources and ({"get", "list", "watch"} & verbs or "*" in verbs):
        return True
    if "pods/exec" in resources:
        return True
    return False


def analyse_rbac(
    roles: List[Dict[str, Any]],
    cluster_roles: List[Dict[str, Any]],
    role_bindings: List[Dict[str, Any]],
    cluster_role_bindings: List[Dict[str, Any]],
) -> List[Finding]:
    """Flag overly permissive RBAC roles and bindings."""
    findings: List[Finding] = []

    def check_role(role: Dict[str, Any], kind: str) -> None:
        meta = role.get("metadata") or {}
        name = meta.get("name", "unknown")
        namespace = meta.get("namespace", "cluster-scoped")
        for rule in _rules(role):
            if _is_dangerous_rule(rule):
                findings.append(
                    Finding(
                        rule_id="RBAC-001",
                        title=f"Over-permissive {kind}",
                        severity="CRITICAL" if "*" in (rule.get("verbs") or []) else "HIGH",
                        resource=name,
                        namespace=namespace,
                        category="rbac",
                        remediation_key="least_privilege_rbac",
                        details=str(rule),
                    )
                )

    for role in roles:
        check_role(role, "Role")
    for role in cluster_roles:
        check_role(role, "ClusterRole")

    for binding in cluster_role_bindings:
        meta = binding.get("metadata") or {}
        ref = (binding.get("role_ref") or binding.get("roleRef") or {}).get("name", "")
        if ref == "cluster-admin":
            findings.append(
                Finding(
                    rule_id="RBAC-002",
                    title="cluster-admin ClusterRoleBinding",
                    severity="CRITICAL",
                    resource=meta.get("name", "unknown"),
                    namespace="cluster-scoped",
                    category="rbac",
                    remediation_key="avoid_cluster_admin",
                    details="Binding grants cluster-admin",
                )
            )

    return findings
