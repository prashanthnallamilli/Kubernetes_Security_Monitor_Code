"""Misconfiguration detection rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    resource: str
    namespace: str
    category: str
    remediation_key: str
    details: str = ""


RULES = [
    {
        "id": "MC-001",
        "title": "Container running as root",
        "severity": "HIGH",
        "remediation_key": "run_as_non_root",
        "check": "run_as_root",
    },
    {
        "id": "MC-002",
        "title": "Privileged container",
        "severity": "CRITICAL",
        "remediation_key": "disable_privileged",
        "check": "privileged",
    },
    {
        "id": "MC-003",
        "title": "hostPath volume mounted",
        "severity": "HIGH",
        "remediation_key": "avoid_hostpath",
        "check": "host_path",
    },
    {
        "id": "MC-004",
        "title": "hostNetwork enabled",
        "severity": "HIGH",
        "remediation_key": "disable_hostnetwork",
        "check": "host_network",
    },
]


def _sc(container: Dict[str, Any]) -> Dict[str, Any]:
    return container.get("security_context") or container.get("securityContext") or {}


def _pod_sc(pod: Dict[str, Any]) -> Dict[str, Any]:
    spec = pod.get("spec") or {}
    return spec.get("security_context") or spec.get("securityContext") or {}


def _is_root(container: Dict[str, Any], pod: Dict[str, Any]) -> bool:
    csc = _sc(container)
    psc = _pod_sc(pod)
    if csc.get("run_as_non_root") or csc.get("runAsNonRoot"):
        return False
    if psc.get("run_as_non_root") or psc.get("runAsNonRoot"):
        return False
    run_as = csc.get("run_as_user", csc.get("runAsUser", psc.get("run_as_user", psc.get("runAsUser"))))
    if run_as is None:
        return True  # default often root
    return int(run_as) == 0


def detect_misconfigurations(pods: List[Dict[str, Any]]) -> List[Finding]:
    """Evaluate pods against the misconfiguration catalogue."""
    findings: List[Finding] = []

    for pod in pods:
        meta = pod.get("metadata") or {}
        name = meta.get("name", "unknown")
        namespace = meta.get("namespace", "default")
        spec = pod.get("spec") or {}
        containers = spec.get("containers") or []

        if spec.get("host_network") or spec.get("hostNetwork"):
            findings.append(
                Finding(
                    rule_id="MC-004",
                    title="hostNetwork enabled",
                    severity="HIGH",
                    resource=name,
                    namespace=namespace,
                    category="misconfiguration",
                    remediation_key="disable_hostnetwork",
                    details="Pod uses hostNetwork=true",
                )
            )

        for vol in spec.get("volumes") or []:
            if vol.get("host_path") or vol.get("hostPath"):
                findings.append(
                    Finding(
                        rule_id="MC-003",
                        title="hostPath volume mounted",
                        severity="HIGH",
                        resource=name,
                        namespace=namespace,
                        category="misconfiguration",
                        remediation_key="avoid_hostpath",
                        details=f"Volume: {vol.get('name')}",
                    )
                )

        for container in containers:
            cname = container.get("name", "container")
            if _sc(container).get("privileged") is True:
                findings.append(
                    Finding(
                        rule_id="MC-002",
                        title="Privileged container",
                        severity="CRITICAL",
                        resource=f"{name}/{cname}",
                        namespace=namespace,
                        category="misconfiguration",
                        remediation_key="disable_privileged",
                    )
                )
            if _is_root(container, pod):
                findings.append(
                    Finding(
                        rule_id="MC-001",
                        title="Container running as root",
                        severity="HIGH",
                        resource=f"{name}/{cname}",
                        namespace=namespace,
                        category="misconfiguration",
                        remediation_key="run_as_non_root",
                    )
                )

    return findings
