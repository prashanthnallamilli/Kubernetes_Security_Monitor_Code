"""P1–P4 prioritisation and overall security score."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .misconfig import Finding
from .trivy_scanner import ImageCVE


PRIORITY_WEIGHT = {"P1": 25, "P2": 10, "P3": 4, "P4": 1}


@dataclass
class PrioritisedItem:
    priority: str
    source: str
    title: str
    resource: str
    severity: str


def priority_for_finding(finding: Finding, exposed: bool = False) -> str:
    sev = finding.severity.upper()
    if sev == "CRITICAL" and (exposed or finding.category == "rbac"):
        return "P1"
    if sev == "CRITICAL":
        return "P2"
    if sev == "HIGH" and exposed:
        return "P1"
    if sev == "HIGH":
        return "P2"
    if sev == "MEDIUM":
        return "P3"
    return "P4"


def priority_for_cve(cve: ImageCVE, exposed: bool = False) -> str:
    sev = cve.severity.upper()
    if sev == "CRITICAL" and exposed:
        return "P1"
    if sev == "CRITICAL":
        return "P2"
    if sev == "HIGH" and exposed:
        return "P2"
    if sev == "HIGH":
        return "P3"
    if sev == "MEDIUM":
        return "P3"
    return "P4"


def build_priority_list(
    findings: List[Finding],
    cves: List[ImageCVE],
    exposed_resources: set | None = None,
) -> List[PrioritisedItem]:
    exposed_resources = exposed_resources or set()
    items: List[PrioritisedItem] = []

    for f in findings:
        exposed = f.resource.split("/")[0] in exposed_resources
        items.append(
            PrioritisedItem(
                priority=priority_for_finding(f, exposed),
                source=f.category,
                title=f.title,
                resource=f.resource,
                severity=f.severity,
            )
        )

    for cve in cves:
        items.append(
            PrioritisedItem(
                priority=priority_for_cve(cve, exposed=False),
                source="image",
                title=f"{cve.vulnerability_id} ({cve.package})",
                resource=cve.image,
                severity=cve.severity,
            )
        )

    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    items.sort(key=lambda x: order.get(x.priority, 9))
    return items


def compute_security_score(items: List[PrioritisedItem]) -> Tuple[int, str]:
    """
    Start at 100 and subtract weighted penalties.
    Returns (score 0-100, risk level).
    """
    score = 100
    for item in items:
        score -= PRIORITY_WEIGHT.get(item.priority, 1)
    score = max(0, min(100, score))

    if score >= 85:
        level = "Low"
    elif score >= 65:
        level = "Medium"
    elif score >= 40:
        level = "High"
    else:
        level = "Critical"
    return score, level
