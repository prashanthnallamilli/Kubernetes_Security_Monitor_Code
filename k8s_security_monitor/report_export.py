"""Downloadable Markdown security report export."""

from __future__ import annotations

from datetime import datetime
from typing import List

from .scoring import PrioritisedItem


def export_markdown_report(
    score: int,
    level: str,
    items: List[PrioritisedItem],
    path: str = "security_report.md",
) -> str:
    lines = [
        "# Kubernetes Security Report",
        "",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        f"Security score: **{score}/100** ({level})",
        "",
        "## Findings",
        "",
        "| Priority | Source | Title | Resource | Severity |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item.priority} | {item.source} | {item.title} | "
            f"{item.resource} | {item.severity} |"
        )

    lines.extend(
        [
            "",
            "## Remediation notes",
            "- Prefer non-root containers (`runAsNonRoot: true`).",
            "- Remove privileged mode unless strictly required.",
            "- Replace cluster-admin bindings with least-privilege roles.",
            "- Rebuild images from patched bases for CRITICAL/HIGH CVEs.",
            "",
        ]
    )
    content = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
