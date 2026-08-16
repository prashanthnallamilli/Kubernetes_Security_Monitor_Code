"""Trivy image vulnerability scanning integration."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class ImageCVE:
    image: str
    vulnerability_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: str


def _trivy_available() -> bool:
    return shutil.which("trivy") is not None


def scan_image(image: str) -> List[ImageCVE]:
    """
    Scan a container image with Trivy (JSON output).
    Returns an empty list if Trivy is not installed (offline demo mode).
    """
    if not _trivy_available():
        return []

    cmd = [
        "trivy",
        "image",
        "--quiet",
        "--format",
        "json",
        "--severity",
        "CRITICAL,HIGH,MEDIUM,LOW",
        image,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        # Trivy returns 1 when vulnerabilities are found depending on flags
        raise RuntimeError(f"Trivy failed for {image}: {proc.stderr}")

    data = json.loads(proc.stdout or "{}")
    results: List[ImageCVE] = []
    for target in data.get("Results") or []:
        for vuln in target.get("Vulnerabilities") or []:
            results.append(
                ImageCVE(
                    image=image,
                    vulnerability_id=vuln.get("VulnerabilityID", ""),
                    severity=(vuln.get("Severity") or "UNKNOWN").upper(),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", "") or "",
                )
            )
    return results


def scan_images(images: List[str]) -> List[ImageCVE]:
    """Scan unique image references once per cycle."""
    unique = list(dict.fromkeys(images))
    all_cves: List[ImageCVE] = []
    for image in unique:
        all_cves.extend(scan_image(image))
    return all_cves
