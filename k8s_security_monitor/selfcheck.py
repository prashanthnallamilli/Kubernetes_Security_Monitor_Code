"""Offline unit checks for misconfig + scoring (no live cluster required)."""

from k8s_security_monitor.misconfig import detect_misconfigurations
from k8s_security_monitor.scoring import build_priority_list, compute_security_score


def sample_privileged_pod():
    return {
        "metadata": {"name": "insecure-root-pod", "namespace": "default"},
        "spec": {
            "hostNetwork": True,
            "containers": [
                {
                    "name": "web",
                    "image": "nginx:1.21",
                    "securityContext": {"privileged": True, "runAsUser": 0},
                }
            ],
        },
    }


if __name__ == "__main__":
    findings = detect_misconfigurations([sample_privileged_pod()])
    items = build_priority_list(findings, [])
    score, level = compute_security_score(items)
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f" - {f.rule_id}: {f.title}")
    print(f"Score: {score} ({level})")
    assert any(f.rule_id == "MC-002" for f in findings)
    print("Self-check passed.")
