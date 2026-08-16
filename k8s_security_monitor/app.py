"""Flask dashboard entry point for the monitoring platform."""

from __future__ import annotations

import os
from functools import wraps

from flask import Flask, redirect, render_template_string, request, session, url_for

from .auth import authenticate, create_admin
from .collector import KubernetesCollector
from .misconfig import detect_misconfigurations
from .rbac_analyser import analyse_rbac
from .report_export import export_markdown_report
from .scoring import build_priority_list, compute_security_score
from .trivy_scanner import scan_images

app = Flask(__name__)
app.secret_key = os.getenv("K8S_MON_SECRET", "dev-only-change-me")

# Cookie sessions cannot hold a full cluster scan (browser limit ~4KB).
# Keep the latest scan in memory, keyed by logged-in user.
SCAN_STORE: dict = {}

ADMIN = create_admin(
    os.getenv("K8S_MON_USER", "admin"),
    os.getenv("K8S_MON_PASS", "ChangeMe123!"),
)

DASHBOARD_HTML = """
<!doctype html>
<title>K8s Security Monitor</title>
<style>
 body{font-family:Arial,sans-serif;margin:2rem;background:#f7f9fc;color:#222}
 .card{background:#fff;padding:1rem 1.25rem;border-radius:8px;box-shadow:0 1px 4px #0001;margin-bottom:1rem}
 .p1{color:#b00020;font-weight:bold}.score{font-size:2rem}
 table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:.5rem;text-align:left}
</style>
<div class="card">
  <h1>Kubernetes Security Monitor</h1>
  <p>Logged in as {{ user }} | <a href="{{ url_for('logout') }}">Logout</a></p>
  <p class="score">Score: {{ score }} / 100 ({{ level }})</p>
  <p>P1 alerts: <span class="p1">{{ p1_count }}</span></p>
  <form method="post" action="{{ url_for('scan') }}"><button type="submit">Run scan</button></form>
</div>
<div class="card">
  <h2>Prioritised findings</h2>
  <table>
    <tr><th>Priority</th><th>Source</th><th>Title</th><th>Resource</th><th>Severity</th></tr>
    {% for i in items %}
    <tr><td>{{ i.priority }}</td><td>{{ i.source }}</td><td>{{ i.title }}</td>
        <td>{{ i.resource }}</td><td>{{ i.severity }}</td></tr>
    {% endfor %}
  </table>
</div>
"""

LOGIN_HTML = """
<!doctype html>
<title>Login</title>
<form method="post" style="margin:3rem auto;width:320px;font-family:Arial">
  <h2>Admin login</h2>
  <p><input name="username" placeholder="Username" required></p>
  <p><input name="password" type="password" placeholder="Password" required></p>
  <button type="submit">Sign in</button>
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</form>
"""


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if authenticate(ADMIN, request.form["username"], request.form["password"]):
            session["user"] = request.form["username"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    stored = SCAN_STORE.get(session.get("user"), {})
    items = stored.get("items") or []
    score = stored.get("score", "—")
    level = stored.get("level", "Unknown")
    p1_count = sum(1 for i in items if i.get("priority") == "P1")
    return render_template_string(
        DASHBOARD_HTML,
        user=session["user"],
        items=items,
        score=score,
        level=level,
        p1_count=p1_count,
    )


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    collector = KubernetesCollector()
    snap = collector.collect()

    findings = detect_misconfigurations(snap.pods)
    findings += analyse_rbac(
        snap.roles,
        snap.cluster_roles,
        snap.role_bindings,
        snap.cluster_role_bindings,
    )
    cves = scan_images(snap.images)
    items = build_priority_list(findings, cves)
    score, level = compute_security_score(items)

    compact = [i.__dict__ for i in items[:80]]
    SCAN_STORE[session["user"]] = {
        "items": compact,
        "score": score,
        "level": level,
    }
    export_markdown_report(score, level, items, path="security_report.md")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
