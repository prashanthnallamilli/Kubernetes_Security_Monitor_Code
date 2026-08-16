"""Administrator authentication for the monitoring dashboard."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Optional


@dataclass
class AdminUser:
    username: str
    password_hash: str
    salt: str


def _hash_password(password: str, salt: str) -> str:
    """Create a salted SHA-256 hash for stored credentials."""
    payload = f"{salt}:{password}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_admin(username: str, password: str) -> AdminUser:
    """Register an administrator account (lab / local use)."""
    salt = secrets.token_hex(16)
    return AdminUser(
        username=username,
        password_hash=_hash_password(password, salt),
        salt=salt,
    )


def authenticate(user: AdminUser, username: str, password: str) -> bool:
    """Return True when username and password match the stored admin."""
    if username != user.username:
        return False
    candidate = _hash_password(password, user.salt)
    return hmac.compare_digest(candidate, user.password_hash)


def load_admin_from_env() -> Optional[AdminUser]:
    """
    Load credentials from environment variables.
    Expected:
      K8S_MON_USER, K8S_MON_PASS
    """
    username = os.getenv("K8S_MON_USER")
    password = os.getenv("K8S_MON_PASS")
    if not username or not password:
        return None
    return create_admin(username, password)


if __name__ == "__main__":
    demo = create_admin("admin", "ChangeMe123!")
    print("Auth OK:", authenticate(demo, "admin", "ChangeMe123!"))
    print("Auth FAIL:", authenticate(demo, "admin", "wrong"))
