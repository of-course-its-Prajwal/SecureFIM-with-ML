"""
SecureFIM Pro — Shared Authentication Module

Provides two security primitives used by BOTH the monitoring API (port 8443)
and the Admin Panel (port 8444), so credential storage stays consistent:

  1. Salted password hashing (PBKDF2-HMAC-SHA256, 200k iterations, per-user
     random salt). Replaces the old unsalted SHA-256 scheme. Legacy hashes
     are still accepted on login and transparently upgraded to the salted
     format, so existing accounts keep working.

  2. Token-based session authentication. On login the server issues a random
     bearer token; sensitive admin endpoints require it via the
     `require_admin` decorator (or a blueprint before_request guard). This
     closes the hole where admin routes performed no per-request auth check.

Uses only the Python standard library — no new dependencies.
"""

import functools
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from typing import Optional

from flask import request, jsonify

log = logging.getLogger("securefim.auth")

# ── Credential storage ────────────────────────────────────────────────────

ADMIN_CREDS_FILE = os.getenv("ADMIN_CREDS_FILE", "data/admin_credentials.json")

# ── Password hashing (PBKDF2-HMAC-SHA256) ─────────────────────────────────

_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16

_users_lock = threading.Lock()


def hash_password(password: str) -> str:
    """
    Hash a password with a fresh random salt.
    Returns a self-describing string:  pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def _looks_like_legacy_sha256(stored: str) -> bool:
    """Old scheme was a bare 64-char hex SHA-256 digest with no '$' markers."""
    return isinstance(stored, str) and "$" not in stored and len(stored) == 64


def verify_password(password: str, stored: str) -> tuple[bool, bool]:
    """
    Verify a password against a stored hash.

    Returns (is_valid, needs_upgrade):
      - is_valid       True if the password matches.
      - needs_upgrade  True if the stored hash is in the old unsalted format
                       and should be re-hashed with hash_password().
    """
    if not stored:
        return False, False

    # New salted format
    if stored.startswith("pbkdf2_"):
        try:
            _, iter_s, salt_hex, hash_hex = stored.split("$", 3)
            iterations = int(iter_s)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(dk, expected), False
        except Exception as exc:
            log.warning("Malformed salted hash: %s", exc)
            return False, False

    # Legacy unsalted SHA-256 (transparently upgrade on success)
    if _looks_like_legacy_sha256(stored):
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if hmac.compare_digest(legacy, stored):
            return True, True
        return False, False

    return False, False


# ── User store (shared by both Flask apps) ────────────────────────────────

def load_users() -> dict:
    """Load {username: hashed_password}. Seeds defaults on first run."""
    if os.path.exists(ADMIN_CREDS_FILE):
        try:
            with open(ADMIN_CREDS_FILE) as f:
                return json.load(f)
        except Exception as exc:
            log.error("Could not read %s: %s", ADMIN_CREDS_FILE, exc)

    # First run: seed default accounts (already salted).
    defaults = {
        "admin": hash_password("admin123"),
        "prajwal": hash_password("securefim"),
    }
    save_users(defaults)
    log.warning("Seeded default admin accounts — CHANGE THESE PASSWORDS IMMEDIATELY.")
    return defaults


def save_users(users: dict):
    try:
        os.makedirs(os.path.dirname(ADMIN_CREDS_FILE) or ".", exist_ok=True)
        with open(ADMIN_CREDS_FILE, "w") as f:
            json.dump(users, f, indent=2)
    except Exception as exc:
        log.error("Could not save %s: %s", ADMIN_CREDS_FILE, exc)


def authenticate(users: dict, username: str, password: str) -> bool:
    """
    Check credentials. If the stored hash is legacy, upgrade it in place and
    persist. Thread-safe. Returns True on success.
    """
    stored = users.get(username)
    if not stored:
        # Constant-work path to reduce username enumeration via timing.
        verify_password(password, hash_password("dummy"))
        return False

    ok, needs_upgrade = verify_password(password, stored)
    if ok and needs_upgrade:
        with _users_lock:
            users[username] = hash_password(password)
            save_users(users)
        log.info("Upgraded legacy password hash for user '%s'", username)
    return ok


# ── Token-based session auth ──────────────────────────────────────────────

_TOKEN_TTL_SECONDS = int(os.getenv("ADMIN_TOKEN_TTL", str(8 * 3600)))  # 8 hours
_tokens: dict[str, dict] = {}     # token -> {"username": str, "expires": float}
_tokens_lock = threading.Lock()


def issue_token(username: str) -> str:
    """Create a new session token for a successfully authenticated user."""
    token = secrets.token_urlsafe(32)
    with _tokens_lock:
        _tokens[token] = {"username": username, "expires": time.time() + _TOKEN_TTL_SECONDS}
        _prune_locked()
    return token


def revoke_token(token: str):
    with _tokens_lock:
        _tokens.pop(token, None)


def _prune_locked():
    now = time.time()
    for t in [t for t, v in _tokens.items() if v["expires"] < now]:
        _tokens.pop(t, None)


def validate_token(token: str) -> Optional[str]:
    """Return the username for a valid, unexpired token, else None."""
    if not token:
        return None
    with _tokens_lock:
        rec = _tokens.get(token)
        if not rec:
            return None
        if rec["expires"] < time.time():
            _tokens.pop(token, None)
            return None
        return rec["username"]


def _extract_token() -> str:
    """Read the token from Authorization: Bearer <t> or X-Admin-Token header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.headers.get("X-Admin-Token", "").strip()


def current_user() -> Optional[str]:
    """Username of the caller, if a valid token was supplied."""
    return validate_token(_extract_token())


def require_admin(fn):
    """
    Flask decorator: reject the request with 401 unless a valid session
    token is present. Use on any state-changing / sensitive admin route.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper


def guard_blueprint(public_suffixes: tuple[str, ...]):
    """
    Returns a before_request handler that requires a valid token for every
    route EXCEPT those whose path ends with one of `public_suffixes`
    (e.g. login / password-reset endpoints) and CORS preflight (OPTIONS).
    """
    def _guard():
        if request.method == "OPTIONS":
            return None
        path = request.path.rstrip("/")
        if any(path.endswith(s) for s in public_suffixes):
            return None
        if current_user() is None:
            return jsonify({"error": "Authentication required"}), 401
        return None
    return _guard