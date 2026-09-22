import hashlib
import hmac
import os
import re
import time


class AuthSystem:
    def __init__(self, max_attempts: int = 5, lockout_seconds: float = 15 * 60):
        self.users = {}      # username -> (salt_hex, hash_hex)
        self.attempts = {}   # username -> {"count": int, "locked_until": float | None}
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
        salt = salt or os.urandom(16)
        # scrypt params chosen to match Node's crypto.scryptSync defaults closely enough for a demo
        derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
        return salt.hex(), derived.hex()

    def register_user(self, username: str, password: str) -> None:
        salt_hex, hash_hex = self._hash_password(password)
        self.users[username] = (salt_hex, hash_hex)

    # Whitelist validation: only alnum/underscore/dot, 3-30 chars.
    # This is what makes SQL-injection-style payloads harmless here —
    # they never reach a query because they never pass this check.
    def _is_valid_username(self, username) -> bool:
        return isinstance(username, str) and bool(re.fullmatch(r"[a-zA-Z0-9_.]{3,30}", username))

    def login(self, username: str, password: str) -> dict:
        if not username or not password or not username.strip() or not password.strip():
            return {"success": False, "error": "Username and password are required"}

        if not self._is_valid_username(username):
            # Generic message on purpose — never say *why* it was rejected.
            return {"success": False, "error": "Invalid credentials"}

        lock = self.attempts.get(username)
        if lock and lock.get("locked_until") and lock["locked_until"] > time.time():
            return {"success": False, "error": "Account locked. Try again later."}

        record = self.users.get(username)
        if not record:
            self._register_failure(username)
            return {"success": False, "error": "Invalid credentials"}

        salt_hex, stored_hash_hex = record
        attempt_hash = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1, dklen=64
        ).hex()

        if not hmac.compare_digest(attempt_hash, stored_hash_hex):
            self._register_failure(username)
            return {"success": False, "error": "Invalid credentials"}

        self.attempts.pop(username, None)  # reset counter on success
        return {"success": True}

    def _register_failure(self, username: str) -> None:
        current = self.attempts.get(username, {"count": 0, "locked_until": None})
        current["count"] += 1
        if current["count"] >= self.max_attempts:
            current["locked_until"] = time.time() + self.lockout_seconds
        self.attempts[username] = current