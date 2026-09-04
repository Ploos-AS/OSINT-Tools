"""Dependency-free local authentication, sessions and RBAC helpers."""
from __future__ import annotations
import base64, hashlib, hmac, secrets, time
_failures: dict[str, list[float]] = {}

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
def hash_password(password: str) -> str:
    salt=secrets.token_bytes(16); return "scrypt$1$"+base64.urlsafe_b64encode(salt).decode()+"$"+hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1).hex()
def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme,ver,salt_b,digest=encoded.split("$",3); salt=base64.urlsafe_b64decode(salt_b.encode()); got=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1).hex(); return scheme=="scrypt" and ver=="1" and hmac.compare_digest(got,digest)
    except Exception: return False
def token_hash(token: str) -> str: return hashlib.sha256(token.encode()).hexdigest()
def new_session(): return secrets.token_urlsafe(32), secrets.token_urlsafe(32)
def allowed(role: str, required: str) -> bool: return ROLES.get(role,0) >= ROLES.get(required,99)
def login_limited(key: str, window: int = 60, limit: int = 10) -> bool:
    now=time.monotonic(); values=[v for v in _failures.get(key,[]) if now-v < window]; _failures[key]=values; return len(values) >= limit
def note_login_failure(key: str) -> None: _failures.setdefault(key,[]).append(time.monotonic())
