from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import threading
import time
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, Request, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.database import get_db, SessionLocal
from app.models.user import User
from app.models.session import UserSession
from app.models.audit import AuditLog

TOKEN_TTL_HOURS = int(os.getenv("SENTINELX_SESSION_HOURS", "8"))
MAX_SESSIONS_PER_USER = int(os.getenv("SENTINELX_MAX_SESSIONS", "5"))
IDLE_TIMEOUT_MINUTES = int(os.getenv("SENTINELX_IDLE_MINUTES", "30"))
ROLE_PERMISSIONS = {
    "admin": ["dashboard.read","events.read","alerts.read","alerts.manage","incidents.read","incidents.manage","devices.read","devices.manage","network.discover","rules.read","rules.manage","ai.investigate","iam.read","iam.manage","audit.read","system.read"],
    "employee": ["dashboard.read","events.read","alerts.read","alerts.manage","incidents.read","incidents.manage","devices.read","devices.manage","network.discover","rules.read","ai.investigate","audit.read","system.read"],
    "user": ["dashboard.read","events.read","alerts.read","incidents.read","devices.read","rules.read","ai.investigate","system.read"],
}

_rate_lock = threading.Lock()
_failures: dict[tuple[str, str], list[float]] = {}
LOCKOUT_SECONDS = 60
WINDOW_SECONDS = 300
MAX_FAILURES = 6


def _rate_key(request: Request, username: str) -> tuple[str, str]:
    ip = request.client.host if request.client else "unknown"
    return (ip, username.strip().lower())


def check_login_rate(request: Request, username: str):
    now = time.time()
    key = _rate_key(request, username)
    with _rate_lock:
        values = [x for x in _failures.get(key, []) if now - x <= WINDOW_SECONDS]
        _failures[key] = values
        if len(values) >= MAX_FAILURES:
            retry = max(1, int(LOCKOUT_SECONDS - (now - values[-1])))
            raise HTTPException(status_code=429, detail=f"Too many failed sign-in attempts. Try again in {retry} seconds.")


def record_login_failure(request: Request, username: str):
    key = _rate_key(request, username)
    with _rate_lock:
        values = [x for x in _failures.get(key, []) if time.time() - x <= WINDOW_SECONDS]
        values.append(time.time())
        _failures[key] = values


def clear_login_failures(request: Request, username: str):
    with _rate_lock:
        _failures.pop(_rate_key(request, username), None)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def validate_password_strength(password: str):
    errors = []
    if len(password) < 10: errors.append("at least 10 characters")
    if not any(c.isupper() for c in password): errors.append("an uppercase letter")
    if not any(c.islower() for c in password): errors.append("a lowercase letter")
    if not any(c.isdigit() for c in password): errors.append("a number")
    if not any(not c.isalnum() for c in password): errors.append("a special character")
    return errors


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256": return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def audit(db: Session, user: User | None, action: str, result: str = "success", resource: str | None = None, ip: str | None = None, details: str | None = None):
    db.add(AuditLog(user_id=user.id if user else None, username=user.username if user else None, action=action, result=result, resource=resource, ip_address=ip, details=details))
    db.commit()


def create_session(db: Session, user: User, request: Request) -> str:
    now = datetime.utcnow()
    active = db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None), UserSession.expires_at >= now).order_by(UserSession.created_at.desc()).all()
    if len(active) >= MAX_SESSIONS_PER_USER:
        for old in active[MAX_SESSIONS_PER_USER - 1:]:
            old.revoked_at = now
    raw = secrets.token_urlsafe(48)
    session = UserSession(
        user_id=user.id,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=now + timedelta(hours=TOKEN_TTL_HOURS),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:500],
        last_activity_at=now,
    )
    db.add(session)
    user.last_login = now
    db.commit()
    return raw


def current_user_from_token(db: Session, token: str) -> User | None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.query(UserSession).filter(UserSession.token_hash == token_hash, UserSession.revoked_at.is_(None)).first()
    now = datetime.utcnow()
    if not row or row.expires_at < now:
        return None
    last = row.last_activity_at or row.created_at
    if last and (now - last).total_seconds() > IDLE_TIMEOUT_MINUTES * 60:
        row.revoked_at = now
        db.commit()
        return None
    row.last_activity_at = now
    db.commit()
    return db.query(User).filter(User.id == row.user_id, User.is_active == True).first()

bearer = HTTPBearer(auto_error=False)


def collector_identity(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer), x_agent_key: str | None = Header(default=None, alias="X-Agent-Key"), db: Session = Depends(get_db)):
    expected=os.getenv("SENTINELX_AGENT_KEY", "")
    if expected and x_agent_key and hmac.compare_digest(x_agent_key, expected):
        return {"type":"agent","user":None}
    if credentials:
        user=current_user_from_token(db, credentials.credentials)
        if user: return {"type":"user","user":user}
    raise HTTPException(status_code=401, detail="Collector authentication required")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = current_user_from_token(db, credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return user


def current_session(db: Session, token: str) -> UserSession | None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return db.query(UserSession).filter(UserSession.token_hash == token_hash, UserSession.revoked_at.is_(None)).first()


def require_roles(*roles):
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep


def require_collector_auth(request: Request, x_agent_key: str | None = Header(default=None, alias="X-Agent-Key"), user: User | None = None):
    expected=os.getenv("SENTINELX_AGENT_KEY", "")
    if expected and x_agent_key and hmac.compare_digest(x_agent_key, expected):
        return None
    return None

def require_permission(permission: str):
    def dep(user: User = Depends(get_current_user)) -> User:
        if permission not in ROLE_PERMISSIONS.get(user.role, []):
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        return user
    return dep


def seed_default_users():
    db = SessionLocal()
    try:
        defaults = [
            ("admin", "SentinelX Administrator", "Admin@12345", "admin", "admin@sentinelx.local", "Security Operations"),
            ("employee", "SOC Employee", "Employee@12345", "employee", "employee@sentinelx.local", "Security Operations"),
            ("user", "SentinelX User", "User@12345", "user", "user@sentinelx.local", "General"),
        ]
        for username, display, pwd, role, email, dept in defaults:
            existing = db.query(User).filter(User.username == username).first()
            if not existing:
                db.add(User(username=username, display_name=display, password_hash=hash_password(pwd), role=role, email=email, department=dept, must_change_password=False))
        db.commit()
    finally:
        db.close()
