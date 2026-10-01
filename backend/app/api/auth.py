from datetime import datetime
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
from app.models.session import UserSession
from app.models.audit import AuditLog
from app.services.auth import ROLE_PERMISSIONS, TOKEN_TTL_HOURS, IDLE_TIMEOUT_MINUTES, hash_password, verify_password, create_session, current_user_from_token, get_current_user, require_roles, audit, bearer, current_session, validate_password_strength, check_login_rate, record_login_failure, clear_login_failures

router = APIRouter(prefix="/auth", tags=["Authentication & IAM"])

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)

class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=10, max_length=200)

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    display_name: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=10, max_length=200)
    role: str = "user"
    email: str | None = None
    department: str | None = None

class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    email: str | None = None
    department: str | None = None
    is_active: bool | None = None
    new_password: str | None = None

@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = payload.username.strip().lower()
    check_login_rate(request, username)
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        record_login_failure(request, username)
        audit(db, user, "login", "failed", "session", request.client.host if request.client else None, "Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    clear_login_failures(request, username)
    token = create_session(db, user, request)
    audit(db, user, "login", "success", "session", request.client.host if request.client else None)
    return {"access_token": token, "token_type": "bearer", "expires_in_hours": TOKEN_TTL_HOURS, "idle_timeout_minutes": IDLE_TIMEOUT_MINUTES, "must_change_password": False, "user": user_dict(user), "permissions": ROLE_PERMISSIONS.get(user.role, [])}

@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"user": user_dict(user), "permissions": ROLE_PERMISSIONS.get(user.role, [])}

@router.get("/session")
def session_info(credentials=Depends(bearer), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not credentials: raise HTTPException(401, "Authentication required")
    row = current_session(db, credentials.credentials)
    if not row: raise HTTPException(401, "Session expired or invalid")
    now = datetime.utcnow()
    absolute_remaining = max(0, int((row.expires_at - now).total_seconds()))
    last = row.last_activity_at or row.created_at
    idle_remaining = max(0, int(IDLE_TIMEOUT_MINUTES * 60 - (now - last).total_seconds()))
    remaining = min(absolute_remaining, idle_remaining)
    active = db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None), UserSession.expires_at >= datetime.utcnow()).count()
    return {"created_at": row.created_at.isoformat(), "expires_at": row.expires_at.isoformat(), "last_activity_at": last.isoformat(), "remaining_seconds": remaining, "absolute_remaining_seconds": absolute_remaining, "idle_remaining_seconds": idle_remaining, "idle_timeout_minutes": IDLE_TIMEOUT_MINUTES, "active_sessions": active}

@router.post("/change-password")
def change_password(payload: PasswordChange, request: Request, credentials=Depends(bearer), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not credentials: raise HTTPException(401, "Authentication required")
    if not verify_password(payload.current_password, user.password_hash):
        audit(db, user, "password.change", "failed", f"user:{user.id}", request.client.host if request.client else None, "Current password rejected")
        raise HTTPException(400, "Current password is incorrect")
    errors = validate_password_strength(payload.new_password)
    if errors: raise HTTPException(400, "New password must contain " + ", ".join(errors) + ".")
    if verify_password(payload.new_password, user.password_hash): raise HTTPException(400, "New password must differ from the current password")
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.token_hash != token_hash, UserSession.revoked_at.is_(None)).update({UserSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()
    audit(db, user, "password.change", "success", f"user:{user.id}", request.client.host if request.client else None)
    return {"status": "success", "message": "Password changed. Other active sessions were signed out."}

@router.post("/logout")
def logout(request: Request, credentials=Depends(bearer), db: Session = Depends(get_db)):
    if credentials:
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        row = db.query(UserSession).filter(UserSession.token_hash == token_hash, UserSession.revoked_at.is_(None)).first()
        if row:
            row.revoked_at = datetime.utcnow()
            db.commit()
            user = db.query(User).filter(User.id == row.user_id).first()
            audit(db, user, "logout", "success", "session", request.client.host if request.client else None)
    return {"status": "logged_out"}

@router.post("/logout-all")
def logout_all(request: Request, credentials=Depends(bearer), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None)).update({UserSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit(); audit(db, user, "logout_all", "success", f"user:{user.id}", request.client.host if request.client else None)
    return {"status": "logged_out", "message": "All active sessions have been signed out."}

@router.get("/roles")
def roles(user: User = Depends(get_current_user)):
    return {"roles": ROLE_PERMISSIONS}

@router.get("/users")
def list_users(user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    rows = db.query(User).order_by(User.created_at.desc()).all(); return [user_dict(x) for x in rows]

@router.post("/users")
def create_user(payload: UserCreate, request: Request, user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    if payload.role not in ROLE_PERMISSIONS: raise HTTPException(400, "Invalid role")
    errors = validate_password_strength(payload.password)
    if errors: raise HTTPException(400, "Password must contain " + ", ".join(errors) + ".")
    username = payload.username.strip().lower()
    if db.query(User).filter(User.username == username).first(): raise HTTPException(409, "Username already exists")
    u = User(username=username, display_name=payload.display_name, password_hash=hash_password(payload.password), role=payload.role, email=payload.email, department=payload.department, must_change_password=False)
    db.add(u); db.commit(); db.refresh(u); audit(db, user, "iam.create_user", "success", f"user:{u.id}", request.client.host if request.client else None, f"role={u.role}"); return user_dict(u)

@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, request: Request, user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u: raise HTTPException(404, "User not found")
    data = payload.model_dump(exclude_none=True)
    if "role" in data and data["role"] not in ROLE_PERMISSIONS: raise HTTPException(400, "Invalid role")
    if "new_password" in data:
        errors = validate_password_strength(data["new_password"])
        if errors: raise HTTPException(400, "Password must contain " + ", ".join(errors) + ".")
        u.password_hash = hash_password(data.pop("new_password")); u.must_change_password = False
    for k,v in data.items(): setattr(u,k,v)
    db.commit(); db.refresh(u); audit(db, user, "iam.update_user", "success", f"user:{u.id}", request.client.host if request.client else None); return user_dict(u)

@router.get("/audit")
def audit_logs(limit: int = 200, user: User = Depends(require_roles("admin", "employee")), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(max(1,min(limit,500))).all()
    return [{"id":x.id,"timestamp":x.timestamp.isoformat(),"username":x.username,"action":x.action,"resource":x.resource,"result":x.result,"ip_address":x.ip_address,"details":x.details} for x in rows]

def user_dict(u: User):
    return {"id":u.id,"username":u.username,"display_name":u.display_name,"role":u.role,"email":u.email,"department":u.department,"is_active":u.is_active,"must_change_password":u.must_change_password,"created_at":u.created_at.isoformat() if u.created_at else None,"last_login":u.last_login.isoformat() if u.last_login else None}
