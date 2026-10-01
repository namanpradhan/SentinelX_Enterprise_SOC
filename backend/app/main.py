from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from uuid import uuid4
import os, time, hmac

from app.core.database import Base, engine, SessionLocal, DB_FILE
from app.models import SecurityEvent, Alert, Incident, Device, User, UserSession, AuditLog, RuleState
from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.dashboard import router as dashboard_router
from app.api.ai import router as ai_router
from app.api.devices import router as devices_router
from app.api.collectors import router as collectors_router
from app.api.assets import router as assets_router
from app.api.rules import router as rules_router
from app.api.soc import router as soc_router
from app.api.network import router as network_router
from app.api.auth import router as auth_router
from app.api.system import router as system_router
from app.api.vulnerabilities import router as vulnerabilities_router
from app.api.integrations import router as integrations_router
from app.services.auth import current_user_from_token, seed_default_users
from app.rules.detection import ensure_rule_states

VERSION = "4.2.13"
ROOT_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = ROOT_DIR / "frontend"

Base.metadata.create_all(bind=engine)
with engine.begin() as conn:
    cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(user_sessions)").fetchall()}
    if "last_activity_at" not in cols:
        conn.exec_driver_sql("ALTER TABLE user_sessions ADD COLUMN last_activity_at DATETIME")

seed_default_users()
db = SessionLocal()
try:
    ensure_rule_states(db)
finally:
    db.close()

app = FastAPI(
    title="SentinelX Enterprise SOC",
    description="Defensive Security Operations Center platform for authorized monitoring, detection, investigation and response.",
    version=VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    swagger_ui_parameters={"displayRequestDuration": True, "persistAuthorization": False},
)

ALLOWED_HOSTS = [h.strip() for h in os.getenv("SENTINELX_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

ALLOWED_ORIGINS = {"http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:5500", "http://localhost:5500"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED_ORIGINS),
    allow_origin_regex=r"https?://(127\.0\.0\.1|localhost):55\d{2}$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Agent-Key", "X-Request-ID"],
)

MAX_REQUEST_BYTES = int(os.getenv("SENTINELX_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
_RATE_WINDOW, _RATE_MAX, _RATE_STATE = 60, 180, {}
PUBLIC = {"/", "/health", "/api/info", "/auth/login", "/docs", "/openapi.json", "/redoc", "/favicon.svg"}

def _is_public_path(path: str) -> bool:
    return path in PUBLIC or path.startswith("/static/") or path.startswith("/docs") or path.startswith("/redoc")

@app.middleware("http")
async def security_and_auth(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    path = request.url.path
    length = request.headers.get("content-length")
    response = None
    if length and length.isdigit() and int(length) > MAX_REQUEST_BYTES:
        response = JSONResponse({"detail": "Request body exceeds the SentinelX size limit.", "request_id": request_id}, status_code=413)
    elif request.method != "OPTIONS" and not _is_public_path(path):
        client = request.client.host if request.client else "unknown"
        key = (client, request.method, path.split('/')[1] if '/' in path else path)
        now = time.time()
        values = [t for t in _RATE_STATE.get(key, []) if now - t < _RATE_WINDOW]
        values.append(now); _RATE_STATE[key] = values
        if len(values) > _RATE_MAX:
            response = JSONResponse({"detail": "Request rate limit exceeded. Retry shortly.", "request_id": request_id}, status_code=429)
        else:
            auth = request.headers.get("authorization", "")
            token = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else None
            agent_key = request.headers.get("X-Agent-Key")
            expected_agent = os.getenv("SENTINELX_AGENT_KEY", "")
            agent_ok = bool(path.startswith("/collectors/") and expected_agent and agent_key and hmac.compare_digest(agent_key, expected_agent))
            if agent_ok:
                response = await call_next(request)
            elif not token:
                response = JSONResponse({"detail": "Authentication required", "request_id": request_id}, status_code=401)
            else:
                db = SessionLocal()
                try:
                    user = current_user_from_token(db, token)
                finally:
                    db.close()
                if not user:
                    response = JSONResponse({"detail": "Session expired or invalid", "request_id": request_id}, status_code=401)
                else:
                    response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self' data:; font-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' http://127.0.0.1:5500 http://localhost:5500;"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-SentinelX-Version"] = VERSION
    if "server" in response.headers:
        del response.headers["server"]
    return response

for router in [events_router, alerts_router, incidents_router, dashboard_router, ai_router, devices_router, collectors_router, assets_router, rules_router, soc_router, network_router, auth_router, system_router, vulnerabilities_router, integrations_router]:
    app.include_router(router)

@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html", media_type="text/html")

@app.get("/favicon.svg")
def favicon():
    return FileResponse(FRONTEND_DIR / "favicon.svg", media_type="image/svg+xml")

@app.get("/api/info")
def api_info():
    return {"project": "SentinelX", "edition": "Enterprise SOC", "version": VERSION, "status": "operational", "ui": "same-origin", "database": "connected"}

@app.get("/health")
def health():
    return {"status": "healthy", "database": "connected", "version": VERSION, "ui": "served-by-fastapi"}

# Serve frontend assets from the same origin so the UI and API cannot drift apart locally.
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="frontend-static")
