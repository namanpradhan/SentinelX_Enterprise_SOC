import os
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db, DB_FILE
from app.models.device import Device
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.rule_state import RuleState
from app.models.user import User
from app.models.session import UserSession
from app.rules.detection import RULES
from app.services.idsips import status as ids_status
from app.services.ai import models as ai_models
from app.services.auth import get_current_user
from app.api.network import local_info_data

router = APIRouter(prefix="/system", tags=["System & Security"])

@router.get("/status")
def status(db: Session = Depends(get_db), user=Depends(get_current_user)):
    local = local_info_data()
    active_sessions = db.query(UserSession).filter(UserSession.revoked_at.is_(None), UserSession.expires_at >= datetime.utcnow()).count()
    enabled_rules = db.query(RuleState).filter(RuleState.enabled.is_(True)).count()
    return {
        "version": os.getenv("SENTINELX_VERSION", "4.2.8"),
        "database": "connected",
        "database_file": str(DB_FILE),
        "rules": {"total": len(RULES), "enabled": enabled_rules},
        "users": db.query(User).count(),
        "sessions": active_sessions,
        "events": db.query(SecurityEvent).count(),
        "alerts": db.query(Alert).count(),
        "devices": db.query(Device).count(),
        "network": local,
        "security_controls": [
            "Role-based access control",
            "Bearer session tokens",
            "API authorization middleware",
            "CORS allowlist",
            "Security headers",
            "Request size and rate controls at application boundary",
            "Audit logging",
            "Content Security Policy and cross-origin hardening",
            "Request size and API rate controls",
            "Protected collector endpoints",
            "Defensive vulnerability assessment integration",
            "Suricata/Snort telemetry integration",
            "Metasploit module intelligence with execution disabled",
        ],
        "integrations": {"ids_ips": ids_status(), "ai": ai_models()},
    }
