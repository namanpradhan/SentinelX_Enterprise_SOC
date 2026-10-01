from datetime import datetime
from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.device import Device
from app.services.auth import get_current_user

router = APIRouter(prefix="/soc", tags=["SOC Command Center"])

@router.get("/overview")
def overview(db: Session = Depends(get_db), user=Depends(get_current_user)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(250).all()
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(250).all()
    devices = db.query(Device).order_by(Device.last_seen.desc()).limit(500).all()
    incidents = db.query(Incident).order_by(Incident.updated_at.desc()).limit(100).all()
    severity = Counter(a.severity for a in alerts)
    status = Counter(a.status for a in alerts)
    platforms = Counter(d.platform for d in devices)
    device_status = Counter(d.status for d in devices)
    rules = Counter(a.rule for a in alerts)
    risk_values = [max(0, min(100, int(d.risk_score or 0))) for d in devices]
    posture = round(sum(risk_values) / len(risk_values), 1) if risk_values else 0
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "posture_score": posture,
        "counts": {
            "events": db.query(SecurityEvent).count(),
            "alerts": db.query(Alert).count(),
            "open_alerts": db.query(Alert).filter(Alert.status == "open").count(),
            "critical_alerts": db.query(Alert).filter(Alert.severity == "critical").count(),
            "high_alerts": db.query(Alert).filter(Alert.severity == "high").count(),
            "incidents": db.query(Incident).count(),
            "open_incidents": db.query(Incident).filter(Incident.status != "resolved").count(),
            "devices": db.query(Device).count(),
            "online_devices": db.query(Device).filter(Device.status == "online").count(),
        },
        "severity": dict(severity),
        "alert_status": dict(status),
        "platforms": dict(platforms),
        "device_status": dict(device_status),
        "top_rules": [{"rule": k, "count": v} for k, v in rules.most_common(8)],
        "recent_alerts": [
            {"id": a.id, "rule": a.rule, "severity": a.severity, "risk_score": a.risk_score,
             "status": a.status, "created_at": a.created_at.isoformat() if a.created_at else None,
             "mitre": a.mitre_technique}
            for a in alerts[:12]
        ],
        "recent_incidents": [
            {"id": i.id, "title": i.title, "severity": i.severity, "risk_score": i.risk_score,
             "status": i.status, "hostname": i.hostname,
             "updated_at": i.updated_at.isoformat() if i.updated_at else None}
            for i in incidents[:8]
        ],
        "recent_events": [
            {"id": e.id, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
             "source": e.source, "event_type": e.event_type, "severity": e.severity,
             "hostname": e.hostname, "username": e.username, "message": e.message}
            for e in events[:15]
        ],
    }

@router.get("/activity")
def activity(limit: int = 30, db: Session = Depends(get_db), user=Depends(get_current_user)):
    limit = max(1, min(limit, 100))
    rows = []
    for a in db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all():
        rows.append({"time": a.created_at.isoformat() if a.created_at else None,
                     "kind": "alert", "severity": a.severity, "title": a.rule,
                     "description": a.description, "id": a.id})
    for i in db.query(Incident).order_by(Incident.updated_at.desc()).limit(limit).all():
        rows.append({"time": i.updated_at.isoformat() if i.updated_at else None,
                     "kind": "incident", "severity": i.severity, "title": i.title,
                     "description": i.summary, "id": i.id})
    rows.sort(key=lambda x: x["time"] or "", reverse=True)
    return rows[:limit]
