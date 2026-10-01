from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.device import Device
from app.services.telemetry import ingest_event, SUPPORTED_PLATFORMS
from app.services.auth import collector_identity
import os

router = APIRouter(prefix="/collectors", tags=["Universal Telemetry"])

class TelemetryEnvelope(BaseModel):
    platform: str = Field(default="unknown")
    source: str | None = None
    event_type: str = "generic_event"
    severity: str = "low"
    hostname: str | None = None
    device_name: str | None = None
    username: str | None = None
    message: str = "Universal telemetry event"
    ip_address: str | None = None
    device_type: str | None = None
    os_version: str | None = None
    agent_version: str | None = None

@router.get("/platforms")
def platforms():
    return [{"key": k, "name": v} for k, v in SUPPORTED_PLATFORMS.items()]

@router.post("/ingest")
def ingest(payload: TelemetryEnvelope, db: Session = Depends(get_db), identity=Depends(collector_identity)):
    p = payload.model_dump()
    platform = p["platform"].lower().replace(" ", "_")
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"Unsupported platform: {payload.platform}")
    # Upsert a lightweight asset heartbeat when an asset identity is available.
    identity = payload.hostname or payload.device_name
    if identity:
        device = db.query(Device).filter(Device.hostname == identity).first()
        if not device:
            device = Device(name=identity, hostname=identity, ip_address=payload.ip_address,
                            device_type=payload.device_type or "endpoint", platform=SUPPORTED_PLATFORMS[platform],
                            os_version=payload.os_version, status="online", agent_version=payload.agent_version,
                            source="universal_collector", last_seen=datetime.utcnow())
            db.add(device); db.commit()
        else:
            device.status = "online"; device.last_seen = datetime.utcnow()
            if payload.ip_address: device.ip_address = payload.ip_address
            if payload.agent_version: device.agent_version = payload.agent_version
            db.commit()
    event, alert, incident, detection = ingest_event(db, p)
    return {
        "status":"accepted", "platform":SUPPORTED_PLATFORMS[platform], "event_id":event.id,
        "detected":detection.get("detected", False),
        "alert_id": alert.id if alert else None,
        "incident_id": incident.id if incident else None,
        "detection": detection,
    }

@router.post("/{platform}/heartbeat")
def heartbeat(platform: str, hostname: str, db: Session = Depends(get_db)):
    key = platform.lower().replace(" ", "_")
    if key not in SUPPORTED_PLATFORMS: raise HTTPException(status_code=400, detail="Unsupported platform")
    d = db.query(Device).filter(Device.hostname == hostname).first()
    if not d: raise HTTPException(status_code=404, detail="Device not registered")
    d.status="online"; d.last_seen=datetime.utcnow(); db.commit()
    return {"status":"online", "hostname":hostname, "platform":SUPPORTED_PLATFORMS[key], "last_seen":d.last_seen.isoformat()}
