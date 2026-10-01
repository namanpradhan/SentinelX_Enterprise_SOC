from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.incident import Incident


def correlate_alert(db: Session, alert: Alert, hostname: str | None, username: str | None):
    window_start = datetime.utcnow() - timedelta(minutes=10)

    query = db.query(Alert).filter(
        Alert.created_at >= window_start,
        Alert.status == "open",
    )

    alerts = query.all()

    related = [
        item for item in alerts
        if item.id == alert.id or _same_context(item, alert, hostname, username, db)
    ]

    if len(related) < 3:
        return None

    total_risk = min(100, sum(item.risk_score for item in related))
    highest = "critical" if total_risk >= 90 else "high"

    existing = (
        db.query(Incident)
        .filter(
            Incident.status == "open",
            Incident.hostname == hostname,
            Incident.username == username,
        )
        .first()
    )

    if existing:
        existing.updated_at = datetime.utcnow()
        existing.risk_score = max(existing.risk_score, total_risk)
        existing.severity = highest
        existing.summary = (
            f"Correlated activity: {len(related)} open alerts within a 10-minute window."
        )
        db.commit()
        db.refresh(existing)
        return existing

    incident = Incident(
        title="Correlated Suspicious Activity",
        severity=highest,
        risk_score=total_risk,
        status="open",
        hostname=hostname,
        username=username,
        summary=f"{len(related)} related alerts detected within a 10-minute window.",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def _same_context(item: Alert, alert: Alert, hostname, username, db):
    # Alert does not store hostname/username; resolve the associated event.
    from app.models.event import SecurityEvent

    item_event = db.query(SecurityEvent).filter(SecurityEvent.id == item.event_id).first()
    alert_event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first()

    if not item_event or not alert_event:
        return False

    return (
        item_event.hostname == hostname
        and item_event.username == username
        and item_event.hostname == alert_event.hostname
        and item_event.username == alert_event.username
    )
