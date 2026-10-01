from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text, ForeignKey
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    rule = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(30), default="open", nullable=False)
    description = Column(Text, nullable=False)
    mitre_technique = Column(String(100), nullable=True)
