from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text
from app.core.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), default="low", nullable=False)
    hostname = Column(String(255), nullable=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    message = Column(Text, nullable=True)
