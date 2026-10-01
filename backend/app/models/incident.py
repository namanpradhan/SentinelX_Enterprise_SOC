from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text
from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(30), default="open", nullable=False)
    hostname = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    summary = Column(Text, nullable=False)
