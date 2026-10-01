from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text
from app.core.database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True)
    device_type = Column(String(50), nullable=False, index=True)
    platform = Column(String(100), nullable=False)
    os_version = Column(String(150), nullable=True)
    status = Column(String(30), default="online", nullable=False, index=True)
    risk_score = Column(Integer, default=0, nullable=False)
    agent_version = Column(String(50), nullable=True)
    source = Column(String(100), default="manual", nullable=False)
    location = Column(String(150), nullable=True)
    tags = Column(Text, nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
