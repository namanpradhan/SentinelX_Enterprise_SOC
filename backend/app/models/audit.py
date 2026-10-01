
from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text
from app.core.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    action = Column(String(120), nullable=False)
    resource = Column(String(120), nullable=True)
    result = Column(String(30), nullable=False, default="success")
    ip_address = Column(String(80), nullable=True)
    details = Column(Text, nullable=True)
