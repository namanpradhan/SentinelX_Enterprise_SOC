
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from app.core.database import Base

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_activity_at = Column(DateTime, nullable=True, index=True)
    revoked_at = Column(DateTime, nullable=True)
    ip_address = Column(String(80), nullable=True)
    user_agent = Column(String(500), nullable=True)
