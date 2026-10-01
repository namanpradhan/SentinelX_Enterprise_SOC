
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, String
from app.core.database import Base

class RuleState(Base):
    __tablename__ = "rule_states"
    rule_id = Column(String(120), primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
