
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(150), nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(String(30), nullable=False, default="user", index=True)
    email = Column(String(255), nullable=True)
    department = Column(String(120), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    must_change_password = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
