from typing import Optional
from pydantic import BaseModel, Field


class SecurityEventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = "low"
    hostname: Optional[str] = None
    username: Optional[str] = None
    message: Optional[str] = None
