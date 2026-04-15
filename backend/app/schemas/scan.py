from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any

class ScanBase(BaseModel):
    target_url: str

class ScanCreate(ScanBase):
    pass

class Scan(ScanBase):
    id: int
    status: str
    created_by: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    risk_score: float
    created_at: datetime

    class Config:
        from_attributes = True

class ScanResult(Scan):
    results: Optional[Dict[str, Any]] = {}