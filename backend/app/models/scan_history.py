from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Text
from sqlalchemy.sql import func
from app.core.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    module_name = Column(String, nullable=False)
    status = Column(String, default="pending")
    severity = Column(String, default="info")
    risk_score = Column(Float, default=0.0)
    findings_count = Column(Integer, default=0)
    results = Column(JSON, default={})
    remediation = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
