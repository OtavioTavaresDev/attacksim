from sqlalchemy.orm import Session
from datetime import datetime
from app.models.scan_history import ScanHistory
import json

def save_scan(db: Session, target: str, module: str, result: dict):
    """Salva resultado do scan no histórico."""
    
    severity_map = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 0}
    
    scan = ScanHistory(
        target_url=target,
        module_name=module,
        status="completed",
        severity=result.get('severity', 'info'),
        risk_score=severity_map.get(result.get('severity', 'info'), 0),
        findings_count=len(result.get('findings', [])),
        results=result,
        remediation=result.get('remediation', ''),
        completed_at=datetime.utcnow()
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def get_history(db: Session, skip: int = 0, limit: int = 50):
    """Retorna histórico de scans."""
    return db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).offset(skip).limit(limit).all()

def get_stats(db: Session):
    """Retorna estatísticas gerais."""
    total = db.query(ScanHistory).count()
    vulnerable = db.query(ScanHistory).filter(ScanHistory.severity.in_(['critical', 'high', 'medium'])).count()
    
    avg_score = db.query(ScanHistory).with_entities(
        func.avg(ScanHistory.risk_score).label('avg')
    ).scalar() or 0
    
    by_module = {}
    scans = db.query(ScanHistory).all()
    for scan in scans:
        by_module[scan.module_name] = by_module.get(scan.module_name, 0) + 1
    
    return {
        "total_scans": total,
        "vulnerable_scans": vulnerable,
        "secure_scans": total - vulnerable,
        "average_risk_score": round(avg_score, 2),
        "scans_by_module": by_module
    }
