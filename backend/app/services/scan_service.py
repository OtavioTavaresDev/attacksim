from sqlalchemy.orm import Session
from datetime import datetime

from app.models.scan import Scan
from app.schemas.scan import ScanCreate

def create_scan(db: Session, scan_data: ScanCreate, user_id: int = 1):
    """Cria um novo scan (user_id temporário = 1)."""
    db_scan = Scan(
        target_url=scan_data.target_url,
        status="pending",
        created_by=user_id
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def get_scans(db: Session, skip: int = 0, limit: int = 100):
    """Retorna lista de scans."""
    return db.query(Scan).offset(skip).limit(limit).all()

def get_scan(db: Session, scan_id: int):
    """Retorna um scan específico."""
    return db.query(Scan).filter(Scan.id == scan_id).first()

def execute_scan(db: Session, scan_id: int, target_url: str, orchestrator):
    """Executa o scan em background."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    
    # Atualizar status
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    db.commit()
    
    try:
        # Executar orquestrador
        results = orchestrator.run_scan(target_url)
        
        # Atualizar resultados
        scan.status = "completed"
        scan.risk_score = results["risk_score"]
        scan.results = results
        scan.finished_at = datetime.utcnow()
        
    except Exception as e:
        scan.status = "failed"
        scan.results = {"error": str(e)}
        scan.finished_at = datetime.utcnow()
    
    db.commit()
