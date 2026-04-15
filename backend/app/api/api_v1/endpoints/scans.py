from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.schemas.scan import Scan, ScanCreate, ScanResult
from app.services import scan_service
from app.core.orchestrator import AttackOrchestrator

router = APIRouter()

@router.post("/", response_model=Scan)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Inicia um novo scan de segurança."""
    scan = scan_service.create_scan(db, scan_data)
    
    # Executa o scan em background
    orchestrator = AttackOrchestrator()
    background_tasks.add_task(
        scan_service.execute_scan,
        db,
        scan.id,
        scan_data.target_url,
        orchestrator
    )
    
    return scan

@router.get("/", response_model=List[Scan])
def list_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Lista todos os scans."""
    return scan_service.get_scans(db, skip=skip, limit=limit)

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Obtém detalhes de um scan específico."""
    scan = scan_service.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
