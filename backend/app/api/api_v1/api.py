from fastapi import APIRouter
from app.api.api_v1.endpoints import auth, scans, attacks

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(attacks.router, prefix="/attacks", tags=["attacks"])
