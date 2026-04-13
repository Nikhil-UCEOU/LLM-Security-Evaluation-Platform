from fastapi import APIRouter
from backend.api.v1 import gateway, attacks, evaluations, rca, mitigations, learning, stream
from backend.mitigation_service.routes import router as mie_router
from backend.benchmark_service.routes import router as benchmark_router

router = APIRouter(prefix="/api/v1")

router.include_router(gateway.router)
router.include_router(attacks.router)
router.include_router(evaluations.router)
router.include_router(rca.router)
router.include_router(mitigations.router)
router.include_router(learning.router)
router.include_router(stream.router)
router.include_router(mie_router)
router.include_router(benchmark_router)
