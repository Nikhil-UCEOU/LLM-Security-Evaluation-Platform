from fastapi import APIRouter
from backend.api.v1 import gateway, attacks, evaluations, rca, mitigations, learning

router = APIRouter(prefix="/api/v1")

router.include_router(gateway.router)
router.include_router(attacks.router)
router.include_router(evaluations.router)
router.include_router(rca.router)
router.include_router(mitigations.router)
router.include_router(learning.router)
