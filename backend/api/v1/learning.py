from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db, verify_api_key
from backend.schemas.learning import LearningInsights, AttackRankingOut
from backend.modules.learning_engine.store import get_top_attacks

router = APIRouter(prefix="/learning", tags=["Learning Engine"])


@router.get("/insights")
async def get_insights(
    provider: str = Query(default="openai"),
    model: str = Query(default="gpt-4o-mini"),
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Get learning insights: top attacks and vulnerability trends."""
    top_attacks = await get_top_attacks(db, provider, model, limit=limit)

    # Compute most vulnerable categories
    from collections import Counter
    cat_counter = Counter(a["category"] for a in top_attacks if a["success_rate"] > 0.3)
    most_vulnerable = [cat for cat, _ in cat_counter.most_common(5)]

    return {
        "top_attacks": top_attacks,
        "most_vulnerable_categories": most_vulnerable,
        "provider": provider,
        "model": model,
    }
