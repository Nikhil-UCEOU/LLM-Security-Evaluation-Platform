from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.models.learning import LearningEntry, AttackRanking
from backend.models.evaluation import Classification


async def store_evaluation_results(
    session: AsyncSession,
    provider: str,
    model: str,
    results: List[Dict[str, Any]],
) -> None:
    """
    Persist evaluation results into the learning tables.
    Updates LearningEntry for each attack and refreshes AttackRanking.
    """
    for result in results:
        attack_id = result.get("attack_id")
        if not attack_id:
            continue

        is_success = result["classification"] in (Classification.unsafe, Classification.partial)

        # Upsert LearningEntry
        stmt = select(LearningEntry).where(
            LearningEntry.attack_id == attack_id,
            LearningEntry.provider == provider,
            LearningEntry.model == model,
        )
        entry = (await session.execute(stmt)).scalar_one_or_none()

        if entry:
            entry.total_attempts += 1
            entry.successful_attempts += int(is_success)
            entry.success_rate = entry.successful_attempts / entry.total_attempts
            entry.last_seen = datetime.utcnow()
        else:
            entry = LearningEntry(
                attack_id=attack_id,
                provider=provider,
                model=model,
                total_attempts=1,
                successful_attempts=int(is_success),
                success_rate=float(is_success),
                last_seen=datetime.utcnow(),
            )
            session.add(entry)

        await session.flush()

        # Upsert AttackRanking
        rank_stmt = select(AttackRanking).where(
            AttackRanking.attack_id == attack_id,
            AttackRanking.provider == provider,
            AttackRanking.model == model,
        )
        ranking = (await session.execute(rank_stmt)).scalar_one_or_none()
        rank_score = entry.success_rate

        if ranking:
            ranking.rank_score = rank_score
            ranking.updated_at = datetime.utcnow()
        else:
            ranking = AttackRanking(
                attack_id=attack_id,
                provider=provider,
                model=model,
                rank_score=rank_score,
            )
            session.add(ranking)

    await session.commit()


async def get_top_attacks(
    session: AsyncSession,
    provider: str,
    model: str,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Retrieve top-ranked attacks for a provider/model combination."""
    from sqlalchemy import desc
    from backend.models.attack import AttackTemplate

    stmt = (
        select(AttackRanking, AttackTemplate, LearningEntry)
        .join(AttackTemplate, AttackRanking.attack_id == AttackTemplate.id)
        .join(
            LearningEntry,
            (LearningEntry.attack_id == AttackRanking.attack_id)
            & (LearningEntry.provider == AttackRanking.provider)
            & (LearningEntry.model == AttackRanking.model),
        )
        .where(AttackRanking.provider == provider, AttackRanking.model == model)
        .order_by(desc(AttackRanking.rank_score))
        .limit(limit)
    )
    rows = (await session.execute(stmt)).all()

    return [
        {
            "attack_id": row.AttackRanking.attack_id,
            "attack_name": row.AttackTemplate.name,
            "category": row.AttackTemplate.category.value,
            "provider": provider,
            "model": model,
            "rank_score": row.AttackRanking.rank_score,
            "success_rate": row.LearningEntry.success_rate,
        }
        for row in rows
    ]
