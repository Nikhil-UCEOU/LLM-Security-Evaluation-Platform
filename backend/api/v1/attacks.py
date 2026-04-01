from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, asc, desc
from typing import List, Optional

from backend.api.deps import get_db, verify_api_key
from backend.schemas.attack import (
    AttackTemplateCreate, AttackTemplateUpdate, AttackTemplateOut, StrategyPlanRequest
)
from backend.models.attack import AttackTemplate, AttackCategory, AttackType, AttackDomain
from backend.modules.attack_engine.static.loader import load_attacks_as_db_dicts
from backend.modules.attack_engine.strategy_planner import build_strategy_plan, get_strategy_options
from backend.modules.adaptive_attack_engine.mutator import mutate

router = APIRouter(prefix="/attacks", tags=["Attack Engine"])


@router.get("/", response_model=List[AttackTemplateOut])
async def list_attacks(
    level: Optional[int] = Query(None, ge=1, le=5, description="Filter by level 1-5"),
    attack_type: Optional[str] = Query(None, description="Filter by type: prompt/rag/api/strategy"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    category: Optional[str] = Query(None, description="Filter by category"),
    sort_by: Optional[str] = Query(default="created_at", description="Sort by: success_rate|risk_score|level|created_at"),
    sort_dir: Optional[str] = Query(default="desc", description="asc or desc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> List[AttackTemplateOut]:
    """List all attack templates with optional filtering and sorting."""
    stmt = select(AttackTemplate).where(AttackTemplate.is_active == True)

    if level is not None:
        stmt = stmt.where(AttackTemplate.level == level)
    if attack_type:
        stmt = stmt.where(AttackTemplate.attack_type == attack_type)
    if domain:
        stmt = stmt.where(AttackTemplate.domain == domain)
    if category:
        stmt = stmt.where(AttackTemplate.category == category)

    sort_col = {
        "success_rate": AttackTemplate.success_rate,
        "risk_score": AttackTemplate.risk_score,
        "level": AttackTemplate.level,
        "created_at": AttackTemplate.created_at,
    }.get(sort_by, AttackTemplate.created_at)

    stmt = stmt.order_by(desc(sort_col) if sort_dir == "desc" else asc(sort_col))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/", response_model=AttackTemplateOut, status_code=status.HTTP_201_CREATED)
async def create_attack(
    body: AttackTemplateCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> AttackTemplateOut:
    """Create a new custom attack template."""
    attack = AttackTemplate(**body.model_dump())
    db.add(attack)
    await db.commit()
    await db.refresh(attack)
    return attack


@router.get("/strategy-options")
async def strategy_options(_: str = Depends(verify_api_key)) -> dict:
    """Return available options for the Strategy Builder dropdowns."""
    return get_strategy_options()


@router.post("/strategy-plan")
async def create_strategy_plan(
    body: StrategyPlanRequest,
    _: str = Depends(verify_api_key),
) -> dict:
    """Generate a strategy plan and return the preview payload."""
    plan = build_strategy_plan(
        goal=body.goal,
        method=body.method,
        target_vulnerability=body.target_vulnerability,
        domain=body.domain,
        steps=body.steps,
    )
    return {
        "goal": plan.goal,
        "method": plan.method,
        "target_vulnerability": plan.target_vulnerability,
        "domain": plan.domain,
        "steps": plan.steps,
        "generated_payload": plan.generated_payload,
        "estimated_level": plan.level,
    }


@router.get("/{attack_id}", response_model=AttackTemplateOut)
async def get_attack(
    attack_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> AttackTemplateOut:
    attack = await db.get(AttackTemplate, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    return attack


@router.patch("/{attack_id}", response_model=AttackTemplateOut)
async def update_attack(
    attack_id: int,
    body: AttackTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> AttackTemplateOut:
    attack = await db.get(AttackTemplate, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(attack, field, value)
    await db.commit()
    await db.refresh(attack)
    return attack


@router.delete("/{attack_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_attack(
    attack_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    attack = await db.get(AttackTemplate, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    attack.is_active = False
    await db.commit()


@router.post("/{attack_id}/mutate", response_model=AttackTemplateOut, status_code=status.HTTP_201_CREATED)
async def mutate_attack(
    attack_id: int,
    strategy: str = Query(default="random", description="Mutation strategy: prefix|suffix|obfuscate|case|random"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> AttackTemplateOut:
    """Generate a mutated variant of an existing attack."""
    original = await db.get(AttackTemplate, attack_id)
    if not original:
        raise HTTPException(status_code=404, detail="Attack not found")

    from backend.modules.attack_engine.base_attack import AttackPayload

    original_payload = AttackPayload(
        attack_id=original.id,
        name=original.name,
        category=original.category,
        payload=original.payload_template,
        level=original.level,
        attack_type=original.attack_type.value,
        domain=original.domain.value,
        risk_score=original.risk_score,
    )
    mutated = mutate(original_payload, strategy=strategy)

    new_attack = AttackTemplate(
        name=mutated.name,
        category=original.category,
        attack_type=original.attack_type,
        level=original.level,
        domain=original.domain,
        description=mutated.description,
        payload_template=mutated.payload,
        source="adaptive",
        parent_id=original.id,
        risk_score=original.risk_score,
        strategy_goal=original.strategy_goal,
        strategy_method=original.strategy_method,
        strategy_vulnerability=original.strategy_vulnerability,
        strategy_steps=original.strategy_steps,
    )
    db.add(new_attack)

    # Increment parent's mutation count
    original.mutation_count = (original.mutation_count or 0) + 1
    await db.commit()
    await db.refresh(new_attack)
    return new_attack


@router.post("/seed-static", status_code=status.HTTP_201_CREATED)
async def seed_static_attacks(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Seed the database with the full 5-tier attack library."""
    raw_attacks = load_attacks_as_db_dicts()
    added = 0
    for item in raw_attacks:
        existing = (await db.execute(
            select(AttackTemplate).where(AttackTemplate.name == item["name"])
        )).scalar_one_or_none()
        if not existing:
            attack = AttackTemplate(
                name=item["name"],
                category=item["category"],
                attack_type=item.get("attack_type", "prompt"),
                level=item.get("level", 1),
                domain=item.get("domain", "general"),
                description=item.get("description", ""),
                payload_template=item["payload"],
                source="static",
                risk_score=item.get("risk_score", 0.5),
                strategy_goal=item.get("strategy_goal", ""),
                strategy_method=item.get("strategy_method", ""),
                strategy_vulnerability=item.get("strategy_vulnerability", ""),
                strategy_steps=item.get("strategy_steps", []),
            )
            db.add(attack)
            added += 1
    await db.commit()
    return {"message": f"Seeded {added} new attack templates across 5 difficulty levels."}
