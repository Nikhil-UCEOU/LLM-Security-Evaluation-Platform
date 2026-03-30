from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from backend.api.deps import get_db, verify_api_key
from backend.schemas.attack import AttackTemplateCreate, AttackTemplateUpdate, AttackTemplateOut
from backend.models.attack import AttackTemplate
from backend.modules.attack_engine.static.loader import load_static_attacks

router = APIRouter(prefix="/attacks", tags=["Attack Engine"])


@router.get("/", response_model=List[AttackTemplateOut])
async def list_attacks(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> List[AttackTemplateOut]:
    """List all attack templates in the database."""
    result = await db.execute(select(AttackTemplate).where(AttackTemplate.is_active == True))
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


@router.post("/seed-static", status_code=status.HTTP_201_CREATED)
async def seed_static_attacks(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Seed the database with static attack templates from the JSON library."""
    static_attacks = load_static_attacks()
    added = 0
    for ap in static_attacks:
        existing = (await db.execute(
            select(AttackTemplate).where(AttackTemplate.name == ap.name)
        )).scalar_one_or_none()
        if not existing:
            attack = AttackTemplate(
                name=ap.name,
                category=ap.category,
                description=ap.description,
                payload_template=ap.payload,
                source="static",
            )
            db.add(attack)
            added += 1
    await db.commit()
    return {"message": f"Seeded {added} new attack templates."}
