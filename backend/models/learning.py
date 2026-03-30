from datetime import datetime
from sqlalchemy import String, Float, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column
from backend.core.database import Base


class LearningEntry(Base):
    __tablename__ = "learning_entries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    attack_id: Mapped[int] = mapped_column(ForeignKey("attack_templates.id"), index=True)
    provider: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(100))
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)
    total_attempts: Mapped[int] = mapped_column(Integer, default=0)
    successful_attempts: Mapped[int] = mapped_column(Integer, default=0)
    mutation_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AttackRanking(Base):
    __tablename__ = "attack_rankings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    attack_id: Mapped[int] = mapped_column(ForeignKey("attack_templates.id"), index=True)
    provider: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(100))
    rank_score: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
