from datetime import datetime
from sqlalchemy import Text, DateTime, Float, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.core.database import Base


class MitigationPlan(Base):
    __tablename__ = "mitigation_plans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), index=True)
    strategy: Mapped[str] = mapped_column(String(255))
    original_system_prompt: Mapped[str] = mapped_column(Text, default="")
    hardened_prompt: Mapped[str] = mapped_column(Text, default="")
    guardrails: Mapped[dict] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    result: Mapped["MitigationResult"] = relationship("MitigationResult", back_populates="plan", uselist=False)


class MitigationResult(Base):
    __tablename__ = "mitigation_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("mitigation_plans.id"), unique=True, index=True)
    original_isr: Mapped[float] = mapped_column(Float)
    hardened_isr: Mapped[float] = mapped_column(Float)
    improvement_pct: Mapped[float] = mapped_column(Float)
    retest_run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    plan: Mapped["MitigationPlan"] = relationship("MitigationPlan", back_populates="result")
