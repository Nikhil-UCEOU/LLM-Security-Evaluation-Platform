from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum, Float, ForeignKey, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional, List
from backend.core.database import Base
import enum


class RunStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Classification(str, enum.Enum):
    safe = "safe"
    unsafe = "unsafe"
    partial = "partial"
    unknown = "unknown"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    provider: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(100))
    system_prompt: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.pending)
    global_isr: Mapped[float] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    results: Mapped[list["EvaluationResult"]] = relationship("EvaluationResult", back_populates="run")


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), index=True)
    attack_id: Mapped[int] = mapped_column(ForeignKey("attack_templates.id"), nullable=True)
    attack_name: Mapped[str] = mapped_column(String(255))
    attack_payload: Mapped[str] = mapped_column(Text)
    response_text: Mapped[str] = mapped_column(Text)
    classification: Mapped[Classification] = mapped_column(Enum(Classification))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.none)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    isr_contribution: Mapped[float] = mapped_column(Float, default=0.0)
    attack_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    attack_strategy: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owasp_risk: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    signals: Mapped[Optional[List]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    run: Mapped["EvaluationRun"] = relationship("EvaluationRun", back_populates="results")
