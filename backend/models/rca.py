from datetime import datetime
from sqlalchemy import Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.core.database import Base


class RCAReport(Base):
    __tablename__ = "rca_reports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), unique=True, index=True)
    root_causes: Mapped[dict] = mapped_column(JSON, default=list)
    patterns: Mapped[dict] = mapped_column(JSON, default=list)
    affected_prompt_sections: Mapped[dict] = mapped_column(JSON, default=list)
    behavioral_analysis: Mapped[str] = mapped_column(Text, default="")
    architectural_findings: Mapped[str] = mapped_column(Text, default="")
    attack_trace: Mapped[dict] = mapped_column(JSON, default=list)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
