from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum, Float, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.core.database import Base
import enum


class AttackSource(str, enum.Enum):
    static = "static"
    adaptive = "adaptive"
    manual = "manual"
    strategy = "strategy"


class AttackCategory(str, enum.Enum):
    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    role_play = "role_play"
    indirect_injection = "indirect_injection"
    context_manipulation = "context_manipulation"
    multi_turn = "multi_turn"
    payload_encoding = "payload_encoding"
    rag_poisoning = "rag_poisoning"
    api_abuse = "api_abuse"
    cognitive = "cognitive"
    strategy_based = "strategy_based"


class AttackType(str, enum.Enum):
    prompt = "prompt"
    rag = "rag"
    api = "api"
    strategy = "strategy"
    document = "document"


class AttackDomain(str, enum.Enum):
    general = "general"
    finance = "finance"
    healthcare = "healthcare"
    legal = "legal"
    hr = "hr"
    security = "security"


class AttackLevel(int, enum.Enum):
    L1 = 1   # Basic sanity check
    L2 = 2   # Structured attacks
    L3 = 3   # Contextual attacks
    L4 = 4   # Cognitive attacks
    L5 = 5   # Adaptive adversarial


class AttackTemplate(Base):
    __tablename__ = "attack_templates"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    category: Mapped[AttackCategory] = mapped_column(Enum(AttackCategory))
    attack_type: Mapped[AttackType] = mapped_column(Enum(AttackType), default=AttackType.prompt)
    level: Mapped[int] = mapped_column(Integer, default=1)  # 1-5
    domain: Mapped[AttackDomain] = mapped_column(Enum(AttackDomain), default=AttackDomain.general)
    description: Mapped[str] = mapped_column(Text, default="")
    payload_template: Mapped[str] = mapped_column(Text)

    # Strategy plan (for L3-L5 attacks)
    strategy_goal: Mapped[str] = mapped_column(Text, default="")
    strategy_method: Mapped[str] = mapped_column(String(255), default="")
    strategy_vulnerability: Mapped[str] = mapped_column(String(255), default="")
    strategy_steps: Mapped[list] = mapped_column(JSON, default=list)

    # Metrics (updated by learning engine)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    mutation_count: Mapped[int] = mapped_column(Integer, default=0)

    # Parent attack (for mutations)
    parent_id: Mapped[int] = mapped_column(Integer, nullable=True)

    source: Mapped[AttackSource] = mapped_column(Enum(AttackSource), default=AttackSource.static)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
