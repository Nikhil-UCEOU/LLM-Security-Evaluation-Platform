from datetime import datetime
from sqlalchemy import String, Text, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column
from backend.core.database import Base
import enum


class AttackSource(str, enum.Enum):
    static = "static"
    adaptive = "adaptive"
    manual = "manual"


class AttackCategory(str, enum.Enum):
    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    role_play = "role_play"
    indirect_injection = "indirect_injection"
    context_manipulation = "context_manipulation"
    multi_turn = "multi_turn"
    payload_encoding = "payload_encoding"


class AttackTemplate(Base):
    __tablename__ = "attack_templates"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    category: Mapped[AttackCategory] = mapped_column(Enum(AttackCategory))
    description: Mapped[str] = mapped_column(Text, default="")
    payload_template: Mapped[str] = mapped_column(Text)
    source: Mapped[AttackSource] = mapped_column(Enum(AttackSource), default=AttackSource.static)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
