from backend.core.database import get_db
from backend.core.security import verify_api_key
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

# Re-export common deps for use in routes
__all__ = ["get_db", "verify_api_key", "AsyncSession", "Depends"]
