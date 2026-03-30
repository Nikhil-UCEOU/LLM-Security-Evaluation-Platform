from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.core.database import init_db
from backend.api.v1.router import router as api_router
from backend.api.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CortexFlow AI – LLM Security Evaluation Platform",
    description="Enterprise-grade LLM security evaluation: prompt injection, jailbreaks, RCA, and mitigation.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "name": "CortexFlow AI",
        "version": "1.0.0",
        "docs": "/docs",
    }
