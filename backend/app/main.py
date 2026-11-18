import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyze import router as analyze_router
from app.api.report import router as report_router

app = FastAPI(title="MailShield AI", version="0.1.0")

_cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in _cors_origins.split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(report_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "mailshield-ai", "version": "0.1.0"}
