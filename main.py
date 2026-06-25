from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine
from models import Base
from routers import scans, experts, messages, admin
from routers import telegram_liaison, telegram_webhook
from routers import auth as auth_router

# Crée toutes les tables au démarrage
Base.metadata.create_all(bind=engine)

app = FastAPI(title="CyberGuardian API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(scans.router)
app.include_router(experts.router)
app.include_router(messages.router)
app.include_router(admin.router)
app.include_router(telegram_liaison.router)
app.include_router(telegram_webhook.router)


@app.get("/")
def root():
    return {"status": "ok", "service": "CyberGuardian API", "version": "1.0.0"}
