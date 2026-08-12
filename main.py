from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import FRONTEND_URL, signaler_incoherences
from database import engine
from models import Base
from routers import scans, experts, messages, admin, notifications, statistiques
from routers import telegram_liaison, telegram_webhook, github_oauth
from routers import auth as auth_router
from services.prechauffage import prechauffer_modele

# Crée toutes les tables au démarrage
Base.metadata.create_all(bind=engine)

app = FastAPI(title="CyberGuardian API", version="1.0.0")

# Origines autorisées : les deux ports de développement, plus FRONTEND_URL pour
# la production. Servi par le même nginx que l'API, le frontend partage son
# origine et n'a alors pas besoin de CORS ; l'entrée reste utile si les deux
# sont un jour séparés sur des domaines distincts.
origines = ["http://localhost:3000", "http://localhost:5173"]
if FRONTEND_URL and FRONTEND_URL not in origines:
    origines.append(FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origines,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(scans.router)
app.include_router(experts.router)
app.include_router(messages.router)
app.include_router(admin.router)
app.include_router(notifications.router)
app.include_router(statistiques.router)
app.include_router(telegram_liaison.router)
app.include_router(telegram_webhook.router)
app.include_router(github_oauth.router)


@app.on_event("startup")
def demarrage():
    # Une valeur de développement laissée dans le .env du serveur ne se voyait
    # jusqu'ici qu'à l'usage, quand un client butait sur la fonction cassée.
    signaler_incoherences()

    # Charge le modèle en mémoire GPU sans bloquer le démarrage : le premier
    # client n'attend pas les quinze secondes de chargement.
    prechauffer_modele()


@app.get("/")
def root():
    return {"status": "ok", "service": "CyberGuardian API", "version": "1.0.0"}
