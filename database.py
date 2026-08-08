import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Le .env est chargé ici plutôt que de compter sur un import préalable de
# config.py : ce module est aussi importé directement par seed.py et par les
# scripts utilitaires, qui utiliseraient sinon les valeurs par défaut sans
# prévenir, et se connecteraient à une autre base que l'application.
load_dotenv()

# Valeurs par défaut du poste de développement, surchargées par .env
DB_USER     = os.getenv("DB_USER",     "cguser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "cg2026")
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = os.getenv("DB_PORT",     "5432")
DB_NAME     = os.getenv("DB_NAME",     "cyberguardian")

DATABASE_URL = (
    f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # vérifie la connexion avant chaque requête
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
