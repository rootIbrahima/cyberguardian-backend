"""
Initialise la base de données avec les comptes par défaut.
Usage : python seed.py
"""
from datetime import datetime, timezone
from database import engine, SessionLocal
from models import Base, User
from auth import hash_password

USERS = [
    {"email": "admin@cyberguardian.sn",  "name": "Admin CyberGuardian", "password": "Admin2026!", "role": "admin"},
    {"email": "expert@cyberguardian.sn", "name": "Mamadou Diallo",      "password": "Expert2026!", "role": "expert"},
    {"email": "ibrahima.ly@ec2lt.sn",    "name": "Ibrahima LY",         "password": "Client2026!", "role": "client"},
]


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    created = 0
    try:
        for u in USERS:
            exists = db.query(User).filter(User.email == u["email"]).first()
            if not exists:
                user = User(
                    email         = u["email"],
                    name          = u["name"],
                    password_hash = hash_password(u["password"]),
                    role          = u["role"],
                    created_at    = datetime.now(timezone.utc).isoformat(),
                )
                db.add(user)
                created += 1
                print(f"  [+] {u['role']:8s} {u['email']} — mot de passe : {u['password']}")
            else:
                print(f"  [=] {u['role']:8s} {u['email']} — déjà existant")
        db.commit()
        print(f"\n{created} compte(s) créé(s). Base prête.")
    finally:
        db.close()


if __name__ == "__main__":
    print("=== Seed CyberGuardian ===\n")
    seed()
