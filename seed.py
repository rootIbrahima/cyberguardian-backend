"""
Initialise la base de données avec les comptes par défaut
et l'annuaire d'experts validés.
Usage : python seed.py
"""
from datetime import datetime, timezone
from database import engine, SessionLocal
from models import Base, User, ExpertProfile
from auth import hash_password

USERS = [
    {"email": "admin@cyberguardian.sn",  "name": "Admin CyberGuardian", "password": "Admin2026!", "role": "admin"},
    {"email": "expert@cyberguardian.sn", "name": "Mamadou Diallo",      "password": "Expert2026!", "role": "expert"},
    {"email": "ibrahima.ly@ec2lt.sn",    "name": "Ibrahima LY",         "password": "Client2026!", "role": "client"},
    {"email": "fatou.sow@cyberguardian.sn",      "name": "Fatou Sow",       "password": "Expert2026!", "role": "expert"},
    {"email": "ousmane.ba@cyberguardian.sn",     "name": "Ousmane Ba",      "password": "Expert2026!", "role": "expert"},
    {"email": "aissatou.ndiaye@cyberguardian.sn", "name": "Aissatou Ndiaye", "password": "Expert2026!", "role": "expert"},
]

# Profils des experts validés (annuaire de démonstration)
EXPERT_PROFILES = {
    "expert@cyberguardian.sn":           {"cni": "1 789 1985 0 0421", "level": "Master 2",  "specialty": "DNS & Email",      "rating": 4.8, "missions": 47, "price": 150000, "city": "Dakar",       "color": "#1F5C99"},
    "fatou.sow@cyberguardian.sn":        {"cni": "2 912 1992 0 0183", "level": "Ingénieur", "specialty": "Sécurité Web",     "rating": 4.6, "missions": 32, "price": 200000, "city": "Thiès",       "color": "#10B981"},
    "ousmane.ba@cyberguardian.sn":       {"cni": "1 645 1988 0 0752", "level": "Doctorat",  "specialty": "Audit sécurité",   "rating": 4.9, "missions": 68, "price": 180000, "city": "Dakar",       "color": "#F59E0B"},
    "aissatou.ndiaye@cyberguardian.sn":  {"cni": "2 304 1990 0 0617", "level": "Master 2",  "specialty": "Réseau & Pentest", "rating": 4.7, "missions": 41, "price": 160000, "city": "Saint-Louis", "color": "#8B5CF6"},
}


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

        for email, p in EXPERT_PROFILES.items():
            user = db.query(User).filter(User.email == email).first()
            if not user:
                continue
            exists = db.query(ExpertProfile).filter(ExpertProfile.user_id == user.id).first()
            if not exists:
                db.add(ExpertProfile(
                    user_id    = user.id,
                    status     = "approved",
                    applied_at = "01 jun. 2026",
                    **p,
                ))
                print(f"  [+] profil expert validé : {user.name} ({p['specialty']})")
        db.commit()
        print(f"\n{created} compte(s) créé(s). Base prête.")
    finally:
        db.close()


if __name__ == "__main__":
    print("=== Seed CyberGuardian ===\n")
    seed()
