"""
Initialise la base de données avec les comptes par défaut
et l'annuaire d'experts validés.

Usage :
    python seed.py                        crée les comptes manquants
    python seed.py --maj-mots-de-passe    réapplique aussi les mots de passe
                                          aux comptes déjà existants

Les mots de passe viennent de .env (SEED_*_PASSWORD) et jamais de ce fichier :
le dépôt est public, une valeur écrite ici serait lisible par tout le monde.
Sans valeur dans .env, un mot de passe aléatoire est tiré et affiché une fois.
"""
import secrets
import sys
from datetime import datetime, timezone

from config import SEED_ADMIN_PASSWORD, SEED_CLIENT_PASSWORD, SEED_EXPERT_PASSWORD
from database import engine, SessionLocal
from models import Base, User, ExpertProfile
from auth import hash_password

USERS = [
    {"email": "admin@cyberguardian.sn",  "name": "Admin CyberGuardian", "role": "admin"},
    {"email": "expert@cyberguardian.sn", "name": "Mamadou Diallo",      "role": "expert"},
    {"email": "ibrahima.ly@ec2lt.sn",    "name": "Ibrahima LY",         "role": "client"},
    {"email": "fatou.sow@cyberguardian.sn",      "name": "Fatou Sow",       "role": "expert"},
    {"email": "ousmane.ba@cyberguardian.sn",     "name": "Ousmane Ba",      "role": "expert"},
    {"email": "aissatou.ndiaye@cyberguardian.sn", "name": "Aissatou Ndiaye", "role": "expert"},
]

# Profils des experts validés (annuaire de démonstration)
EXPERT_PROFILES = {
    "expert@cyberguardian.sn":           {"cni": "1 789 1985 0 0421", "level": "Master 2",  "specialty": "DNS & Email",      "rating": 4.8, "missions": 47, "price": 150000, "city": "Dakar",       "color": "#1F5C99"},
    "fatou.sow@cyberguardian.sn":        {"cni": "2 912 1992 0 0183", "level": "Ingénieur", "specialty": "Sécurité Web",     "rating": 4.6, "missions": 32, "price": 200000, "city": "Thiès",       "color": "#10B981"},
    "ousmane.ba@cyberguardian.sn":       {"cni": "1 645 1988 0 0752", "level": "Doctorat",  "specialty": "Audit sécurité",   "rating": 4.9, "missions": 68, "price": 180000, "city": "Dakar",       "color": "#F59E0B"},
    "aissatou.ndiaye@cyberguardian.sn":  {"cni": "2 304 1990 0 0617", "level": "Master 2",  "specialty": "Réseau & Pentest", "rating": 4.7, "missions": 41, "price": 160000, "city": "Saint-Louis", "color": "#8B5CF6"},
}


def _mots_de_passe() -> tuple[dict[str, str], set[str]]:
    """Mot de passe à appliquer par rôle, et rôles dont la valeur a été tirée
    au sort faute d'entrée dans .env. Un tirage aléatoire vaut mieux qu'une
    valeur par défaut : celle-ci finirait dans le dépôt et serait donc connue."""
    configures = {
        "admin":  SEED_ADMIN_PASSWORD,
        "expert": SEED_EXPERT_PASSWORD,
        "client": SEED_CLIENT_PASSWORD,
    }
    tires = {role for role, valeur in configures.items() if not valeur}
    return (
        {role: valeur or secrets.token_urlsafe(12) for role, valeur in configures.items()},
        tires,
    )


def seed(maj_mots_de_passe: bool = False):
    Base.metadata.create_all(bind=engine)
    par_role, tires = _mots_de_passe()
    db = SessionLocal()
    crees = 0
    mis_a_jour = 0
    try:
        for u in USERS:
            mot_de_passe = par_role[u["role"]]
            # Un mot de passe tiré au sort n'est affiché qu'une fois : sans cela
            # il serait perdu. Ceux de .env ne sont jamais réécrits en console.
            trace = f", mot de passe : {mot_de_passe}" if u["role"] in tires else ""

            existant = db.query(User).filter(User.email == u["email"]).first()
            if not existant:
                db.add(User(
                    email         = u["email"],
                    name          = u["name"],
                    password_hash = hash_password(mot_de_passe),
                    role          = u["role"],
                    created_at    = datetime.now(timezone.utc).isoformat(),
                ))
                crees += 1
                print(f"  [+] {u['role']:8s} {u['email']}{trace}")
            elif maj_mots_de_passe:
                existant.password_hash = hash_password(mot_de_passe)
                mis_a_jour += 1
                print(f"  [~] {u['role']:8s} {u['email']}, mot de passe réappliqué{trace}")
            else:
                print(f"  [=] {u['role']:8s} {u['email']}, déjà existant")
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

        print(f"\n{crees} compte(s) créé(s), {mis_a_jour} mot(s) de passe réappliqué(s). Base prête.")
        if tires:
            roles = ", ".join(sorted(tires))
            print(f"\n  Mot de passe tiré au sort pour : {roles}.")
            print("  Notez-le maintenant, il n'est pas conservé. Pour en fixer un,")
            print("  renseignez SEED_ADMIN_PASSWORD / SEED_EXPERT_PASSWORD /")
            print("  SEED_CLIENT_PASSWORD dans backend/.env.")
    finally:
        db.close()


if __name__ == "__main__":
    print("=== Seed CyberGuardian ===\n")
    seed(maj_mots_de_passe="--maj-mots-de-passe" in sys.argv)
