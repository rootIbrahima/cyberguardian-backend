"""
Mise à niveau du schéma sur une base déjà en service.

create_all() de SQLAlchemy crée les tables absentes mais n'ajoute jamais une
colonne à une table existante : une base en production resterait en arrière.
Ce script comble l'écart. Il est idempotent, le relancer ne fait rien de plus.

Usage : python migrer.py
"""

from sqlalchemy import inspect, text

from database import engine, SessionLocal
from models import Base, Conversation, Scan


def _colonnes(table: str) -> set[str]:
    inspecteur = inspect(engine)
    if table not in inspecteur.get_table_names():
        return set()
    return {c["name"] for c in inspecteur.get_columns(table)}


def ajouter_scan_id() -> bool:
    """Lien direct conversation → scan, à la place de la comparaison de chaînes."""
    if "scan_id" in _colonnes("conversations"):
        print("  [=] conversations.scan_id déjà présente")
        return False
    with engine.begin() as cx:
        cx.execute(text(
            "ALTER TABLE conversations "
            "ADD COLUMN scan_id INTEGER REFERENCES scans(id)"
        ))
    print("  [+] conversations.scan_id ajoutée")
    return True


def ajouter_alertes_email() -> bool:
    """Préférence d'alerte par e-mail, active pour les comptes déjà en base."""
    if "alertes_email" in _colonnes("users"):
        print("  [=] users.alertes_email déjà présente")
        return False
    with engine.begin() as cx:
        cx.execute(text(
            "ALTER TABLE users "
            "ADD COLUMN alertes_email BOOLEAN NOT NULL DEFAULT TRUE"
        ))
    print("  [+] users.alertes_email ajoutée")
    return True


def rattacher_conversations() -> int:
    """Renseigne scan_id pour les conversations créées avant la colonne, en
    rejouant l'ancienne règle : dernier scan du client sur la cible du sujet."""
    db = SessionLocal()
    rattachees = 0
    try:
        for conv in db.query(Conversation).filter(Conversation.scan_id.is_(None)).all():
            scan = (
                db.query(Scan)
                .filter(Scan.user_id == conv.client_id, Scan.target == conv.subject)
                .order_by(Scan.id.desc())
                .first()
            )
            if scan:
                conv.scan_id = scan.id
                rattachees += 1
        db.commit()
    finally:
        db.close()
    print(f"  [~] {rattachees} conversation(s) rattachée(s) à leur scan")
    return rattachees


if __name__ == "__main__":
    print("=== Mise à niveau du schéma CyberGuardian ===\n")
    # Crée les tables absentes, dont message_attachments
    Base.metadata.create_all(bind=engine)
    print("  [=] tables manquantes créées le cas échéant")
    ajouter_scan_id()
    ajouter_alertes_email()
    rattacher_conversations()
    print("\nBase à jour.")
