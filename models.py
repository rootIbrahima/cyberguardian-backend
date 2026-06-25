from datetime import datetime
from sqlalchemy import Column, Integer, Float, String, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    email         = Column(String, unique=True, index=True, nullable=False)
    name          = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role          = Column(String, default="client")   # client | expert | admin
    is_active     = Column(Boolean, default=True)
    created_at    = Column(String)

    scans = relationship("Scan", back_populates="user", lazy="dynamic")


class Scan(Base):
    __tablename__ = "scans"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=True)
    target     = Column(String, nullable=False)
    type       = Column(String, nullable=False)        # domain | ip | url | github
    type_label = Column(String)
    score      = Column(Integer, nullable=True)
    status     = Column(String, default="completed")
    vulns      = Column(Integer, default=0)
    cve        = Column(Integer, default=0)
    date       = Column(String)
    results    = Column(JSON, default=dict)
    issues     = Column(JSON, default=list)
    conversations = Column(JSON, default=list)

    user = relationship("User", back_populates="scans")

    def to_dict(self) -> dict:
        # Les scans EASM antérieurs au score pondéré stockaient le score SSL /25 :
        # on les ramène à l'échelle /100 (même normalisation que calculate_score
        # quand seul le critère SSL est évalué).
        score = self.score
        if (self.type != "github" and score is not None
                and not (self.results or {}).get("score_detail")):
            score = round(score / 25 * 100)
        return {
            "id":            self.id,
            "user_id":       self.user_id,
            "target":        self.target,
            "type":          self.type,
            "typeLabel":     self.type_label,
            "score":         score,
            "status":        self.status,
            "vulns":         self.vulns,
            "cve":           self.cve,
            "date":          self.date,
            "results":       self.results or {},
            "issues":        self.issues or [],
            "conversations": self.conversations or [],
        }


class ExpertProfile(Base):
    __tablename__ = "expert_profiles"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    cni          = Column(String, nullable=False)
    level        = Column(String)                       # niveau d'études
    specialty    = Column(String)
    cni_file     = Column(String)                       # chemin du fichier téléversé
    diploma_file = Column(String)
    status       = Column(String, default="pending")    # pending | approved | rejected
    rating       = Column(Float, default=4.5)
    missions     = Column(Integer, default=0)
    price        = Column(Integer, default=150000)      # FCFA
    city         = Column(String, default="Dakar")
    color        = Column(String, default="#1F5C99")
    applied_at   = Column(String)                       # date de candidature (libellé)

    user = relationship("User")

    def to_card(self) -> dict:
        """Format attendu par ExpertCard.jsx (annuaire des experts)."""
        return {
            "id":        self.id,
            "user_id":   self.user_id,
            "name":      self.user.name if self.user else "",
            "specialty": self.specialty,
            "rating":    self.rating or 4.5,
            "missions":  self.missions or 0,
            "price":     self.price or 150000,
            "city":      self.city or "Dakar",
            "color":     self.color or "#1F5C99",
        }

    def to_pending(self) -> dict:
        """Format attendu par AdminPage.jsx (candidatures en attente)."""
        return {
            "id":        self.id,
            "name":      self.user.name if self.user else "",
            "cni":       self.cni,
            "level":     self.level,
            "specialty": self.specialty,
            "date":      self.applied_at,
        }


class Conversation(Base):
    __tablename__ = "conversations"

    id               = Column(Integer, primary_key=True, index=True)
    client_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    expert_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject          = Column(String, nullable=False)    # cible du scan concerné
    level            = Column(Integer, default=1)        # 1 demande | 2 mission | 3 contrat
    mission_start    = Column(String, nullable=True)     # ISO — début de l'accès 48h (niveau 3)
    rating           = Column(Integer, nullable=True)    # note du client (1-5) après mission
    client_last_read = Column(String, nullable=True)     # ISO — pour le compteur non-lus
    expert_last_read = Column(String, nullable=True)
    created_at       = Column(String)

    client   = relationship("User", foreign_keys=[client_id])
    expert   = relationship("User", foreign_keys=[expert_id])
    messages = relationship("Message", back_populates="conversation",
                            order_by="Message.id", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id              = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    sender_id       = Column(Integer, ForeignKey("users.id"), nullable=True)   # NULL = message système
    text            = Column(String, nullable=False)
    created_at      = Column(String)                     # ISO

    conversation = relationship("Conversation", back_populates="messages")


class TelegramLink(Base):
    """Liaison vérifiée entre un compte CyberGuardian et un compte Telegram.
    Telegram identifie par chat_id (pas par numéro). Un seul compte Telegram
    par utilisateur, un seul utilisateur par chat_id."""
    __tablename__ = "telegram_links"

    id        = Column(Integer, primary_key=True, index=True)
    user_id   = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    chat_id   = Column(String, unique=True, nullable=False, index=True)
    linked_at = Column(DateTime, default=datetime.utcnow)
    actif     = Column(Boolean, default=True)

    user = relationship("User")


class TelegramCode(Base):
    """Code de liaison à usage unique (CG-XXXXXX), valable 5 minutes."""
    __tablename__ = "telegram_codes"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    code       = Column(String, unique=True, nullable=False, index=True)
    expire_at  = Column(DateTime, nullable=False)
    utilise    = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class TelegramMessage(Base):
    """Historique des échanges du bot, pour donner une mémoire de conversation
    à l'assistant (les questions ne sont plus traitées isolément)."""
    __tablename__ = "telegram_messages"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    role       = Column(String, nullable=False)   # 'user' | 'assistant'
    content    = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
