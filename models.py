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
    # Alertes par e-mail vers l'adresse du compte. Actif par défaut : sur une
    # plateforme de surveillance, un client qui ignore qu'un secret a fuité est
    # moins bien servi qu'un client qui reçoit un message de trop.
    alertes_email = Column(Boolean, default=True, nullable=False, server_default="true")

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
    date       = Column(String)                        # libellé d'affichage : « 27 jul. 2026, 12:09 »
    created_at = Column(String, index=True)            # ISO, comparable, sert au quota journalier
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
    mission_start    = Column(String, nullable=True)     # ISO, début de l'accès 48h (niveau 3)
    rating           = Column(Integer, nullable=True)    # note du client (1-5) après mission
    scan_id          = Column(Integer, ForeignKey("scans.id"), nullable=True)
    client_last_read = Column(String, nullable=True)     # ISO, pour le compteur non-lus
    expert_last_read = Column(String, nullable=True)
    created_at       = Column(String)

    client   = relationship("User", foreign_keys=[client_id])
    expert   = relationship("User", foreign_keys=[expert_id])
    messages = relationship("Message", back_populates="conversation",
                            order_by="Message.id", cascade="all, delete-orphan")
    scan     = relationship("Scan", foreign_keys=[scan_id])


class Message(Base):
    __tablename__ = "messages"

    id              = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    sender_id       = Column(Integer, ForeignKey("users.id"), nullable=True)   # NULL = message système
    text            = Column(String, nullable=False)
    created_at      = Column(String)                     # ISO

    conversation = relationship("Conversation", back_populates="messages")
    piece_jointe = relationship("MessageAttachment", back_populates="message",
                                uselist=False, cascade="all, delete-orphan")


class MessageAttachment(Base):
    """Pièce jointe d'un message : capture, extrait de journal, configuration.
    Table séparée plutôt que colonnes sur « messages » : la très grande majorité
    des messages n'en portent pas, et une nouvelle table se crée toute seule au
    démarrage sans toucher aux lignes existantes."""

    __tablename__ = "message_attachments"

    id         = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    nom        = Column(String, nullable=False)    # nom d'origine, affiché au destinataire
    type_mime  = Column(String, nullable=False)
    taille     = Column(Integer, nullable=False)   # octets
    chemin     = Column(String, nullable=False)    # emplacement sur disque, jamais exposé

    message = relationship("Message", back_populates="piece_jointe")


class Notification(Base):
    """Notification persistante : reste visible (marquée lue) après consultation,
    contrairement à un simple compteur dérivé d'une requête live. Une ligne par
    événement (nouveau message, mission acceptée, contrat signé, candidature
    expert, remédiation proposée...)."""
    __tablename__ = "notifications"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    type       = Column(String, nullable=False)    # message | mission_level | contract | expert_pending | expert_decision | remediation
    title      = Column(String, nullable=False)
    body       = Column(String)
    link       = Column(String)                    # route frontend à ouvrir au clic
    read_at    = Column(String, nullable=True)      # ISO, NULL = non lue
    created_at = Column(String)                     # ISO

    # Suivi de la remise sur les canaux externes. L'envoi était jusqu'ici sans
    # trace : une exception était écrite dans la sortie du serveur et oubliée,
    # si bien qu'un Telegram délié ou un SMTP en refus ne se voyait nulle part.
    # NULL tant que le fil d'envoi n'a pas rendu son verdict.
    remise_etat   = Column(String, nullable=True)   # ok | echec | sans_canal
    remise_le     = Column(String, nullable=True)   # ISO
    remise_erreur = Column(String, nullable=True)

    user = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "type":      self.type,
            "title":     self.title,
            "body":      self.body,
            "link":      self.link,
            "read":      self.read_at is not None,
            "createdAt": self.created_at,
        }


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


class GitHubConnection(Base):
    """Autorisation OAuth d'un client : le jeton permet à l'agent d'ouvrir une
    Pull Request de correction sur ses dépôts (portée public_repo, moindre
    privilège). Le backend reste maître ; l'agent ne pousse jamais en direct."""
    __tablename__ = "github_connections"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    access_token = Column(String, nullable=False)
    github_login = Column(String)
    connected_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class RepoAutorisation(Base):
    """Consentement explicite et révocable : le client autorise la correction
    assistée d'un dépôt précis. C'est la trace technique sur laquelle l'admin
    s'appuie avant de déclencher l'agent."""
    __tablename__ = "repo_autorisations"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    repo_slug   = Column(String, nullable=False, index=True)   # owner/repo
    actif       = Column(Boolean, default=True)
    autorise_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class SurveillanceCible(Base):
    """Actif qu'un client demande à faire réanalyser périodiquement.

    C'est ce qui sépare un scanner d'une plateforme de surveillance : sans
    passage régulier, un port qui s'ouvre ou un certificat qui approche de son
    terme n'est découvert qu'au prochain scan manuel, c'est-à-dire souvent
    jamais. L'alerte, elle, n'a rien à réinventer : le scan planifié emprunte le
    même chemin que le scan manuel et déclenche la même comparaison."""
    __tablename__ = "surveillances"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target     = Column(String, nullable=False)
    asset_type = Column(String, nullable=False)          # domain | ip | url | github
    frequence  = Column(String, default="hebdomadaire")  # quotidienne | hebdomadaire
    actif      = Column(Boolean, default=True, nullable=False)
    cree_le    = Column(String)                          # ISO
    # Date du prochain passage, en ISO. C'est elle que le planificateur
    # interroge : conserver la date du dernier passage obligerait à recalculer
    # l'échéance à chaque tour, et à la recalculer partout de la même façon.
    prochain_passage = Column(String, index=True)
    dernier_passage  = Column(String)
    dernier_scan_id  = Column(Integer, ForeignKey("scans.id"))

    user = relationship("User")

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "target":           self.target,
            "asset_type":       self.asset_type,
            "frequence":        self.frequence,
            "actif":            self.actif,
            "prochain_passage": self.prochain_passage,
            "dernier_passage":  self.dernier_passage,
            "dernier_scan_id":  self.dernier_scan_id,
        }
