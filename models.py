from sqlalchemy import Column, Integer, String, Boolean, JSON, ForeignKey
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
        return {
            "id":            self.id,
            "user_id":       self.user_id,
            "target":        self.target,
            "type":          self.type,
            "typeLabel":     self.type_label,
            "score":         self.score,
            "status":        self.status,
            "vulns":         self.vulns,
            "cve":           self.cve,
            "date":          self.date,
            "results":       self.results or {},
            "issues":        self.issues or [],
            "conversations": self.conversations or [],
        }
