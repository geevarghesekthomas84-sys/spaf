"""
Typed models for multi-engagement workspaces and RBAC.

An **engagement** is an isolated workspace: its own scope file, its own audit
trail, its own storage directory for reports, and an optional *signed
authorization* (the written go-ahead that makes active testing lawful). A
**principal** is an API identity with a **role** and a set of engagements it may
touch. Roles are ordered — a check is "principal.role >= required".
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import List, Optional

from pydantic import BaseModel, Field


class Role(IntEnum):
    """Ordered RBAC roles — higher value grants everything a lower one can do."""
    VIEWER = 10      # read-only: status, scope, findings, audit
    OPERATOR = 20    # + launch scans / active agent runs within allowed engagements
    LEAD = 30        # + manage scope, create engagements, sign authorizations

    @classmethod
    def parse(cls, value: "str | int | Role") -> "Role":
        if isinstance(value, Role):
            return value
        if isinstance(value, int):
            return cls(value)
        name = str(value).strip().upper()
        if name not in cls.__members__:
            raise ValueError(f"unknown role '{value}'. Valid: viewer, operator, lead.")
        return cls[name]

    @property
    def label(self) -> str:
        return self.name.lower()


class Principal(BaseModel):
    """An authenticated identity. The raw key is never stored here."""
    key_id: str = Field(description="short, non-secret id for the key (hash prefix)")
    name: str = "anonymous"
    role: Role = Role.VIEWER
    # Engagement ids this principal may access; ["*"] means all.
    engagements: List[str] = Field(default_factory=lambda: ["*"])

    def can_access(self, engagement_id: str) -> bool:
        return "*" in self.engagements or engagement_id in self.engagements

    def has_role(self, required: Role) -> bool:
        return self.role >= required


class EngagementAuthorization(BaseModel):
    """A signed record that active testing of an engagement was authorized."""
    authorized_by: str
    authorized_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    scope_hash: str = ""
    signature: str = ""

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or datetime.utcnow()) >= self.expires_at


class RetentionPolicy(BaseModel):
    """How long engagement results are kept. days=0 means keep indefinitely."""
    days: int = 0

    def cutoff(self, now: Optional[datetime] = None) -> Optional[datetime]:
        if self.days <= 0:
            return None
        from datetime import timedelta
        return (now or datetime.utcnow()) - timedelta(days=self.days)


class Engagement(BaseModel):
    """An isolated workspace: scope + audit + storage + authorization."""
    id: str
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "local"
    scope_file: str
    audit_path: str
    storage_dir: str
    authorization: Optional[EngagementAuthorization] = None
    retention: RetentionPolicy = Field(default_factory=RetentionPolicy)

    @property
    def authorized(self) -> bool:
        return self.authorization is not None and not self.authorization.is_expired()
