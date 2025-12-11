"""Models for FastAPI."""

from pydantic import BaseModel


class User(BaseModel):
    """Model for users authenticated by OTDS."""

    id: str
    full_name: str | None = None
    groups: list[str] | None = None
    is_admin: bool = False
    is_sysadmin: bool = False
    is_tenantadmin: bool = False
