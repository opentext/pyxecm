"""Models for FastAPI."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from pydantic import BaseModel


class User(BaseModel):
    """Model for users authenticated by OTDS."""

    id: str
    full_name: str | None = None
    groups: list[str] | None = None
    is_admin: bool = False
    is_sysadmin: bool = False
    is_tenantadmin: bool = False
