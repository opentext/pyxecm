"""Define Models for the Maintenance Page Config."""

from pydantic import BaseModel


class MaintenanceModel(BaseModel):
    """Status object of the Maintenance Page."""

    enabled: bool
    title: str | None = ""
    text: str | None = ""
    footer: str | None = ""
