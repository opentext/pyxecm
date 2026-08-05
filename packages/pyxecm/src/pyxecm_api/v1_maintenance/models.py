"""Define Models for the Maintenance Page Config."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from pydantic import BaseModel


class MaintenanceModel(BaseModel):
    """Status object of the Maintenance Page."""

    enabled: bool
    title: str | None = ""
    text: str | None = ""
    footer: str | None = ""
