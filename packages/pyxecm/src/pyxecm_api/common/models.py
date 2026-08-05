"""Define common base Models."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from typing import Any

from pydantic import BaseModel


class CustomizerStatus(BaseModel):
    """Define Model for Customizer Status."""

    version: int = 2
    customizer_duration: Any | None
    customizer_end_time: Any | None
    customizer_start_time: Any | None
    status_details: dict
    status: str = "Stopped"
    debug: int = 0
    info: int = 0
    warning: int = 0
    error: int = 0
    critical: int = 0
