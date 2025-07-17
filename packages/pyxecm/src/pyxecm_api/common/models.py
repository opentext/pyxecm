"""Define common base Models."""

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
