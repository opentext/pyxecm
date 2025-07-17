"""Define Models for Payload."""

from typing import Any

from pydantic import BaseModel


class PayloadStats(BaseModel):
    """Defines PayloadStats Model."""

    count: int = 0
    status: dict = {}
    logs: dict = {}


class PayloadListItem(BaseModel):
    """Defines PayloadListItem Model."""

    index: int
    name: str
    filename: str
    dependencies: list
    logfile: str
    status: str
    enabled: bool
    git_url: str | None
    loglevel: str = "INFO"
    start_time: Any | None
    stop_time: Any | None
    duration: Any | None
    log_debug: int = 0
    log_info: int = 0
    log_warning: int = 0
    log_error: int = 0
    log_critical: int = 0
    customizer_settings: dict = {}


class PayloadListItems(BaseModel):
    """Defines PayloadListItems Model."""

    stats: PayloadStats
    results: list[PayloadListItem]


class UpdatedPayloadListItem(BaseModel):
    """Defines UpdatedPayloadListItem Model."""

    message: str
    payload: PayloadListItem
    updated_fields: dict
