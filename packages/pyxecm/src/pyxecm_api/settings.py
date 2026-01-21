"""Settings for Customizer execution."""

import os
import tempfile
import uuid
from typing import Literal

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


## Customzer Settings
class CustomizerAPISettings(BaseSettings):
    """Settings for the Customizer API."""

    title: str = Field(default="Customizer API", description="Name of the API Service")
    description: str = Field(
        default="API provided by [pyxecm](https://github.com/opentext/pyxecm). The documentation for the payload syntax can be found [here](https://opentext.github.io/pyxecm/payload-syntax/).",
        description="Descriptive text on the SwaggerUI page.",
    )

    api_key: str | None = Field(
        default=None,
        description="Optional API KEY that can be specified that has access to the Customizer API, bypassing the OTDS authentication.",
    )
    bind_address: str | list[str] = Field(
        default=["::", "0.0.0.0"],  # noqa: S104
        description="Interface to bind the Customizer API. Supports IPv4, IPv6",
    )
    bind_port: int = Field(default=8000, description="Port to bind the Customizer API to")
    workers: int = Field(default=1, description="Number of workers to use for the API background tasks")
    root_path: str = Field(default="", description="Root path for the Customizer API")
    openapi_url: str = Field(default="/api/openapi.json", description="OpenAPI URL")
    reload: bool = Field(default=False, description="Enable or disable the autoreload feature")

    concurrent_payloads: int = Field(
        default=3, description="Maximum number of concurrent payloads that are executed at the same time."
    )
    import_payload: bool = Field(default=False)
    payload: str = Field(
        default="/payload/payload.yml.gz.b64",
        description="Path to a single payload file to be loaded.",
    )
    payload_dir: str = Field(
        default="/payload-external/",
        description="Path to a directory of payload files. All files in this directory will be loaded in alphabetical order and dependencies will be added automatically on the previous object. So all payload in this folder will be processed sequentially in alphabetical oder.",
    )
    payload_dir_optional: str = Field(
        default="/payload-optional/",
        description="Path of payload files to be loaded. No additional logic for dependencies will be applied, they need to be managed within the payloadSettings section of each payload. See -> payloadOptions in the Payload Syntax documentation.",
    )

    temp_dir: str = Field(
        default=os.path.join(tempfile.gettempdir(), "customizer"),
        description="location of the temp folder. Used for temporary files during the payload execution",
    )

    loglevel: Literal["INFO", "DEBUG", "WARNING", "ERROR"] = "INFO"
    logfolder: str = Field(
        default=os.path.join(tempfile.gettempdir(), "customizer"),
        description="Logfolder for Customizer logfiles",
    )
    logfile: str = Field(
        default="customizer.log",
        description="Logfile for Customizer API. This logfile also contains the execution of every payload.",
    )

    namespace: str = Field(
        default="default",
        description="Namespace to use for otxecm resource lookups",
    )

    maintenance_page: bool = Field(
        default=True,
        description="Start the Maintenance Page server.",
    )

    maintenance_mode: bool = Field(
        default=False,
        description="Automatically enable and disable the maintenance mode during payload deployments.",
    )

    trusted_origins: list[str] = Field(
        default=[
            "http://localhost",
            "http://localhost:5173",
            "http://localhost:8080",
            "https://manager.develop.terrarium.cloud",
            "https://manager.terrarium.cloud",
        ],
    )

    otds_protocol: str = Field(default="http", alias="OTDS_PROTOCOL")
    otds_host: str = Field(default="otds", alias="OTDS_HOSTNAME")
    otds_port: int = Field(default=80, alias="OTDS_SERVICE_PORT_OTDS")
    otds_url: str | None = Field(default=None, alias="OTDS_URL")

    metrics: bool = Field(
        default=True,
        description="Enable or disable the /metrics endpoint for Prometheus",
    )

    victorialogs_host: str = Field(
        default="",
        description="Hostname of the VictoriaLogs Server",
    )
    victorialogs_port: int = Field(
        default=9428,
        description="Port of the VictoriaLogs Server",
    )

    csai: bool = Field(
        default=False,
        description="Enable the CSAI integration",
    )

    csai_prefix: str = Field(
        default="csai",
        description="Prefix for the CSAI",
    )

    upload_folder: str = Field(default=os.path.join(tempfile.gettempdir(), "upload"), description="Folder for uploads")

    upload_key: str = Field(default=str(uuid.uuid4()), description="Upload key for the Logs")

    upload_url: str = Field(
        default="http://customizer:8000/api/v1/otcs/logs/upload", description="Upload URL for the Logs"
    )

    ws_terminal: bool = Field(
        default=False,
        description="Enable the Websocket Terminal endpoint",
    )

    model_config = SettingsConfigDict(env_prefix="CUSTOMIZER_")

    def __init__(self, **data: any) -> None:
        """Class initializer."""

        super().__init__(**data)
        if self.otds_url is None:
            self.otds_url = f"{self.otds_protocol}://{self.otds_host}:{self.otds_port}"


# Create Instance of settings
api_settings = CustomizerAPISettings()
