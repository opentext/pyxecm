"""Settings for Customizer execution."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

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
        description="Path to a directory of payload files. All files in this directory will be loaded in alphabetical order and dependencies will be added automatically on the previous object. So all payload in this folder will be processed sequentially in alphabetical order.",
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

    upload_folder: str = Field(default=os.path.join(tempfile.gettempdir(), "upload"), description="Folder for uploads")

    upload_key: str = Field(default=str(uuid.uuid4()), description="Upload key for the Logs")

    upload_url: str = Field(
        default="http://customizer:8000/api/v1/otcs/logs/upload", description="Upload URL for the Logs"
    )

    ws_terminal: bool = Field(
        default=False,
        description="Enable the Websocket Terminal endpoint",
    )

    pod_access: bool | None = Field(
        default=None,
        description="Enable the pod endpoints: list the pods of the namespace, browse, download and upload their "
        "files and read their logs - and the ConfigMaps, Secrets and workloads of the namespace: show and change "
        "them, restart workloads. Follows ws_terminal when not set.",
    )

    pod_upload_max_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        description="Largest file that can be uploaded into a pod (in bytes).",
    )

    pod_transfer_concurrency: int = Field(
        default=4,
        description="Number of downloads and uploads from and to pods that can run at the same time.",
    )

    pod_log_spool_dir: str = Field(
        default=os.path.join(tempfile.gettempdir(), "podlogs"),
        description="Folder for the copies of the pod logs that are looked at.",
    )

    pod_log_max_bytes: int = Field(
        default=1024 * 1024 * 1024,
        description="Largest copy of a pod log (in bytes). Following the log stops when it is reached.",
    )

    pod_log_idle_seconds: int = Field(
        default=900,
        description="A copy of a pod log that nobody read for this long (in seconds) is stopped and deleted.",
    )

    pod_log_max_sessions: int = Field(
        default=20,
        description="Number of pod logs that can be followed at the same time.",
    )

    model_config = SettingsConfigDict(env_prefix="CUSTOMIZER_")

    def __init__(self, **data: any) -> None:
        """Class initializer."""

        super().__init__(**data)
        if self.otds_url is None:
            self.otds_url = f"{self.otds_protocol}://{self.otds_host}:{self.otds_port}"
        if self.pod_access is None:
            self.pod_access = self.ws_terminal


# Create Instance of settings
api_settings = CustomizerAPISettings()
