"""Define common functions."""

import logging
import os
from typing import Annotated

from fastapi import Depends
from pyxecm.otcs import OTCS
from pyxecm_customizer.k8s import K8s
from pyxecm_customizer.payload_list import PayloadList
from pyxecm_customizer.settings import Settings

from pyxecm_api.auth.functions import get_otcsticket
from pyxecm_api.settings import CustomizerAPISettings, api_settings

logger = logging.getLogger("pyxecm_api")

# Create a LOCK dict for singleton logs collection
LOGS_LOCK = {}
# Initialize the globel Payloadlist object
PAYLOAD_LIST = PayloadList(logger=logger)


def get_k8s_object() -> K8s:
    """Get an instance of a K8s object.

    Returns:
        K8s: Return a K8s object

    """

    return K8s(logger=logger, namespace=api_settings.namespace)


def get_otcs_object() -> OTCS:
    """Get an instance of a Content Server (OTCS) object.

    Returns:
        OTCS:
            Return a new OTCS object.

    """

    settings = Settings()

    otcs = OTCS(
        protocol=settings.otcs.url_backend.scheme,
        hostname=settings.otcs.url_backend.host,
        port=settings.otcs.url_backend.port,
        public_url=str(settings.otcs.url),
        username=settings.otcs.username,
        password=settings.otcs.password.get_secret_value(),
        user_partition=settings.otcs.partition,
        resource_name=settings.otcs.resource_name,
        base_path=settings.otcs.base_path,
        support_path=settings.otcs.support_path,
        download_dir=settings.otcs.download_dir,
        feme_uri=settings.otcs.feme_uri,
        logger=logger,
    )

    # Authenticate at Content Server:
    otcs.authenticate()

    return otcs


def get_otcs_object_from_otcsticket(otcs_ticket: Annotated[str, Depends(get_otcsticket)]) -> OTCS:
    """Get an instance of a Content Server (OTCS) object.

    Returns:
        OTCS:
            Return an OTCS object.

    """

    settings = Settings()

    # Create an OTCS object without defining the username and password:
    otcs = OTCS(
        # protocol=settings.otcs.url_backend.scheme,
        # hostname=settings.otcs.url_backend.host,
        # port=settings.otcs.url_backend.port,
        protocol=settings.otcs.url_frontend.scheme,
        hostname=settings.otcs.url_frontend.host,
        port=settings.otcs.url_frontend.port,
        public_url=str(settings.otcs.url),
        user_partition=settings.otcs.partition,
        resource_name=settings.otcs.resource_name,
        base_path=settings.otcs.base_path,
        support_path=settings.otcs.support_path,
        download_dir=settings.otcs.download_dir,
        feme_uri=settings.otcs.feme_uri,
        logger=logger,
    )

    # Instead set the OTCS authentication ticket directly:
    otcs._otcs_ticket = otcs_ticket  # noqa: SLF001

    return otcs


def get_settings() -> CustomizerAPISettings:
    """Get the API Settings object.

    Returns:
        CustomizerPISettings:
            Returns the API Settings.

    """

    return api_settings


def get_otcs_logs_lock() -> dict:
    """Get the Logs LOCK dict.

    Returns:
        The dict with all LOCKS for the logs

    """

    return LOGS_LOCK


def list_files_in_directory(directory: str) -> dict:
    """Recursively list files in a directory and return a nested JSON structure with URLs."""

    result = {}
    for root, dirs, files in os.walk(directory):
        # Sort directories and files alphabetically
        dirs.sort()
        files.sort()

        current_level = result
        path_parts = root.split(os.sep)
        relative_path = os.path.relpath(root, directory)
        for part in path_parts[len(directory.split(os.sep)) :]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
        for file in files:
            file_path = os.path.join(relative_path, file)
            current_level[file] = file_path

    return result
