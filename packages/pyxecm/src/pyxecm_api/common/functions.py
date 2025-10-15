"""Define common functions."""

import logging
import os
import time
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends
from pyxecm.otca import OTCA
from pyxecm.otcs import OTCS
from pyxecm_customizer import K8s, PayloadList, Settings
from pyxecm_customizer.knowledge_graph import KnowledgeGraph

from pyxecm_api.auth.functions import get_otcsticket
from pyxecm_api.settings import CustomizerAPISettings, api_settings

logger = logging.getLogger("pyxecm_api")

# Create a LOCK dict for singleton logs collection
LOGS_LOCK = {}
# Initialize the globel Payloadlist object
PAYLOAD_LIST = PayloadList(logger=logger)

# This object is initialized in the build_graph() function below.
KNOWLEDGEGRAPH_OBJECT: KnowledgeGraph = None

# The following ontology is fed into the knowledge graph tool description.
# This is currently hard-coded. Ideally this should be derived from OTCM
# or provided via a payload file:

KNOWLEDGEGRAPH_ONTOLOGY = {
    ("Vendor", "Material", "child"): ["offers", "supplies", "provides"],
    ("Vendor", "Purchase Order", "child"): ["supplies", "provides"],
    ("Vendor", "Purchase Contract", "child"): ["signs", "owns"],
    ("Material", "Vendor", "parent"): ["is supplied by"],
    ("Purchase Order", "Material", "child"): ["includes", "is part of"],
    ("Customer", "Sales Order", "child"): ["has ordered"],
    ("Customer", "Sales Contract", "child"): ["signs", "owns"],
    ("Sales Order", "Customer", "parent"): ["belongs to", "is initiated by"],
    ("Sales Order", "Material", "child"): ["includes", "consists of"],
    ("Sales Order", "Delivery", "child"): ["triggers", "is followed by"],
    ("Sales Order", "Production Order", "child"): ["triggers", "is followed by"],
    ("Sales Contract", "Material", "child"): ["includes", "consists of"],
    ("Production Order", "Material", "child"): ["includes", "consists of"],
    ("Production Order", "Delivery", "child"): ["triggers", "is followed by"],
    ("Production Order", "Goods Movement", "child"): ["triggers", "is followed by"],
    ("Delivery", "Goods Movement", "child"): ["triggers", "is followed by"],
    ("Delivery", "Material", "child"): ["triggers", "is followed by"],
}


### Functions


def get_ontology() -> dict:
    """Get the ontology for the knowledge graph.

    Returns:
        dict: The ontology as a dictionary.

    """

    return KNOWLEDGEGRAPH_ONTOLOGY


def get_knowledgegraph_object() -> KnowledgeGraph:
    """Get the Knowledge Graph object."""

    global KNOWLEDGEGRAPH_OBJECT  # noqa: PLW0603

    if KNOWLEDGEGRAPH_OBJECT is None:
        KNOWLEDGEGRAPH_OBJECT = KnowledgeGraph(otcs_object=get_otcs_object(), ontology=KNOWLEDGEGRAPH_ONTOLOGY)

    return KNOWLEDGEGRAPH_OBJECT


def build_graph() -> None:
    """Build the knowledge Graph. And keep it updated every hour."""

    def build() -> None:
        """Build the knowledge graph once."""

        logger.info("Starting knowledge graph build...")
        start_time = datetime.now(UTC)
        result = get_knowledgegraph_object().build_graph(
            workspace_type_exclusions=None,
            workspace_type_inclusions=[
                "Vendor",
                "Purchase Contract",
                "Purchase Order",
                "Material",
                "Customer",
                "Sales Order",
                "Sales Contract",
                "Delivery",
                "Goods Movement",
            ],
            workers=20,  # for multi-threaded traversal
            filter_at_traversal=True,  # also filter for workspace types if following relationships
            relationship_types=["child"],  # only go from parent to child
            strategy="BFS",  # Breadth-First-Search
            metadata=True,  # don't include workspace metadata
        )
        end_time = datetime.now(UTC)
        logger.info(
            "Knowledge graph completed in %s. Processed %d workspace nodes and traversed %d workspace relationships.",
            str(end_time - start_time),
            result["processed"],
            result["traversed"],
        )

    # Endless loop to build knowledge graph and update it every hour:
    while True:
        build()
        logger.info("Waiting for 1 hour before rebuilding the knowledge graph...")
        time.sleep(3600)


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


def get_otca_object(otcs_object: OTCS | None = None) -> OTCA:
    """Get the Content Aviator (OTCA) object.

    Args:
        otcs_object (OTCS | None, optional):
            The Content Server (OTCS) object. Defaults to None.

    Returns:
        OTCA:
            The new Content Aviator object.

    """

    settings = Settings()

    # Get the Kubernetes object:
    k8s_object = get_k8s_object()
    content_system = {}
    # Read the content system (e.g. OTCM) from the Kubernetes Config Map:
    for service in ["chat", "embed"]:
        cm = k8s_object.get_config_map(f"csai-{service}-svc")
        if cm:
            content_system[service] = cm.data.get("CONTENT_SYSTEM", "none")
            logger.info("Set content system for '%s' to -> '%s'.", service, content_system[service])

    # Create the Content Aviator object (OTCA class):
    otca = OTCA(
        chat_url=str(settings.aviator.chat_svc_url),
        embed_url=str(settings.aviator.embed_svc_url),
        studio_url=str(settings.aviator.studio_url),
        otds_url=str(settings.otds.url_internal),
        client_id=settings.aviator.oauth_client,
        client_secret=settings.aviator.oauth_secret,
        otcs_object=otcs_object,
        content_system=content_system,
        logger=logger.getChild("otca"),
    )

    return otca


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
