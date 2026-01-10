"""Define functions for v1_maintenance."""

import logging
import os
from http import HTTPStatus

import yaml
from fastapi import HTTPException
from pydantic import HttpUrl, ValidationError
from pyxecm_customizer.k8s import K8s
from pyxecm_maintenance_page.settings import settings as maint_settings

from pyxecm_api.v1_maintenance.models import MaintenanceModel

logger = logging.getLogger("v1_maintenance.functions")


def get_cshost(k8s_object: K8s) -> str:
    """Get the cs_hostname from the environment Variable OTCS_PUBLIC_HOST otherwise read it from the otcs-frontend-configmap."""

    if "OTCS_PUBLIC_URL" in os.environ:
        return os.getenv("OTCS_PUBLIC_URL", "otcs")

    else:
        cm = k8s_object.get_config_map("otcs-frontend-configmap")

        if cm is None:
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail=f"Could not read otcs-frontend-configmap from namespace: {k8s_object.get_namespace()}",
            )

        config_file = cm.data.get("config.yaml")
        config = yaml.safe_load(config_file)

        try:
            cs_url = HttpUrl(config.get("csurl"))
        except ValidationError as ve:
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail="Could not read otcs_host from environment variable OTCS_PULIBC_URL or configmap otcs-frontend-configmap/config.yaml/cs_url",
            ) from ve
        return cs_url.host


def get_maintenance_mode_status(k8s_object: K8s) -> dict:
    """Get the status of maintenance mode by inspecting the ingress object.

    Args:
        k8s_object (K8s): An instance of the K8s class used to interact with Kubernetes resources.


    Returns:
        dict: A dictionary containing the details of the maintenance mode, including:
            - enabled (bool): Indicates whether maintenance mode is enabled.
            - title (str): The title of the maintenance mode message.
            - text (str): The text of the maintenance mode message.
            - footer (str): The footer of the maintenance mode message.

    Raises:
        HTTPException: If no ingress object is found to determine the maintenance mode status.

    """
    ingress = k8s_object.get_ingress("otxecm-ingress")

    if ingress is None:
        raise HTTPException(
            status_code=500,
            detail="No ingress object found to read Maintenance Mode status",
        )

    enabled = False
    for rule in ingress.spec.rules:
        if rule.host == get_cshost(k8s_object):
            for path in rule.http.paths:
                if path.path == "/":
                    enabled = path.backend.service.name != "otcs-frontend"
                    break

    return MaintenanceModel(
        enabled=enabled, title=maint_settings.title, text=maint_settings.text, footer=maint_settings.footer
    )


def set_maintenance_mode_via_ingress(enabled: bool, k8s_object: K8s) -> None:
    """Set maintenance mode."""

    logger.warning(
        "Setting Maintenance Mode to -> %s",
        (enabled),
    )

    if enabled:
        k8s_object.update_ingress_backend_services(
            "otxecm-ingress",
            get_cshost(k8s_object=k8s_object),
            "customizer",
            5555,
        )
    else:
        k8s_object.update_ingress_backend_services(
            "otxecm-ingress",
            get_cshost(k8s_object=k8s_object),
            "otcs-frontend",
            80,
        )
