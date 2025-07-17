"""Define router for v1_maintenance."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form
from pyxecm_customizer.k8s import K8s
from pyxecm_maintenance_page.settings import settings as maint_settings

from pyxecm_api.auth import models
from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.common.functions import get_k8s_object
from pyxecm_api.v1_maintenance.functions import get_maintenance_mode_status, set_maintenance_mode_via_ingress
from pyxecm_api.v1_maintenance.models import MaintenanceModel

router = APIRouter(prefix="/api/v1/maintenance", tags=["maintenance"])

logger = logging.getLogger("pyxecm_api.v1_maintenance")


@router.get(path="")
async def status(
    user: Annotated[models.User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
) -> MaintenanceModel:
    """Return status of maintenance mode.

    Args:
        user (models.User):
            Added to enforce authentication requirement
        k8s_object (K8s):
            K8s object instance of pyxecm K8s class


    Returns:
        dict:
            Details of maintenance mode.

    """

    return get_maintenance_mode_status(k8s_object)


@router.post(path="")
async def set_maintenance_mode_options(
    user: Annotated[models.User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    config: Annotated[MaintenanceModel, Form()],
) -> MaintenanceModel:
    """Configure the Maintenance Mode and set options.

    Args:
        user (models.User):
            Added to enforce authentication requirement
        k8s_object (K8s):
            K8s object instance of pyxecm K8s class
        config (MaintenanceModel):
            instance of the Maintenance Model

    Returns:
        dict: _description_

    """
    # Enable / Disable the acutual Maintenance Mode
    set_maintenance_mode_via_ingress(config.enabled, k8s_object)

    if config.title:
        maint_settings.title = config.title

    if config.text:
        maint_settings.text = config.text

    if config.footer:
        maint_settings.footer = config.footer

    return get_maintenance_mode_status(k8s_object)
