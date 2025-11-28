"""Define router for v1_maintenance."""

import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse
from pyxecm.otcs import OTCS
from pyxecm_customizer.k8s import K8s

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User
from pyxecm_api.common.functions import get_k8s_object, get_otcs_object, get_settings
from pyxecm_api.settings import CustomizerAPISettings

from .models import CSAIEmbedMetadata

router = APIRouter(prefix="/api/v1/csai", tags=["csai"])

logger = logging.getLogger("pyxecm_api.v1_csai")


@router.post("/metadata")
def embed_metadata(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    otcs_object: Annotated[OTCS, Depends(get_otcs_object)],
    body: Annotated[CSAIEmbedMetadata, Body()],
) -> JSONResponse:
    """Embed the Metadata of the given objects.

    Args:
        user (Annotated[User, Depends):
            User required for authentication.
        otcs_object (Annotated[OTCS, Depends(get_otcs_object)]):
            The OTCS object to interact with OTCM (Content Server).
        body (Annotated[CSAIEmbedMetadata, Body):
            The request body.

    Returns:
        JSONResponse:
            JSONResponse with success=true/false

    """

    success = otcs_object.aviator_embed_metadata(**body.model_dump())

    return JSONResponse({"success": success})


@router.get("")
def get_csai_config_data(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
) -> JSONResponse:
    """Get the csai config data."""

    logger.info("Read CSAI config data by user -> %s", user.id)

    config_data = {}

    try:
        csai_config_maps = [
            cm for cm in k8s_object.list_config_maps().items if cm.metadata.name.startswith(settings.csai_prefix)
        ]

        for config_map in csai_config_maps:
            config_data[config_map.metadata.name] = config_map.data

    except Exception as e:
        logger.error("Could not read config data from k8s -> %s", e)
        return JSONResponse({"status": "error", "message": str(e)})

    return JSONResponse(config_data)


@router.post("")
def set_csai_config_data(
    user: Annotated[User, Depends(get_authorized_user)],
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    config: Annotated[dict, Body()],
) -> JSONResponse:
    """Set the CSAI config data."""

    logger.info("Write CSAI config data by user -> %s", user.id)

    for config_map in config:
        if not config_map.startswith(settings.csai_prefix):
            return JSONResponse(
                {
                    "status": "error",
                    "message": f"Config map name {config_map} does not start with {settings.csai_prefix}",
                },
                status_code=HTTPStatus.BAD_REQUEST,
            )

    try:
        for key, value in config.items():
            logger.info("User: %s -> Replacing config map %s with %s", user.id, key, value)
            k8s_object.replace_config_map(
                config_map_name=key,
                config_map_data=value,
            )

    except Exception as e:
        logger.error("Could not replace config map %s with %s -> %s", key, value, e)
        return JSONResponse({"status": "error", "message": str(e)})

    for deployment in ["chat-svc", "embed-svc", "embed-wrkr"]:
        deployment = f"{settings.csai_prefix}-{deployment}"

        logger.info("User: %s ->Restarting deployment -> %s", user.id, deployment)
        k8s_object.restart_deployment(deployment)

    return get_csai_config_data(user=user, k8s_object=k8s_object, settings=settings)
