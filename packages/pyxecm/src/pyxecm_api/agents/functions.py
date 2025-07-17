"""List of all routers for the csai agents."""

import logging
from importlib.metadata import version
from threading import Thread

from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pyxecm import OTCA, OTCS
from pyxecm_customizer.settings import Settings

from pyxecm_api.common.functions import get_k8s_object, get_otcs_object

logger = logging.getLogger("pyxecm_api.agents")

SETTINGS = Settings()


def get_otca_object(otcs_object: OTCS | None = None) -> OTCA:
    """Get the OTCA object."""

    k8s_object = get_k8s_object()
    content_system = {}
    for service in ["chat", "embed"]:
        cm = k8s_object.get_config_map(f"csai-{service}-svc")
        if cm:
            content_system[service] = cm.data.get("CONTENT_SYSTEM", "none")

    otca = OTCA(
        chat_url=str(SETTINGS.aviator.chat_svc_url),
        embed_url=str(SETTINGS.aviator.embed_svc_url),
        studio_url=str(SETTINGS.aviator.studio_url),
        otds_url=str(SETTINGS.otds.url_internal),
        client_id=SETTINGS.aviator.oauth_client,
        client_secret=SETTINGS.aviator.oauth_secret,
        otcs_object=otcs_object,
        content_system=content_system,
        logger=logger.getChild("otca"),
    )

    return otca


# end function


def register_tool_body(route: APIRoute, agents: list[str] | None = None) -> dict:
    """Generate the request body for the CSAI Studio integration.

    Args:
        route (APIRoute):
            The API routes.
        agents (list[str] | None, optional):
            A list of agents this tool is associated with.
            Defaults to ["retrieverAgent"].

    Returns:
        dict:
            The body for the REST API call to register a tool in Content Aviator.

    """

    if agents is None:
        agents = ["retrieverAgent"]

    return {
        "name": route.name,
        "description": route.description,
        "APISchema": get_openapi(
            title=route.name,
            openapi_version="3.0.0",
            version=version("pyxecm"),
            servers=[{"url": "http://customizer:8000"}],
            routes=[route],
        ),
        "requestTemplate": {
            "data": {"context": {"where": "memory.input.where", "query": "memory.input.query"}},
        },
        "responseTemplate": {},  # Optional response template used to filter the response from the API.
        "agents": agents,
    }


# end function


def register_all() -> None:
    """Register all tools."""

    def register_all_routes() -> None:
        otca = get_otca_object(otcs_object=get_otcs_object())
        response = otca.do_request(
            method="POST",
            url=str(SETTINGS.aviator.studio_url) + "studio/v1/import",
            show_error=False,
            parse_request_response=False,
        )
        if not response or response.text != "Accepted":
            logger.error("Failed to import tools!")
            return
        get_k8s_object().restart_deployment(deployment_name="csai-chat-svc")

        for route in routes:
            logger.info("Registering Content Aviator tool -> '%s'...", route.name)
            request_body = register_tool_body(route=route)
            result = otca.register_tool(request_body=request_body)
            if result:
                logger.info("Tool got registered successfully -> %s", route.name)
                logger.debug("%s", result)

    from pyxecm_api.app import app

    # Get all FastAPI routes and register them as tools:
    routes: list[APIRoute] = [route for route in app.routes if route.path.startswith("/agents")]

    Thread(target=register_all_routes, name="RegisterTools").start()


# end function
