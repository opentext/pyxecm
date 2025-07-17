"""List of all routers for the csai agents."""

import logging

from fastapi import APIRouter

from . import otcm_knowledgegraph_router, otcm_user_agent_router, otcm_workspace_agent_router

logger = logging.getLogger("pyxecm_api.agents")

router = APIRouter(tags=["csai agents"])

agent_routers = [router, otcm_workspace_agent_router, otcm_user_agent_router, otcm_knowledgegraph_router]
