"""init Module."""

from .otcm_knowledgegraph.router import router as otcm_knowledgegraph_router
from .otcm_user_agent.router import router as otcm_user_agent_router
from .otcm_workspace_agent.router import router as otcm_workspace_agent_router

__all__ = ["otcm_knowledgegraph_router", "otcm_user_agent_router", "otcm_workspace_agent_router"]
