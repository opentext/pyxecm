"""Define router for workspace endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException
from pyxecm_customizer.knowledge_graph import KnowledgeGraph

from pyxecm_api.agents.models import Context
from pyxecm_api.agents.otcm_workspace_agent.models import WorkspaceModel

from .functions import (
    KNOWLEDGEGRAPH_ONTOLOGY,
    get_knowledgegraph_object,
)
from .models import (
    KnowledgeGraphQueryModel,
)

router = APIRouter(prefix="/otcm_knowledgegraph_agent", tags=["csai agents"])

logger = logging.getLogger("pyxecm_api.agents.otcm_knowledgegraph_agent")


@router.post(
    path="/query",
    summary="Query the knowledge graph for a list of workspaces matching the user query.",
    description=f"Use the following ontology to understand the relationship between workspace types and the direction of the relationships (either 'parent' or 'child'): {KNOWLEDGEGRAPH_ONTOLOGY}",
    responses={
        200: {"description": "Workspaces found"},
        403: {"description": "Invalid credentials"},
        404: {"description": "No matching workspaces found"},
        500: {"description": "Knowledge Graph is not available"},
    },
    #    response_model=ToolResponse,
    # response_model=list[WorkspaceModel],
    response_description="List of workspaces that match the query. Best presented as a list with hyperlinks to the workspace.",
)
def otcm_knowledgegraph_query(
    context: Context,
    knowledge_graph: Annotated[KnowledgeGraph, Depends(get_knowledgegraph_object)],
    knowledge_graph_query: Annotated[KnowledgeGraphQueryModel, Body()],
) -> dict | None:  # ToolResponse | None:  # list[WorkspaceModel] | None:
    # ) -> list[WorkspaceModel] | None:
    """Query the knowledge graph for a list of workspaces matching the user query. Workspaces are entities and workspace types are entitiy types."""

    if not knowledge_graph:
        raise HTTPException(status_code=500, detail="Knowledge Graph is not available")

    logger.info("Got context -> %s", context)
    results = knowledge_graph.graph_query(
        source_type=knowledge_graph_query.source_type,
        source_value=knowledge_graph_query.source_value,
        intermediate_types=knowledge_graph_query.intermediate_types,
        target_type=knowledge_graph_query.target_type,
        target_value=knowledge_graph_query.target_value,
        direction=knowledge_graph_query.direction,
        max_hops=4,
    )
    if not results:
        raise HTTPException(status_code=404, detail="No result found")

    where_clause = [{"workspaceID": str(workspace[1])} for workspace in results]
    context_update = Context(where=where_clause, query=context.query)
    logger.info("Return context -> %s", context_update)

    results = [WorkspaceModel(name=n, id=i, type=knowledge_graph_query.target_type) for n, i in results]

    return {"where": where_clause}

    #    return results


#    return ToolResponse(results=results, context_update=context_update)
