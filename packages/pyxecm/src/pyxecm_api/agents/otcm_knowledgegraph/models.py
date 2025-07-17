"""Define Models for KnowledgeGraph."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from pyxecm_api.agents.models import Context
from pyxecm_api.agents.otcm_workspace_agent.models import WorkspaceModel


class KnowledgeGraphQueryModel(BaseModel):
    """Defines Model for describing workspaces in OTCM (Opentext Content Management).

    To display an instance of this model, please display the link.
    """

    source_type: Annotated[
        str,
        Field(
            description="Source workspace type name provided in the user query. This provides the start point of the query in the Knowledge Graph."
        ),
    ]
    source_value: Annotated[
        str,
        Field(
            description="Name of the source workspace instance (of the type provided by source_type). This is NOT optional. If it is missing then you need to switch source and target. The source always needs to have a specific value!"
        ),
    ]
    target_type: Annotated[
        str,
        Field(
            description="Target workspace type name provided in the user query. This defines the result workspace types of the Knolwedge Graph query."
        ),
    ] = None
    target_value: Annotated[
        str,
        Field(
            description="Name of the target workspace instance (of the type provided by the target_type). This value is optionalis an additional / optional selection criteria."
        ),
    ] = None
    intermediate_types: Annotated[
        list[str],
        Field(
            description="List of workspace types (entities) that are on the path between the source workspace type and target workspace type. These are typically additional relational conditions the user is giving in the query. The start type and target types should never be in intermediate types!"
        ),
    ] = None
    direction: Annotated[
        Literal["child", "parent"],
        Field(
            description="The direction the graph should be traversed in. This is either 'child' (the default) or 'parent'. 'child' is typically used if traversing from main entities to related sub-entities thus following a '1 -> many' relationship (top-down). 'parent' is typically used if traversing bottom-up. This should reflect the relationship between the source type of the workspace and the requested target type. A 'child' relationship is e.g. 'Customer' -> 'Sales Order'. A 'parent' relationship is e.g. 'Material' -> 'Sales Order'."
        ),
    ] = None


class KnowledgeGraphResponseModel(BaseModel):
    """Response of the Knowledge Graph tool."""

    results: Annotated[list[WorkspaceModel], Field(description="A list of workspaces matching the query.")]
    context_update: Annotated[
        Context, Field(description="An update for the LLM context. Update the graph state with this information!")
    ]
