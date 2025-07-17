"""Define router for workspace endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pyxecm.otcs import OTCS

from pyxecm_api.agents.models import Context
from pyxecm_api.common.functions import get_otcs_object_from_otcsticket

from .models import WorkspaceModel

router = APIRouter(prefix="/otcm_workspace_agent", tags=["csai agents"])

logger = logging.getLogger("pyxecm_api.agents.otcm_workspace_agent")


@router.post(
    path="/find_workspace",
    response_model=WorkspaceModel,
    summary="Find the markdown link to a workspace by workspace name and workspace type and display the link.",
    responses={
        200: {"description": "Workspace found"},
        403: {"description": "Invalid credentials"},
        404: {"description": "Workspace not found"},
    },
)
def otcm_workspace_agent_find_workspace(
    context: Context,
    otcs: Annotated[OTCS, Depends(get_otcs_object_from_otcsticket)],
    workspace: Annotated[WorkspaceModel, Body()],
) -> WorkspaceModel | None:
    """Find a workspace by workspace name and workspace type.

    The returned workspace is an OTCS workspace object. Show the markdown link in the chat response, sothat the user can click on it.
    """

    logger.info("Got context -> %s", context)

    response = otcs.get_workspace_by_type_and_name(type_name=workspace.type, name="contains_" + workspace.name)

    if response and len(response["results"]) == 1:
        result = WorkspaceModel(
            id=otcs.get_result_value(response=response, key="id"),
            name=otcs.get_result_value(response=response, key="name"),
            type=workspace.type,
        )
        logger.info("Workspace found -> %s", result)
        return result

    if response is None or not response["results"]:
        response = otcs.search(search_term=workspace.name)

    if response is None or not response["results"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found.",
        )

    try:
        return WorkspaceModel(
            id=otcs.get_result_value(response=response, key="id"),
            name=otcs.get_result_value(response=response, key="name"),
            type=workspace.type,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found.",
        ) from e


# end function definition


@router.post(
    path="/lookup_workspace",
    response_model=WorkspaceModel,
    summary="Lookup a workspace based on its type and a value of one of the workspace attributes.",
    responses={
        200: {"description": "Workspace found"},
        403: {"description": "Invalid credentials"},
        400: {"description": "Workspace not found"},
    },
)
def otcm_workspace_agent_lookup_workspace(
    otcs: Annotated[OTCS, Depends(get_otcs_object_from_otcsticket)],
    workspace: Annotated[WorkspaceModel, Body()],
) -> WorkspaceModel | None:
    """Lookup a workspace based on its type and a value of one of the workspace attributes.

    Use this tool if the workspace name is _not_ specified but the user asks for a specific
    workspace attribute value like cities, products, or other attributes.

    Return the workspace data if it is found. If it is not found confirm with the user if the workspace should be created or not.
    If it should be created call the tool: otcm_workspace_agent_create_workspace
    """

    # otcs._otcs_ticket = otcsticket

    workspace_attributes = workspace.attributes or {}
    if not workspace_attributes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Workspace attributes must be provided for lookup.",
        )

    category = next((attr.category for attr in workspace_attributes if attr.category), None)
    attribute = next((attr.attribute for attr in workspace_attributes if attr.attribute), None)
    attribute_set = next((attr.set for attr in workspace_attributes if attr.set), None)
    value = next((attr.value for attr in workspace_attributes if attr.value), None)

    response = otcs.lookup_workspace(
        type_name=workspace.type, category=category, attribute=attribute, attribute_set=attribute_set, value=value
    )
    if response is None or not response["results"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No workspace of type -> '{}' with attribute -> '{}'{} and value -> '{}' found!".format(
                workspace.type, attribute, " (set -> {})".format(attribute_set), value
            ),
        )

    try:
        return WorkspaceModel(
            id=otcs.get_result_value(response=response, key="id"),
            name=otcs.get_result_value(response=response, key="name"),
            type=workspace.type,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found") from e


# end function definition


@router.post(
    path="/create_workspace",
    response_model=WorkspaceModel,
    summary="Create a workspace with given workspace name and workspace type and display the link.",
    responses={
        200: {"description": "Workspace created"},
        403: {"description": "Invalid credentials"},
        404: {"description": "Workspace creation failed"},
    },
)
def otcm_workspace_agent_create_workspace(
    otcs: Annotated[OTCS, Depends(get_otcs_object_from_otcsticket)],
    workspace: Annotated[WorkspaceModel, Body()],
) -> WorkspaceModel | None:
    """Create a workspace with given workspace name and workspace type.

    The ID of the created workspace, the final workspace name, and the workspace type will be returned.

    """

    workspace_type_id, workspace_templates = otcs.get_workspace_templates(type_name=workspace.type)
    if workspace_type_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Workspace type -> '{}' not found!".format(workspace.type)
        )
    if not workspace_templates:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace type -> '{}' has no templates!".format(workspace.type),
        )

    workspace_template_id = workspace_templates[0].get("id")

    response = otcs.create_workspace(
        workspace_template_id=workspace_template_id,
        workspace_type=workspace_type_id,
        workspace_name=workspace.name,
        workspace_description="",
    )

    if response is None or not response["results"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Failed to create workspace -> '{}'".format(workspace.name)
        )

    try:
        workspace_id = response.get("results", {}).get("id")

        # The resulting workspace name can be different from the given name,
        # so we need to fetch the workspace details again to get the final name.
        response = otcs.get_workspace(node_id=workspace_id)
        workspace_name = otcs.get_result_value(response=response, key="name")

        return WorkspaceModel(
            id=workspace_id,
            name=workspace_name,
            type=workspace.type,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found") from e


# end function definition
