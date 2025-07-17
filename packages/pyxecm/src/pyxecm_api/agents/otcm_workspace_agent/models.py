"""Define Models for workspaces."""

from typing import Annotated, Any

from pydantic import BaseModel, Field


class WorkspaceAttributeModel(BaseModel):
    """Model for a workspace attribute."""

    category: Annotated[str, Field(description="Category for the workspace attributes")]
    attribute: Annotated[str, Field(description="Name of the attribute")]
    value: Annotated[str, Field(description="Value of the attribute")]
    set: Annotated[str, Field(description="Optional attribute group or set name")]


class WorkspaceModel(BaseModel):
    """Defines Model for describing workspaces in OTCM (Opentext Content Management).

    To display an instance of this model, please display the link.
    """

    id: Annotated[int, Field(description="ID of the workspace")] = None
    name: Annotated[str, Field(description="Name of the workspace")] = None
    type: Annotated[str, Field(description="Name of the workspace type")] = None
    description: Annotated[str, Field(description="Description of the workspace")] = None

    link: Annotated[str, Field(description="Link to the workspace, should be used when the instance is displayed")] = (
        None
    )

    # attributes: Annotated[
    #     list[WorkspaceAttributeModel] | None,
    #     Body(description="List of custom attributes associated with the workspace"),
    # ] = None

    def model_post_init(self, context: Any) -> None:  # noqa: ARG002, ANN401
        """Post model initialization."""
        # this could also be done with `default_factory`:
        self.link = f"[{self.name}](/cs/cs/app/nodes/{self.id})"
