"""Define Models for Payload."""

from pydantic import BaseModel


class CSAIEmbedMetadata(BaseModel):
    """Defines Data Model for embeding metadata for documents and workspaces."""

    node_id: int = None
    crawl: bool = False
    wait_for_completion: bool = False
    message_override: dict = None
    timeout: float = 30.0
    document_metadata: bool = False
    images: bool = False
    image_prompt: str = ""
    workspace_metadata: bool = True
    remove_existing: bool = False
