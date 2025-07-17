"""Define commonly used models."""

from pydantic import BaseModel


class Context(BaseModel):
    """Define Model that is used to provide static context information for tools."""

    where: list[dict]
    query: str
