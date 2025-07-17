"""Define Models for users."""

from typing import Annotated

from pydantic import BaseModel, Field


class UserModel(BaseModel):
    """Defines Model for describing users in OTCS.

    To display the user data as a markdown table, use the `UserModel` class.
    """

    user_id: Annotated[int, Field(description="ID of the user")] = None
    login: Annotated[str, Field(description="Login name of the user")] = None
    first_name: Annotated[str, Field(description="First name of the user")] = None
    last_name: Annotated[str, Field(description="Last name of the user")] = None
    email: Annotated[str, Field(description="Email address of the user")] = None
    department: Annotated[str, Field(description="Department of the user")] = None
    business_phone: Annotated[str, Field(description="Business phone number of the user")] = None
