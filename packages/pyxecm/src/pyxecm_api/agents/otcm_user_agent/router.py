"""Define router for User endpoints."""

import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pyxecm.otcs import OTCS

from pyxecm_api.common.functions import get_otcs_object_from_otcsticket

from .models import UserModel

router = APIRouter(prefix="/otcm_user_agent", tags=["csai agents"])

logger = logging.getLogger("pyxecm_api.agents.otcm_user_agent")


@router.post(
    "/user",
    summary="Find a user by name or user attributes",
    responses={
        200: {"description": "User found"},
        403: {"description": "Invalid credentials"},
        400: {"description": "User not found"},
    },
    response_model=UserModel,
    response_description="Details about a user. Best presented as a table with each user property in a row.",
)
def otcm_user_agent_find_user(
    otcs: Annotated[OTCS, Depends(get_otcs_object_from_otcsticket)],
    user: Annotated[UserModel, Body()],
) -> UserModel | None:
    """Find a user by by its name or other attributes.

    The user ID, the user name (login), user first name, user last name and user email will be returned.
    When a user is returned, display the user data as a markdown table.
    """

    response = otcs.get_users(
        where_name=user.login,
        where_first_name=user.first_name,
        where_last_name=user.last_name,
        where_business_email=user.email,
    )

    if not response or not response["results"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    try:
        department_id = otcs.get_result_value(response=response, key="group_id")
        department = otcs.get_group(group_id=department_id) if department_id else None
        department_name = otcs.get_result_value(response=department, key="name") if department else None
        return UserModel(
            user_id=otcs.get_result_value(response=response, key="id"),
            login=otcs.get_result_value(response=response, key="name"),
            first_name=otcs.get_result_value(response=response, key="first_name"),
            last_name=otcs.get_result_value(response=response, key="last_name"),
            email=otcs.get_result_value(response=response, key="business_email"),
            department=department_name,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from e


# end function definition
