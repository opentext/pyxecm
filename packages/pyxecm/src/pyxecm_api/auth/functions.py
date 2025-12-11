"""Utility library to handle the authentication with OTDS."""

import json
from typing import Annotated

import requests
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer

from pyxecm_api.settings import api_settings

from .models import User

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=False,
    description="Authenticate with OTDS, user needs to be member of 'otadmins@otds.admin' group",
    scheme_name="OTDS Authentication",
)
apikey_header = APIKeyHeader(name="x-api-key", auto_error=False, scheme_name="APIKey")
otcsticket = APIKeyHeader(name="otcsticket", auto_error=True, scheme_name="OTCSTicket")


def get_groups(response: dict, token: str) -> list:
    """Get the groups of the user.

    Args:
        response (dict): _description_
        token (str): _description_

    Returns:
        list: _description_

    """

    headers = {
        "Accept": "application/json",
        "otdsticket": token,
    }
    url = api_settings.otds_url + "/otdsws/rest/users/" + response["user"]["id"] + "/memberof"

    response = requests.request("GET", url, headers=headers, timeout=5)
    if response.ok:
        response = json.loads(response.text)
        return [group["id"] for group in response.get("groups", [])]

    # Retur empty list if request wasn't successful
    return []


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], api_key: Annotated[str, Depends(apikey_header)]
) -> User:
    """Get the current user from OTDS and verify it."""

    if api_settings.api_key is not None and api_key == api_settings.api_key:
        return User(
            id="api",
            full_name="API Key",
            groups=["otadmins@otds.admin"],
            is_admin=True,
            is_sysadmin=True,
            is_tenantadmin=False,
        )

    if token and token.startswith("*OTDSSSO*"):
        url = api_settings.otds_url + "/otdsws/rest/currentuser"
        headers = {
            "Accept": "application/json",
            "otdsticket": token,
        }
        response = requests.request("GET", url, headers=headers, timeout=2)

        if response.ok:
            response = json.loads(response.text)

            # Check if user is tenant admin
            tenant_admin = False
            for attr in response["user"].get("values", []):
                if attr.get("name") == "oTType" and "TenantAdminUser" in attr.get("values", []):
                    tenant_admin = True
                    break

            return User(
                id=response["user"]["id"],
                full_name=response["user"]["name"],
                groups=get_groups(response, token),
                is_admin=response["isAdmin"],
                is_sysadmin=response["isSysAdmin"],
                is_tenantadmin=tenant_admin,
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_authorized_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Check if the user is authorized (member of the Group otadmin@otds.admin or should be a tenantAdmin user)."""

    if "otadmins@otds.admin" not in current_user.groups and not current_user.is_tenantadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User {current_user.id} is not authorized",
        )
    return current_user


async def get_otcsticket(otcsticket: Annotated[str, Depends(otcsticket)]) -> User:
    """Check if the user is authorized (member of the Group otadmin@otds.admin)."""

    return otcsticket
