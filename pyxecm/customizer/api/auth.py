"""Utility library to handle the authentication with OTDS."""

import json
from typing import Annotated

import requests
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pyxecm.customizer.api.models import User
from pyxecm.customizer.api.settings import api_settings

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_groups(response: dict, token: str) -> list:
    """Get the groups of the user.

    Args:
        response (_type_): _description_
        token (_type_): _description_

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


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Get the current user from OTDS and verify it."""

    if api_settings.api_token is not None and token == api_settings.api_token:
        return User(
            id="api",
            full_name="API Token",
            groups=["otadmins@otds.admin"],
            is_admin=True,
            is_sysadmin=True,
        )

    url = api_settings.otds_url + "/otdsws/rest/currentuser"
    headers = {
        "Accept": "application/json",
        "otdsticket": token,
    }
    response = requests.request("GET", url, headers=headers, timeout=2)

    if response.ok:
        response = json.loads(response.text)

        user = User(
            id=response["user"]["id"],
            full_name=response["user"]["name"],
            groups=get_groups(response, token),
            is_admin=response["isAdmin"],
            is_sysadmin=response["isSysAdmin"],
        )

        return user
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_authorized_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Check if the user is authorized (member of the Group otadmin@otds.admin)."""

    if "otadmins@otds.admin" not in current_user.groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User {current_user.id} is not authorized",
        )
    return current_user


@router.post("/token", tags=["auth"])
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> JSONResponse:
    """Login using OTDS and return a token."""

    url = api_settings.otds_url + "/otdsws/rest/authentication/credentials"

    payload = json.dumps(
        {"userName": form_data.username, "password": form_data.password},
    )
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        response = requests.request(
            "POST",
            url,
            headers=headers,
            data=payload,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"{exc.request.url} cannot be reached",
        ) from exc

    if response.ok:
        response = json.loads(response.text)
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return JSONResponse(
        {
            "access_token": response["ticket"],
            "token_type": "bearer",
            "userId": response["userId"],
        },
    )


@router.get("/users/me", tags=["auth"])
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]) -> JSONResponse:
    """Get the current user.

    current_user:
        type: User
        description: The current user.

    """

    if "otadmins@otds.admin" in current_user.groups:
        return JSONResponse(current_user.model_dump())
    else:
        raise HTTPException(
            status_code=403,
            detail=f"User {current_user.id} is not authorized",
        )
