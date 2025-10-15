"""Utility library to handle the authentication with OTDS."""

import json
from typing import Annotated

import requests
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pyxecm_api.settings import api_settings

from .functions import get_current_user
from .models import User

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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

    current_user (User):
        The current user.

    """

    if "otadmins@otds.admin" in current_user.groups:
        return JSONResponse(current_user.model_dump())
    else:
        raise HTTPException(
            status_code=403,
            detail=f"User {current_user.id} is not authorized",
        )
