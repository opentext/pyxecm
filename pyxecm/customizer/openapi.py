"""Module to implement OpenAPI Support for OTCS."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import sys
import tempfile

import httpx
import uvicorn
from decouple import config
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl

from pyxecm import OTCS

app = FastAPI()

PROTOCOL = config("PROTOCOL", default="https")
DOMAIN = config("DOMAIN", "master.terrarium.cloud")
HOSTNAME = config("OTCS_HOST", f"otcs-admin.{DOMAIN}")
PUBLIC_URL = PROTOCOL + "://" + HOSTNAME
USERNAME = config("USERNAME")
PASSWORD = config("PASSWORD")
PORT = config("PORT", default=443, cast=int)
BASE_PATH = config("BASE_PATH", default="/cs/cs")
REST_API = PUBLIC_URL + BASE_PATH + "/api"

otcs_object = OTCS(
    protocol=PROTOCOL,
    hostname=HOSTNAME,
    port=PORT,
    public_url=PUBLIC_URL,
    username=USERNAME,
    password=PASSWORD,
    thread_number=1,
    download_dir=os.path.join(tempfile.gettempdir(), "ollie"),
    base_path=BASE_PATH,
)

cookie = otcs_object.authenticate(wait_for_ready=False)
if not cookie:
    exception = "Authentication failed - exit"
    sys.exit(1)

logging.basicConfig(
    format="%(asctime)s %(levelname)s [%(name)s] [%(threadName)s] %(message)s",
    datefmt="%d-%b-%Y %H:%M:%S",
    level=logging.INFO,
    handlers=[
        logging.FileHandler(os.path.join(tempfile.gettempdir(), "customizing_api.log")),
        logging.StreamHandler(sys.stdout),
    ],
)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, path: str) -> dict | HTTPException:
    """Proxy the request to the backend.

    Args:
        request (Request): _description_
        path (str): _description_

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    """
    async with httpx.AsyncClient() as client:
        backend_url = f"{REST_API}/{path}"

        # Forward headers, query params, and body
        headers = dict(request.headers) | cookie
        query_params = request.query_params
        body = await request.body()

        try:
            response = await client.request(
                method=request.method,
                url=backend_url,
                headers=headers,
                params=query_params,
                content=body,
            )
            return response.json()  # Return the backend response
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Backend error: {e}") from e


class UserData(BaseModel):
    """Response data for users.

    Args:
        BaseModel: pydantic base model

    """

    birth_date: str | None = Field(
        None,
        title="Birth Date",
        description="The user's date of birth, if available.",
    )
    business_email: str | None = Field(
        None,
        title="Business Email",
        description="The user's business email address.",
    )
    business_fax: str | None = Field(
        None,
        title="Business Fax",
        description="The user's business fax number, if available.",
    )
    business_phone: str | None = Field(
        None,
        title="Business Phone",
        description="The user's business phone number, if available.",
    )
    cell_phone: str | None = Field(
        None,
        title="Cell Phone",
        description="The user's cell phone number, if available.",
    )
    deleted: bool = Field(
        ...,
        title="Deleted",
        description="Indicates whether the user's record is deleted.",
    )
    display_language: str | None = Field(
        None,
        title="Display Language",
        description="The preferred display language of the user.",
    )
    first_name: str = Field(
        ...,
        title="First Name",
        description="The user's first name.",
    )
    gender: str | None = Field(
        None,
        title="Gender",
        description="The gender of the user, if specified.",
    )
    group_id: int = Field(
        ...,
        title="Group ID",
        description="The unique identifier for the group the user belongs to.",
    )
    home_address_1: str | None = Field(
        None,
        title="Home Address Line 1",
        description="The first line of the user's home address, if available.",
    )
    home_address_2: str | None = Field(
        None,
        title="Home Address Line 2",
        description="The second line of the user's home address, if available.",
    )
    home_fax: str | None = Field(
        None,
        title="Home Fax",
        description="The user's home fax number, if available.",
    )
    home_phone: str | None = Field(
        None,
        title="Home Phone",
        description="The users's home phone number, if available.",
    )
    user_id: int = Field(
        ...,
        title="User ID",
        description="The unique identifier for the user.",
    )
    initials: str | None = Field(
        None,
        title="Initials",
        description="The user's initials, if specified.",
    )
    last_name: str = Field(..., title="Last Name", description="The user's last name.")
    middle_name: str | None = Field(
        None,
        title="Middle Name",
        description="The user's middle name, if specified.",
    )
    name: str = Field(
        ...,
        title="Username",
        description="The user's username or login name.",
    )
    name_formatted: str = Field(
        ...,
        title="Formatted Name",
        description="The user's full name in formatted form.",
    )
    photo_id: int = Field(
        ...,
        title="Photo ID",
        description="The unique identifier for the user's photo.",
    )
    photo_url: HttpUrl | None = Field(
        None,
        title="Photo URL",
        description="The URL to the user's photo, if available.",
    )
    type: int = Field(
        ...,
        title="Type",
        description="The type of member, represented as an integer.",
    )
    type_name: str = Field(
        ...,
        title="Type Name",
        description="The type of user, represented as a descriptive name.",
    )


class UserResponse(BaseModel):
    """User Response Model."""

    results: list[UserData] = Field(
        ...,
        title="Results",
        description="A list of user data.",
    )


@app.get("/v2/members/{user_id}", response_model=UserResponse)
async def get_user(user_id: int) -> dict | list:
    """Get the user.

    Args:
        user_id (int): _description_

    Returns:
        dict | list: _description_

    """
    backend_url = f"{REST_API}/v2/members/{user_id}"
    async with httpx.AsyncClient() as client:
        response = await client.get(backend_url)
        response.raise_for_status()
        return response.json()


def run_api() -> None:
    """Start the OpenAPI Proxy Server."""
    uvicorn.run("pyxecm.customizer.openapi:app", host="0.0.0.0", port=8000)  # noqa: S104


if __name__ == "__main__":
    run_api()
