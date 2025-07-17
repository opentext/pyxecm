"""Define router for v1_payload."""

import base64
import gzip
import json
import logging
import os
import shutil
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pyxecm_customizer.payload import load_payload

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User
from pyxecm_api.common.functions import PAYLOAD_LIST, get_settings
from pyxecm_api.settings import CustomizerAPISettings

from .functions import prepare_dependencies, tail_log
from .models import PayloadListItem, PayloadListItems, UpdatedPayloadListItem

router = APIRouter(prefix="/api/v1/payload", tags=["payload"])

logger = logging.getLogger("pyxecm_api.v1_payload")


@router.post(path="")
def create_payload_item(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    upload_file: Annotated[UploadFile, File(...)],
    name: Annotated[str, Form()] = "",
    dependencies: Annotated[list[int] | list[str] | None, Form()] = None,
    enabled: Annotated[bool, Form()] = True,
    loglevel: Annotated[
        Literal["DEBUG", "INFO", "WARNING"] | None,
        Form(
            description="Loglevel for the Payload processing",
        ),
    ] = "INFO",
) -> PayloadListItem:
    """Upload a new payload item.

    Args:
        user (User, optional):
            The user who is uploading the payload. Defaults to None.
        settings (CustomizerAPISettings):
            The settings object.
        upload_file (UploadFile, optional):
            The file to upload. Defaults to File(...).
        name (str, optional):
            The name of the payload (if not provided we will use the file name).
        dependencies (list of integers):
            List of other payload items this item depends on.
        enabled (bool):
            Flag indicating if the payload is enabled or not.
        loglevel (str, optional):
            The loglevel for the payload processing. Defaults to "INFO".

    Raises:
        HTTPException:
            Raised, if payload list is not initialized.

    Returns:
        dict:
            The HTTP response.

    """
    if dependencies:
        dependencies = prepare_dependencies(dependencies)

    # Set name if not provided
    name = name or os.path.splitext(os.path.basename(upload_file.filename))[0]
    file_extension = os.path.splitext(upload_file.filename)[1]
    file_name = os.path.join(settings.temp_dir, f"{name}{file_extension}")

    with open(file_name, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    if dependencies == [-1]:
        dependencies = []

    return PayloadListItem(
        PAYLOAD_LIST.add_payload_item(
            name=name,
            filename=file_name,
            status="planned",
            logfile=os.path.join(settings.temp_dir, "{}.log".format(name)),
            dependencies=dependencies or [],
            enabled=enabled,
            loglevel=loglevel,
        )
    )


@router.get(path="")
async def get_payload_items(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
) -> PayloadListItems:
    """Get all Payload items.

    Raises:
        HTTPException: payload list not initialized
        HTTPException: payload list is empty

    Returns:
        dict:
            HTTP response with the result data

    """

    df = PAYLOAD_LIST.get_payload_items()

    if df is None:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Payload list is empty.",
        )

    data = [PayloadListItem(index=idx, **row) for idx, row in df.iterrows()]

    stats = {
        "count": len(df),
        "status": df["status"].value_counts().to_dict(),
        "logs": {
            "debug": df["log_debug"].sum(),
            "info": df["log_info"].sum(),
            "warning": df["log_warning"].sum(),
            "error": df["log_error"].sum(),
            "critical": df["log_critical"].sum(),
        },
    }

    return PayloadListItems(stats=stats, results=data)


@router.get(path="/{payload_id}")
async def get_payload_item(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> PayloadListItem:
    """Get a payload item based on its ID.

    Args:
        user: Annotated[User, Depends(get_authorized_user)]
        payload_id (int): payload item ID

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict:
            HTTP response.

    """
    data = PAYLOAD_LIST.get_payload_item(index=payload_id)

    if data is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload with index -> {} not found".format(payload_id),
        )

    return PayloadListItem(index=payload_id, **data, asd="123")


@router.put(path="/{payload_id}")
async def update_payload_item(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
    name: Annotated[str | None, Form()] = None,
    dependencies: Annotated[list[int] | list[str] | None, Form()] = None,
    enabled: Annotated[bool | None, Form()] = None,
    status: Annotated[Literal["planned", "completed"] | None, Form()] = None,
    loglevel: Annotated[
        Literal["DEBUG", "INFO", "WARNING"] | None,
        Form(
            description="Loglevel for the Payload processing",
        ),
    ] = None,
    customizer_settings: Annotated[str | None, Form()] = None,
) -> UpdatedPayloadListItem:
    """Update an existing payload item.

    Args:
        user (Optional[User]): User performing the update.
        payload_id (int): ID of the payload to update.
        upload_file (UploadFile, optional): replace the file name
        name (Optional[str]): Updated name.
        dependencies (Optional[List[int]]): Updated list of dependencies.
        enabled (Optional[bool]): Updated enabled status.
        loglevel (Optional[str]): Updated loglevel.
        status (Optional[str]): Updated status.
        customizer_settings (Optional[str]): Updated customizer settings.

    Returns:
        dict: HTTP response with the updated payload details.

    """

    if dependencies:
        dependencies = prepare_dependencies(dependencies)
    # Check if the payload exists
    payload_item = PAYLOAD_LIST.get_payload_item(
        payload_id,
    )  # Assumes a method to retrieve payload by ID
    if payload_item is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload with ID -> {} not found.".format(payload_id),
        )

    update_data = {}

    # Update fields if provided
    if name is not None:
        update_data["name"] = name
    if dependencies is not None:
        update_data["dependencies"] = dependencies
    if enabled is not None:
        update_data["enabled"] = enabled
    if status is not None:
        update_data["status"] = status
    if loglevel is not None:
        update_data["loglevel"] = loglevel

        thread_logger = logging.getLogger(name=f"Payload_{payload_id}")
        thread_logger.setLevel(loglevel)

    if customizer_settings is not None:
        try:
            update_data["customizer_settings"] = json.loads(customizer_settings)
        except Exception as e:
            raise HTTPException(detail=e, status_code=HTTPStatus.BAD_REQUEST) from e

    if "status" in update_data and update_data["status"] == "planned":
        logger.info("Resetting log message counters for -> %s", payload_id)
        update_data["log_debug"] = 0
        update_data["log_info"] = 0
        update_data["log_warning"] = 0
        update_data["log_error"] = 0
        update_data["log_critical"] = 0

        update_data["start_time"] = None
        update_data["stop_time"] = None
        update_data["duration"] = None

        data = PAYLOAD_LIST.get_payload_item(index=payload_id)
        if os.path.isfile(data.logfile):
            logger.info(
                "Deleting log file (for payload) -> %s (%s)",
                data.logfile,
                payload_id,
            )

            now = datetime.now(UTC)
            old_log_name = (
                os.path.dirname(data.logfile)
                + "/"
                + os.path.splitext(os.path.basename(data.logfile))[0]
                + now.strftime("_%Y-%m-%d_%H-%M-%S.log")
            )

            os.rename(data.logfile, old_log_name)

    # Save the updated payload back to the list (or database)
    result = PAYLOAD_LIST.update_payload_item(
        index=payload_id,
        update_data=update_data,
    )  # Assumes a method to update the payload
    if not result:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Failed to update Payload with ID -> {} with data -> {}".format(
                payload_id,
                update_data,
            ),
        )

    return UpdatedPayloadListItem(
        message="Payload updated successfully",
        payload=PayloadListItem(index=payload_id, **PAYLOAD_LIST.get_payload_item(index=payload_id)),
        updated_fields=update_data,
    )


@router.delete(path="/{payload_id}")
async def delete_payload_item(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> JSONResponse:
    """Delete an existing payload item.

    Args:
        user (Optional[User]): User performing the update.
        payload_id (int): The ID of the payload to update.

    Returns:
        dict: response or None

    """

    # Check if the payload exists
    result = PAYLOAD_LIST.remove_payload_item(payload_id)
    if not result:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload with ID -> {} not found.".format(payload_id),
        )


@router.put(path="/{payload_id}/up")
async def move_payload_item_up(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> dict:
    """Move a payload item up in the list.

    Args:
        user: Annotated[User, Depends(get_authorized_user)]
        payload_id (int): payload item ID

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict: HTTP response

    """

    position = PAYLOAD_LIST.move_payload_item_up(index=payload_id)

    if position is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload item with index -> {} is either out of range or is already on top of the payload list!".format(
                payload_id,
            ),
        )

    return {"result": {"new_position": position}}


@router.put(path="/{payload_id}/down")
async def move_payload_item_down(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> dict:
    """Move a payload item down in the list.

    Args:
        user: Annotated[User, Depends(get_authorized_user)]
        payload_id (int):
            The payload item ID.

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict: HTTP response

    """

    position = PAYLOAD_LIST.move_payload_item_down(index=payload_id)

    if position is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload item with index -> {} is either out of range or is already on bottom of the payload list!".format(
                payload_id,
            ),
        )

    return {"result": {"new_position": position}}


@router.get(path="/{payload_id}/content")
async def get_payload_content(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    # pylint: disable=unused-argument
    payload_id: int,
) -> dict | None:
    """Get a payload item based on its ID.

    Args:
        user: Annotated[User, Depends(get_authorized_user)]
        payload_id (int):
            The payload item ID.

    Raises:
        HTTPException:
            A payload item with the given ID couldn't be found.

    Returns:
        dict:
            HTTP response.

    """

    data = PAYLOAD_LIST.get_payload_item(index=payload_id)

    if data is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload with ID -> {} not found!".format(payload_id),
        )

    filename = data.filename

    return load_payload(payload_source=filename)


@router.get(path="/{payload_id}/download")
def download_payload_content(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> FileResponse:
    """Download the payload for a specific payload item."""

    payload = PAYLOAD_LIST.get_payload_item(index=payload_id)

    if payload is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload with ID -> {} not found!".format(payload_id),
        )

    if not os.path.isfile(payload.filename):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Payload file -> '{}' not found".format(payload.filename),
        )

    with open(payload.filename, encoding="UTF-8") as file:
        content = file.read()

        if payload.filename.endswith(".gz.b64"):
            content = base64.b64decode(content)
            content = gzip.decompress(content)

    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(payload.filename.removesuffix(".gz.b64"))}"',
        },
    )


@router.get(path="/{payload_id}/log")
def download_payload_logfile(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> FileResponse:
    """Download the logfile for a specific payload."""

    payload = PAYLOAD_LIST.get_payload_item(index=payload_id)

    if payload is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Payload not found")

    filename = payload.logfile

    if not os.path.isfile(filename):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Log file -> '{}' not found".format(filename),
        )
    with open(filename, encoding="UTF-8") as file:
        content = file.read()
    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"',
        },
    )


@router.get(path="/{payload_id}/log/stream")
async def stream_logfile(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> StreamingResponse:
    """Stream the logfile and follow changes."""

    payload = PAYLOAD_LIST.get_payload_item(index=payload_id)

    if payload is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Payload not found")

    filename = payload.logfile

    if os.path.isfile(filename):
        return StreamingResponse(tail_log(filename), media_type="text/plain")

    raise HTTPException(status_code=HTTPStatus.NOT_FOUND)
