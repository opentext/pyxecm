"""API Implemenation for the Customizer to start and control the payload processing.

Endpoints:

GET  /app/v1/payload - get processing list of payloads
POST /app/v1/payload - add new payload to processing list
GET  /api/v1/payload/{payload_id} - get a specific payload
GET  /api/v1/payload/{payload_id}/content - get a specific payload content
GET  /api/v1/payload/{payload_id}/log - get a specific payload content
GET  /api/v1/payload/{payload_id}/log - get a specific payload content

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import shutil
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from importlib.metadata import version
from threading import Thread
from typing import Annotated, Literal

import uvicorn
import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import OAuth2PasswordBearer
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import HttpUrl, ValidationError

from pyxecm.customizer import K8s
from pyxecm.customizer.api import auth, models
from pyxecm.customizer.api.metrics import payload_logs_by_payload, payload_logs_total
from pyxecm.customizer.api.payload_list import PayloadList
from pyxecm.customizer.api.settings import api_settings
from pyxecm.customizer.exceptions import PayloadImportError
from pyxecm.customizer.payload import load_payload
from pyxecm.maintenance_page import run_maintenance_page
from pyxecm.maintenance_page import settings as maint_settings

# Check if Temp dir exists
if not os.path.exists(api_settings.temp_dir):
    os.makedirs(api_settings.temp_dir)

# Check if Logfile and folder exists and is unique
if os.path.isfile(os.path.join(api_settings.logfolder, api_settings.logfile)):
    customizer_start_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d_%H-%M",
    )
    api_settings.logfile = f"customizer_{customizer_start_time}.log"
elif not os.path.exists(api_settings.logfolder):
    os.makedirs(api_settings.logfolder)


handlers = [
    logging.FileHandler(os.path.join(api_settings.logfolder, api_settings.logfile)),
    logging.StreamHandler(sys.stdout),
]

logging.basicConfig(
    format="%(asctime)s %(levelname)s [%(name)s] [%(threadName)s] %(message)s",
    datefmt="%d-%b-%Y %H:%M:%S",
    level=api_settings.loglevel,
    handlers=handlers,
)


@asynccontextmanager
async def lifespan(  # noqa: ANN201
    app: FastAPI,
):  # pylint: disable=unused-argument,redefined-outer-name
    """Lifespan Method for FASTAPI to handle the startup and shutdown process.

    Args:
        app (FastAPI):
            The application.

    """

    app.logger.debug("Settings -> %s", api_settings)

    if api_settings.import_payload:
        app.logger.info("Importing filesystem payloads...")

        # Base Payload
        import_payload(payload=api_settings.payload)

        # External Payload
        import_payload(payload_dir=api_settings.payload_dir, dependencies=True)

        # Optional Payload
        import_payload(payload_dir=api_settings.payload_dir_optional)

    if api_settings.maintenance_mode:
        app.logger.info("Starting maintenance_page thread...")
        maint_thread = Thread(target=run_maintenance_page, name="maintenance_page")
        maint_thread.start()

    app.logger.info("Starting processing thread...")
    thread = Thread(
        target=payload_list.run_payload_processing,
        name="customization_run_api",
    )
    thread.start()

    yield
    app.logger.info("Shutdown")
    payload_list.stop_payload_processing()


app = FastAPI(
    docs_url="/api",
    title="Customizer API",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
    version=version("pyxecm"),
    openapi_tags=[
        {
            "name": "status",
            "description": "Status of Customizer",
        },
        {
            "name": "auth",
            "description": "Authentication Endpoint - Users are authenticated against Opentext Directory Services",
        },
        {
            "name": "payload",
            "description": "Get status and manipulate payload objects ",
        },
        {
            "name": "maintenance",
            "description": "Enable, disable or alter the maintenance mode.",
        },
    ],
)
app.logger = logging.getLogger("CustomizerAPI")
app.add_middleware(
    CORSMiddleware,
    allow_origins=api_settings.trusted_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.k8s_object = K8s(logger=app.logger, namespace=api_settings.namespace)
app.include_router(auth.router)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize the globel Payloadlist object
payload_list = PayloadList(logger=app.logger)

if api_settings.metrics:
    # Add Prometheus Instrumentator for /metrics
    instrumentator = Instrumentator().instrument(app).expose(app)
    instrumentator.add(payload_logs_by_payload(payload_list))
    instrumentator.add(payload_logs_total(payload_list))


@app.get(path="/status", name="Get Status", tags=["status"])
async def get_status() -> dict:
    """Get the status of the Customizer."""

    df = payload_list.get_payload_items()

    if df is None:
        raise HTTPException(
            status_code=500,
            detail="Payload list is empty.",
        )

    all_status = df["status"].value_counts().to_dict()

    return {
        "version": "2",
        "customizer_duration": (all_status.get("running", None)),
        "customizer_end_time": None,
        "customizer_start_time": None,
        "status_details": all_status,
        "status": "Running" if "running" in all_status else "Stopped",
        "debug": df["log_debug"].sum(),
        "info": df["log_info"].sum(),
        "warning": df["log_warning"].sum(),
        "error": df["log_error"].sum(),
        "critical": df["log_critical"].sum(),
    }


def import_payload(
    payload: str | None = None,
    payload_dir: str | None = None,
    enabled: bool | None = None,
    dependencies: bool | None = None,
) -> None:
    """Automatically load payload items from disk of a given directory.

    Args:
        payload (str):
            The name of the payload.
        payload_dir (str):
            The local path.
        enabled (bool, optional):
            Automatically start the processing (True), or only define items (False).
            Defaults to False.
        dependencies (bool, optional):
            Automatically add dependency on the last payload in the queue

    """

    def import_payload_file(
        filename: str,
        enabled: bool | None,
        dependencies: bool | None,
    ) -> None:
        if not os.path.isfile(filename):
            return

        if not (filename.endswith((".yaml", ".tfvars", ".tf", ".yml.gz.b64"))):
            app.logger.debug("Skipping file: %s", filename)
            return

        # Load payload file
        payload_content = load_payload(filename)
        if payload_content is None:
            exception = f"The import of payload -> {filename} failed. Payload content could not be loaded."
            raise PayloadImportError(exception)

        payload_options = payload_content.get("payloadOptions", {})

        if enabled is None:
            enabled = payload_options.get("enabled", True)

        # read name from options section if specified, otherwise take filename
        name = payload_options.get("name", os.path.basename(filename))

        # Get the loglevel from payloadOptions if set, otherwise use the default loglevel
        loglevel = payload_options.get("loglevel", api_settings.loglevel)

        # Get the git_url
        git_url = payload_options.get("git_url", None)

        # Dependency Management
        if dependencies is None:
            dependencies = []

            # Get all dependencies from payloadOptions and resolve their ID
            for dependency_name in payload_options.get("dependencies", []):
                dependend_item = payload_list.get_payload_item_by_name(dependency_name)

                if dependend_item is None:
                    exception = (
                        f"The import of payload -> {name} failed. Dependencies cannot be resovled: {dependency_name}",
                    )
                    raise PayloadImportError(
                        exception,
                    )
                # Add the ID to the list of dependencies
                dependencies.append(dependend_item["index"])

        elif dependencies:
            try:
                payload_items = len(payload_list.get_payload_items()) - 1
                dependencies = [payload_items] if payload_items != -1 else []
            except Exception:
                dependencies = []
        else:
            dependencies = []

        app.logger.info("Adding payload: %s", filename)
        payload = payload_list.add_payload_item(
            name=name,
            filename=filename,
            status="planned",
            logfile=f"{api_settings.logfolder}/{name}.log",
            dependencies=dependencies,
            enabled=enabled,
            git_url=git_url,
            loglevel=loglevel,
        )
        dependencies = payload["index"]

        return

    if payload is None and payload_dir is None:
        exception = "No payload or payload_dir provided"
        raise ValueError(exception)

    if payload and os.path.isdir(payload) and payload_dir is None:
        payload_dir = payload

    if payload_dir is None:
        import_payload_file(payload, enabled, dependencies)
        return
    elif not os.path.isdir(payload_dir):
        return

    for filename in sorted(os.listdir(payload_dir)):
        try:
            import_payload_file(os.path.join(payload_dir, filename), enabled, dependencies)
        except PayloadImportError:
            app.logger.error("Payload import failed")


def prepare_dependencies(dependencies: list) -> list | None:
    """Convert the dependencies string to a list of integers."""
    try:
        list_all = dependencies[0].split(",")
    except IndexError:
        return None

    # Remove empty values from the list
    items = list(filter(None, list_all))
    converted_list = []
    for item in items:
        try:
            converted_list.append(int(item))
        except ValueError:
            continue

    return converted_list


@app.post(path="/api/v1/payload", status_code=201, tags=["payload"])
def create_payload_item(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
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
) -> dict:
    """Upload a new payload item.

    Args:
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
        user (models.User, optional):
            The user who is uploading the payload. Defaults to None.

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
    file_name = os.path.join(api_settings.temp_dir, f"{name}{file_extension}")

    with open(file_name, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    if dependencies == [-1]:
        dependencies = []

    return payload_list.add_payload_item(
        name=name,
        filename=file_name,
        status="planned",
        logfile=os.path.join(api_settings.temp_dir, "{}.log".format(name)),
        dependencies=dependencies or [],
        enabled=enabled,
        loglevel=loglevel,
    )


@app.get(path="/api/v1/payload", tags=["payload"])
async def get_payload_items(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
) -> dict:
    """Get all Payload items.

    Raises:
        HTTPException: payload list not initialized
        HTTPException: payload list is empty

    Returns:
        dict:
            HTTP response with the result data

    """

    df = payload_list.get_payload_items()

    if df is None:
        raise HTTPException(
            status_code=500,
            detail="Payload list is empty.",
        )

    data = [{"index": idx, **row} for idx, row in df.iterrows()]

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

    return {"stats": stats, "results": data}


@app.get(path="/api/v1/payload/{payload_id}", tags=["payload"])
async def get_payload_item(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> dict:
    """Get a payload item based on its ID.

    Args:
        user: Annotated[models.User, Depends(auth.get_authorized_user)]
        payload_id (int): payload item ID

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict:
            HTTP response.

    """
    data = payload_list.get_payload_item(index=payload_id)

    if data is None:
        raise HTTPException(
            status_code=404,
            detail="Payload with index -> {} not found".format(payload_id),
        )

    return {"index": payload_id, **data}


@app.put(path="/api/v1/payload/{payload_id}", status_code=200, tags=["payload"])
async def update_payload_item(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
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
) -> dict:
    """Update an existing payload item.

    Args:
        user (Optional[models.User]): User performing the update.
        payload_id (int): ID of the payload to update.
        upload_file (UploadFile, optional): replace the file name
        name (Optional[str]): Updated name.
        dependencies (Optional[List[int]]): Updated list of dependencies.
        enabled (Optional[bool]): Updated enabled status.
        loglevel (Optional[str]): Updated loglevel.
        status (Optional[str]): Updated status.

    Returns:
        dict: HTTP response with the updated payload details.

    """

    if dependencies:
        dependencies = prepare_dependencies(dependencies)
    # Check if the payload exists
    payload_item = payload_list.get_payload_item(
        payload_id,
    )  # Assumes a method to retrieve payload by ID
    if payload_item is None:
        raise HTTPException(
            status_code=404,
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

    if "status" in update_data and update_data["status"] == "planned":
        app.logger.info("Resetting log message counters for -> %s", payload_id)
        update_data["log_debug"] = 0
        update_data["log_info"] = 0
        update_data["log_warning"] = 0
        update_data["log_error"] = 0
        update_data["log_critical"] = 0

        update_data["start_time"] = None
        update_data["stop_time"] = None
        update_data["duration"] = None

        data = payload_list.get_payload_item(index=payload_id)
        if os.path.isfile(data.logfile):
            app.logger.info(
                "Deleting log file (for payload) -> %s (%s)",
                data.logfile,
                payload_id,
            )

            now = datetime.now(timezone.utc)
            old_log_name = (
                os.path.dirname(data.logfile)
                + "/"
                + os.path.splitext(os.path.basename(data.logfile))[0]
                + now.strftime("_%Y-%m-%d_%H-%M-%S.log")
            )

            os.rename(data.logfile, old_log_name)

    # Save the updated payload back to the list (or database)
    result = payload_list.update_payload_item(
        index=payload_id,
        update_data=update_data,
    )  # Assumes a method to update the payload
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Failed to update Payload with ID -> {} with data -> {}".format(
                payload_id,
                update_data,
            ),
        )

    return {
        "message": "Payload updated successfully",
        "payload": {**payload_list.get_payload_item(index=payload_id)},
        "updated_fields": update_data,
    }


@app.delete(path="/api/v1/payload/{payload_id}", status_code=204, tags=["payload"])
async def delete_payload_item(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> JSONResponse:
    """Delete an existing payload item.

    Args:
        user (Optional[models.User]): User performing the update.
        payload_id (int): The ID of the payload to update.

    Returns:
        dict: response or None

    """

    # Check if the payload exists
    result = payload_list.remove_payload_item(payload_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Payload with ID -> {} not found.".format(payload_id),
        )


@app.put(path="/api/v1/payload/{payload_id}/up", tags=["payload"])
async def move_payload_item_up(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> dict:
    """Move a payload item up in the list.

    Args:
        user: Annotated[models.User, Depends(auth.get_authorized_user)]
        payload_id (int): payload item ID

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict: HTTP response

    """

    position = payload_list.move_payload_item_up(index=payload_id)

    if position is None:
        raise HTTPException(
            status_code=404,
            detail="Payload item with index -> {} is either out of range or is already on top of the payload list!".format(
                payload_id,
            ),
        )

    return {"result": {"new_position": position}}


@app.put(path="/api/v1/payload/{payload_id}/down", tags=["payload"])
async def move_payload_item_down(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> dict:
    """Move a payload item down in the list.

    Args:
        user: Annotated[models.User, Depends(auth.get_authorized_user)]
        payload_id (int):
            The payload item ID.

    Raises:
        HTTPException: a payload item with the given ID couldn't be found

    Returns:
        dict: HTTP response

    """

    position = payload_list.move_payload_item_down(index=payload_id)

    if position is None:
        raise HTTPException(
            status_code=404,
            detail="Payload item with index -> {} is either out of range or is already on bottom of the payload list!".format(
                payload_id,
            ),
        )

    return {"result": {"new_position": position}}


@app.get(path="/api/v1/payload/{payload_id}/content", tags=["payload"])
async def get_payload_content(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    # pylint: disable=unused-argument
    payload_id: int,
) -> dict | None:
    """Get a payload item based on its ID.

    Args:
        user: Annotated[models.User, Depends(auth.get_authorized_user)]
        payload_id (int):
            The payload item ID.

    Raises:
        HTTPException:
            A payload item with the given ID couldn't be found.

    Returns:
        dict:
            HTTP response.

    """

    data = payload_list.get_payload_item(index=payload_id)

    if data is None:
        raise HTTPException(
            status_code=404,
            detail="Payload with ID -> {} not found!".format(payload_id),
        )

    filename = data.filename

    return load_payload(payload_source=filename)


@app.get(path="/api/v1/payload/{payload_id}/download", tags=["payload"])
def download_payload_content(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> FileResponse:
    """Download the payload for a specific payload item."""

    payload = payload_list.get_payload_item(index=payload_id)

    if payload is None:
        raise HTTPException(
            status_code=404,
            detail="Payload with ID -> {} not found!".format(payload_id),
        )

    if not os.path.isfile(payload.filename):
        raise HTTPException(
            status_code=404,
            detail="Payload file -> '{}' not found".format(payload.filename),
        )
    with open(payload.filename, encoding="UTF-8") as file:
        content = file.read()
    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(payload.filename)}"',
        },
    )


@app.get(path="/api/v1/payload/{payload_id}/log", tags=["payload"])
def download_payload_logfile(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
    payload_id: int,
) -> FileResponse:
    """Download the logfile for a specific payload."""

    payload = payload_list.get_payload_item(index=payload_id)

    if payload is None:
        raise HTTPException(status_code=404, detail="Payload not found")

    filename = payload.logfile

    if not os.path.isfile(filename):
        raise HTTPException(
            status_code=404,
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


def get_cshost() -> str:
    """Get the cs_hostname from the environment Variable OTCS_PUBLIC_HOST otherwise read it from the otcs-frontend-configmap."""

    if "OTCS_PUBLIC_URL" in os.environ:
        return os.getenv("OTCS_PUBLIC_URL", "otcs")

    else:
        cm = app.k8s_object.get_config_map("otcs-frontend-configmap")

        if cm is None:
            raise HTTPException(
                status_code=500,
                detail=f"Could not read otcs-frontend-configmap from namespace: {app.k8s_object.get_namespace()}",
            )

        config_file = cm.data.get("config.yaml")
        config = yaml.safe_load(config_file)

        try:
            cs_url = HttpUrl(config.get("csurl"))
        except ValidationError as ve:
            raise HTTPException(
                status_code=500,
                detail="Could not read otcs_host from environment variable OTCS_PULIBC_URL or configmap otcs-frontend-configmap/config.yaml/cs_url",
            ) from ve
        return cs_url.host


def __get_maintenance_mode_status() -> dict:
    """Get status of maintenance mode.

    Returns:
        dict:
            Details of maintenance mode.

    """
    ingress = app.k8s_object.get_ingress("otxecm-ingress")

    if ingress is None:
        raise HTTPException(
            status_code=500,
            detail="No ingress object found to read Maintenance Mode status",
        )

    enabled = False
    for rule in ingress.spec.rules:
        if rule.host == get_cshost():
            enabled = rule.http.paths[0].backend.service.name != "otcs-frontend"

    return {
        "enabled": enabled,
        "title": maint_settings.title,
        "text": maint_settings.text,
        "footer": maint_settings.footer,
    }


@app.get(path="/api/v1/maintenance", tags=["maintenance"])
async def get_maintenance_mode_status(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # noqa: ARG001
) -> JSONResponse:
    """Return status of maintenance mode.

    Returns:
        dict:
            Details of maintenance mode.

    """

    return __get_maintenance_mode_status()


def set_maintenance_mode_via_ingress(enabled: bool) -> None:
    """Set maintenance mode."""

    app.logger.warning(
        "Setting Maintenance Mode to -> %s",
        (enabled),
    )

    if enabled:
        app.k8s_object.update_ingress_backend_services(
            "otxecm-ingress",
            get_cshost(),
            "otxecm-customizer",
            5555,
        )
    else:
        app.k8s_object.update_ingress_backend_services(
            "otxecm-ingress",
            get_cshost(),
            "otcs-frontend",
            80,
        )


@app.post(path="/api/v1/maintenance", tags=["maintenance"])
async def set_maintenance_mode_options(
    user: Annotated[models.User, Depends(auth.get_authorized_user)],  # pylint: disable=unused-argument  # noqa: ARG001
    enabled: Annotated[bool, Form()],
    title: Annotated[str | None, Form()] = "",
    text: Annotated[str | None, Form()] = "",
    footer: Annotated[str | None, Form()] = "",
) -> dict:
    """Configure the Maintenance Mode and set options.

    Args:
        user (models.User):
            Added to enforce authentication requirement
        enabled (bool, optional):
            Enable or disable the maintenance mode to allow access to the OTCS Frontend.
        title (Optional[str], optional):
            Title for the Maintenance Page.
        text (Optional[str], optional):
            Text for the Maintenance Page.
        footer (Optional[str], optional):
            Text for the Footer of the Maintenance Page.

    Returns:
        dict: _description_

    """
    # Enable / Disable the acutual Maintenance Mode
    set_maintenance_mode_via_ingress(enabled)

    if title is not None and title != "":
        maint_settings.title = title

    if text is not None and text != "":
        maint_settings.text = text

    if footer is not None:
        maint_settings.footer = footer

    return __get_maintenance_mode_status()


@app.get("/api/shutdown", include_in_schema=False)
def shutdown(user: Annotated[models.User, Depends(auth.get_authorized_user)]) -> JSONResponse:
    """Endpoint to end the application."""

    app.logger.warning(
        "Shutting down the API - Requested via api by user -> %s",
        user.id,
    )
    os.kill(os.getpid(), signal.SIGTERM)

    return JSONResponse()


def run_api() -> None:
    """Start the FASTAPI Webserver."""

    uvicorn.run("pyxecm.customizer.api:app", host=api_settings.bind_address, port=api_settings.bind_port)
