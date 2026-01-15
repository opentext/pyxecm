"""API Implemenation for the Customizer to start and control the payload processing."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import logging
import os
from collections.abc import AsyncGenerator

import anyio
from opentelemetry import trace
from pyxecm_customizer.exceptions import PayloadImportError
from pyxecm_customizer.payload import load_payload

from pyxecm_api.common.functions import PAYLOAD_LIST
from pyxecm_api.settings import api_settings

tracer = trace.get_tracer(__name__)
logger = logging.getLogger("pyxecm_api.v1_payload")

# Initialize the globel Payloadlist object


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
            logger.debug("Skipping file: %s", filename)
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
                dependend_item = PAYLOAD_LIST.get_payload_item_by_name(dependency_name)

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
                payload_items = len(PAYLOAD_LIST.get_payload_items()) - 1
                dependencies = [payload_items] if payload_items != -1 else []
            except Exception:
                dependencies = []
        else:
            dependencies = []

        customizer_settings = payload_content.get("customizerSettings", {})

        logger.info("Adding payload: %s", filename)
        payload = PAYLOAD_LIST.add_payload_item(
            name=name,
            filename=filename,
            status="planned",
            logfile=f"{api_settings.logfolder}/{name}.log",
            dependencies=dependencies,
            enabled=enabled,
            git_url=git_url,
            loglevel=loglevel,
            customizer_settings=customizer_settings,
        )
        dependencies = payload["index"]

        return

    if payload is None and payload_dir is None:
        exception = "No payload or payload_dir provided"
        raise ValueError(exception)

    if payload and os.path.isdir(payload) and payload_dir is None:
        payload_dir = payload

    if payload_dir is None:
        try:
            import_payload_file(payload, enabled, dependencies)
        except PayloadImportError as exc:
            logger.error(exc)
            logger.debug(exc, exc_info=True)
        return

    elif not os.path.isdir(payload_dir):
        return

    for filename in sorted(os.listdir(payload_dir)):
        try:
            with tracer.start_as_current_span("import_payload") as t:
                t.set_attribute("payload", filename)
                import_payload_file(os.path.join(payload_dir, filename), enabled, dependencies)
        except PayloadImportError as exc:
            logger.error(exc)
            logger.debug(exc, exc_info=True)


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


async def tail_log(file_path: str) -> AsyncGenerator[str]:
    """Asynchronously follow the log file like `tail -f`."""
    try:
        async with await anyio.open_file(file_path) as file:
            # Move the pointer to the end of the file
            await file.seek(0, os.SEEK_END)

            while True:
                # Read new line
                line = await file.readline()
                if not line:
                    # Sleep for a little while before checking for new lines
                    await asyncio.sleep(0.5)
                    continue
                yield line
    except asyncio.exceptions.CancelledError:
        pass
