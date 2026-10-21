"""Define a websocket to connect to a shell session in a pod."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import contextlib
import json
import os
import pty
import shutil
import signal

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from pyxecm_api.auth.functions import get_authorized_user, get_current_user
from pyxecm_api.pods.functions import MAX_PATH_LENGTH, is_container_name, is_pod_name

router = APIRouter(tags=["terminal"])

# Starts the command in the folder $1 (if it can be opened), then runs the command $2.
CWD_SCRIPT = 'cd -- "$1" 2>/dev/null || echo "Cannot open the folder $1" >&2; exec "$2"'


def local_executable(command: str) -> str:
    """Find a command to run in the Customizer container.

    A path that does not exist (anymore) falls back to the command's name on the PATH: the manager
    asked for k9s at /root/.local/bin/k9s, where older images installed it.

    Args:
        command (str): command name, or path of the executable.

    Returns:
        str: The executable to run.

    """

    if os.sep in command and not os.access(command, os.X_OK):
        return shutil.which(os.path.basename(command)) or command
    return command


def valid_cwd(cwd: str | None) -> bool:
    """Check the folder a terminal is asked to start in."""

    return cwd is None or (cwd.startswith("/") and "\0" not in cwd and len(cwd) <= MAX_PATH_LENGTH)


@router.websocket("/ws/terminal")
async def ws_terminal(
    websocket: WebSocket,
    pod: str = Query(...),
    command: str = Query(...),
    container: str = Query(None),
    cwd: str = Query(None),
) -> None:
    """Websocket to connect to a shell session in a pod.

    Args:
        websocket (WebSocket): WebSocket to connect to the shell session.
        pod (str): pod name to connect to.
        command (str): command to be executed.
        container (str, optional): container name to connect to.
        cwd (str, optional): folder to start the command in (absolute).

    """
    await websocket.accept()

    # A pod or container name is checked, so that it cannot be taken for an option of kubectl.
    if (
        (pod != "customizer" and not is_pod_name(pod))
        or (container is not None and not is_container_name(container))
        or not valid_cwd(cwd)
    ):
        await websocket.send_text("Invalid pod, container or folder")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        # Wait for the first message to be the token
        token = await websocket.receive_text()

        # get_current_user is sync (blocking HTTP call to OTDS) - run it off the event loop
        user = await asyncio.to_thread(get_current_user, token=token, api_key=token)
        await get_authorized_user(user)

    except HTTPException as e:
        await websocket.send_text("Invalid Token" if e.status_code == status.HTTP_401_UNAUTHORIZED else e.detail)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    except WebSocketDisconnect:
        return

    container = ["-c", container] if container else []

    if pod == "customizer":
        process = [local_executable(command)]
    elif cwd:
        process = ["kubectl", "exec", "-it", pod, *container, "--", "sh", "-c", CWD_SCRIPT, "sh", cwd, command]
    else:
        process = ["kubectl", "exec", "-it", pod, *container, "--", command]

    pid, fd = pty.fork()
    import fcntl
    import struct
    import termios

    if pid == 0:
        # The child is a copy of the API process: it becomes the command, with the pty as its
        # terminal, and must never return into the code of the API.
        if pod == "customizer" and cwd:
            with contextlib.suppress(OSError):
                os.chdir(cwd)
        try:
            os.execvp(process[0], process)  # noqa: S606
        except OSError as error:
            os.write(2, "Cannot start '{}': {}\r\n".format(process[0], error).encode())
        os._exit(127)

    async def read_from_pty() -> None:
        loop = asyncio.get_event_loop()
        try:
            while True:
                data = await loop.run_in_executor(None, os.read, fd, 1024)
                if not data:
                    break  # The command ended (Linux raises an OSError instead).
                await websocket.send_text(data.decode(errors="ignore"))
        except Exception:  # noqa: S110
            pass  # PTY closed or WebSocket failed

    async def write_to_pty() -> None:
        try:
            while True:
                data = await websocket.receive_text()
                if data.startswith("{") and data.endswith("}"):
                    message = json.loads(data)
                    if message.get("type") == "resize":
                        rows = message.get("rows")
                        cols = message.get("cols")

                        packed_size = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed_size)

                else:
                    os.write(fd, data.encode())
        except Exception:  # noqa: S110
            pass

    try:
        # Launch read/write tasks
        read_task = asyncio.create_task(read_from_pty())
        write_task = asyncio.create_task(write_to_pty())

        _done, pending = await asyncio.wait([read_task, write_task], return_when=asyncio.FIRST_COMPLETED)

        # Cancel other task
        for task in pending:
            task.cancel()
    finally:
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)

        with contextlib.suppress(Exception):
            os.kill(pid, signal.SIGKILL)

        # Reap the child, so that no zombie process is left behind.
        with contextlib.suppress(Exception):
            await asyncio.to_thread(os.waitpid, pid, 0)

        with contextlib.suppress(Exception):
            os.close(fd)
