"""Define a websocket to connect to a shell session in a pod."""

import asyncio
import contextlib
import json
import os
import pty
import signal
import subprocess

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from pyxecm_api.auth.functions import get_authorized_user, get_current_user

router = APIRouter(tags=["terminal"])


@router.websocket("/ws/terminal")
async def ws_terminal(
    websocket: WebSocket, pod: str = Query(...), command: str = Query(...), container: str = Query(None)
) -> None:
    """Websocket to connect to a shell session in a pod.

    Args:
        websocket (WebSocket): WebSocket to connect to the shell session.
        pod (str): pod name to connect to.
        command (str): command to be executed.
        container (str, optional): container name to connect to.

    """
    await websocket.accept()

    try:
        # Wait for the first message to be the token
        token = await websocket.receive_text()

        user = await get_current_user(token=token, api_key=token)
        authrorized = await get_authorized_user(user)

        if not authrorized:
            await websocket.send_text("Invalid User: " + str(user))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    except HTTPException:
        await websocket.send_text("Invalid Token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)

    except WebSocketDisconnect:
        return

    container = ["-c", container] if container else []

    process = [command] if pod == "customizer" else ["kubectl", "exec", "-it", pod, *container, "--", command]

    pid, fd = pty.fork()
    import fcntl
    import struct
    import termios

    if pid == 0:
        process = subprocess.run(process, check=False)  # noqa: ASYNC221

    async def read_from_pty() -> None:
        loop = asyncio.get_event_loop()
        try:
            while True:
                data = await loop.run_in_executor(None, os.read, fd, 1024)
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
            process.terminate()

        with contextlib.suppress(Exception):
            os.kill(pid, signal.SIGKILL)

        with contextlib.suppress(Exception):
            os.close(fd)
