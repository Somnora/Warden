"""Native desktop launcher for the Warden operator dashboard.

The FastAPI control plane remains bound to loopback only.  ``pywebview``
displays it in a native window, so an operator does not need a terminal or a
browser address to use Warden.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from contextlib import closing
from urllib.request import urlopen


APP_NAME = "Warden"


def find_available_port() -> int:
    """Ask the OS for an unused loopback port rather than relying on 8000."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until_ready(url: str, timeout_seconds: float = 15.0) -> None:
    """Wait for Uvicorn before loading the native window."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{url}/health", timeout=0.5) as response:  # nosec B310: fixed local URL
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Warden's local control plane did not start in time.")


def main() -> None:
    """Start a loopback-only control plane and present it in a native window."""
    try:
        import uvicorn
        import webview
    except ImportError as exc:  # pragma: no cover - packaging/runtime guidance
        raise SystemExit(
            "Desktop support is not installed. Run: pip install 'warden[desktop]'"
        ) from exc

    # A desktop package is intentionally safe to open out of the box.  A
    # customer can opt into the live Cloud Run configuration with environment
    # variables, exactly as they can in the server deployment.
    os.environ.setdefault("WARDEN_MODE", "mock")
    port = find_available_port()
    url = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(
        "warden.server:app", host="127.0.0.1", port=port, log_level="warning", access_log=False
    )
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, name="warden-control-plane", daemon=True)
    server_thread.start()

    try:
        wait_until_ready(url)
        webview.create_window(APP_NAME, url, width=1440, height=960, min_size=(1100, 720))
        webview.start()
    except Exception as exc:  # pragma: no cover - native UI failure path
        if sys.platform == "darwin":
            import tkinter.messagebox as messagebox

            messagebox.showerror(APP_NAME, str(exc))
        raise
    finally:
        server.should_exit = True
        server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
