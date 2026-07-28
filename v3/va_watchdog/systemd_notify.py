from __future__ import annotations

import os
import socket


_NOTIFY_SOCKET = os.environ.pop("NOTIFY_SOCKET", "")


def notify(message: str) -> bool:
    notify_socket = _NOTIFY_SOCKET
    if not notify_socket:
        return False
    address = notify_socket
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode("utf-8"))
        return True
    except Exception:
        return False
