"""Client für siem-hostd (Unix-Socket, eine JSON-Zeile je Anfrage). Nur Allowlist-Aktionen."""

from __future__ import annotations

import json
import socket
from typing import Any


class HostdUnavailable(Exception):
    pass


class HostdRejected(Exception):
    pass


def call(socket_path: str, action: str, params: dict[str, Any], actor: str, timeout: float = 30.0) -> Any:
    family = getattr(socket, "AF_UNIX", None)  # fehlt unter Windows (nur Entwicklung)
    if family is None:
        raise HostdUnavailable("Unix-Sockets nicht verfügbar")
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall((json.dumps({"action": action, "params": params, "actor": actor}) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        raise HostdUnavailable(str(exc)) from exc
    try:
        resp = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise HostdUnavailable("ungültige Antwort") from exc
    if not resp.get("ok"):
        raise HostdRejected(str(resp.get("error", ""))[:200])
    return resp["result"]
