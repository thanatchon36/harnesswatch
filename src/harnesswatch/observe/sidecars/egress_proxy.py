"""Egress sidecar: an HTTP(S) forward proxy that allows only the model host and logs everything.

Bench containers sit on an internal Docker network with no route out; HTTP(S)_PROXY points here.
Allowed: CONNECT/requests to hosts in HW_ALLOW (default `ollama:11434`). Everything else gets 403.
Every request is logged to /log/egress.jsonl as host, port, method and action only: no paths,
headers or bodies (ASSUMPTIONS A17). Standard library only, so it runs in a stock python image.
"""

import json
import os
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ALLOW = {h.strip() for h in os.environ.get("HW_ALLOW", "ollama:11434").split(",") if h.strip()}
LOG = os.environ.get("HW_EGRESS_LOG", "/log/egress.jsonl")
LOCK = threading.Lock()


def log(entry: dict[str, object]) -> None:
    entry["t"] = time.time()
    with LOCK, open(LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


class Proxy(BaseHTTPRequestHandler):
    def _target(self) -> tuple[str, int]:
        try:
            if self.command == "CONNECT":
                host, _, port = self.path.partition(":")
                return host, int(port or 443)
            parts = urlsplit(self.path)
            return parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:  # malformed target: still blocked, and now logged
            return "<malformed>", 0

    def _allowed(self, host: str, port: int) -> bool:
        return f"{host}:{port}" in ALLOW

    def _deny(self, host: str, port: int) -> None:
        log({"action": "blocked", "method": self.command, "host": host, "port": port})
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_CONNECT(self) -> None:
        host, port = self._target()
        if not self._allowed(host, port):
            return self._deny(host, port)
        log({"action": "allowed", "method": "CONNECT", "host": host, "port": port})
        upstream = socket.create_connection((host, port), timeout=600)
        self.send_response(200, "Connection established")
        self.end_headers()
        sockets = [self.connection, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 600)
            if not readable:
                break
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    upstream.close()
                    return
                (upstream if sock is self.connection else self.connection).sendall(data)

    def _forward(self) -> None:
        host, port = self._target()
        if not self._allowed(host, port):
            return self._deny(host, port)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        parts = urlsplit(self.path)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        upstream = socket.create_connection((host, port), timeout=600)
        headers = "".join(
            f"{k}: {v}\r\n" for k, v in self.headers.items() if k.lower() != "proxy-connection"
        )
        upstream.sendall(f"{self.command} {path} HTTP/1.1\r\n{headers}\r\n".encode() + body)
        log({"action": "allowed", "method": self.command, "host": host, "port": port})
        while chunk := upstream.recv(65536):
            self.connection.sendall(chunk)
        upstream.close()
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _forward

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 3128), Proxy).serve_forever()
