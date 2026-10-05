"""HTTP service exposing POST /api/apng/audit.

Implemented with the Python standard library only, so the container image
needs no third-party packages.
"""

from __future__ import annotations

import hashlib
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .apng import APNGError, MAX_BYTES, parse_apng

AUDIT_PATH = "/api/apng/audit"
HEALTH_PATH = "/health"
APNG_CONTENT_TYPE = "image/apng"


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "APNGAuditor/1.0"
    # Every response carries Content-Length, so persistent connections are
    # safe.
    protocol_version = "HTTP/1.1"

    # ---- helpers -------------------------------------------------------

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _content_type(self) -> str:
        raw = self.headers.get("Content-Type", "")
        return raw.split(";", 1)[0].strip().lower()

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Compact single-line access log on stdout.
        print(
            "%s - %s" % (self.address_string(), fmt % args),
            flush=True,
        )

    # ---- routing -------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path.split("?", 1)[0] == AUDIT_PATH:
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "use POST to submit an APNG"},
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != AUDIT_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if self._content_type() != APNG_CONTENT_TYPE:
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {
                    "error": "Content-Type must be image/apng",
                    "chunk": None,
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "Content-Length is required", "chunk": None},
            )
            return
        if length > MAX_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": f"file exceeds the {MAX_BYTES}-byte limit",
                    "chunk": None,
                },
            )
            return

        body = self._read_exactly(length)
        if body is None:
            return  # error response already sent

        try:
            animation = parse_apng(body)
        except APNGError as exc:
            # Never leak a partial frame list: the error document is the only
            # body, and it locates the offending chunk by its ordinal.
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": exc.message, "chunk": exc.chunk},
            )
            return

        self._send_json(HTTPStatus.OK, _report(animation))

    # ---- body reading --------------------------------------------------

    def _read_exactly(self, length: int) -> bytes | None:
        remaining = length
        chunks = []
        while remaining > 0:
            block = self.rfile.read(min(remaining, 65536))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        if remaining != 0:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "request body shorter than Content-Length",
                    "chunk": None,
                },
            )
            return None
        return b"".join(chunks)


def _report(animation) -> dict:
    return {
        "canvas": {
            "width": animation.width,
            "height": animation.height,
            "bit_depth": animation.bit_depth,
            "color_type": animation.color_type,
        },
        "num_frames": animation.num_frames,
        "num_plays": animation.num_plays,
        "infinite": animation.num_plays == 0,
        "frames": [
            {
                **frame.to_dict(order),
                "compressed_data_sha256": hashlib.sha256(frame.data).hexdigest(),
            }
            for order, frame in enumerate(animation.frames)
        ],
    }


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = _Server((host, port), AuditHandler)
    print(f"APNG audit service listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    import os

    serve(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
    )
