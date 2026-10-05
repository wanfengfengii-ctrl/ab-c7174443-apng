"""End-to-end tests for POST /api/apng/audit over real HTTP."""

import hashlib
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from app.apng import MAX_BYTES
from app.apng_build import build_apng
from app.server import AUDIT_PATH, AuditHandler
from app.apng import parse_apng


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), AuditHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _post(port: int, body: bytes, content_type: str = "image/apng"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{AUDIT_PATH}",
        data=body,
        method="POST",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class HttpAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.thread = _start_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_valid_animation_report(self):
        blob = build_apng(num_plays=0)
        status, report = _post(self.port, blob)
        self.assertEqual(status, 200)
        self.assertEqual(report["canvas"], {
            "width": 16,
            "height": 16,
            "bit_depth": 8,
            "color_type": 6,
        })
        self.assertEqual(report["num_frames"], 3)
        self.assertEqual(report["num_plays"], 0)
        self.assertTrue(report["infinite"])
        rects = [f["rect"] for f in report["frames"]]
        self.assertEqual(rects[0], {"x": 0, "y": 0, "width": 8, "height": 8})
        self.assertEqual(rects[1], {"x": 8, "y": 0, "width": 8, "height": 8})
        self.assertEqual(report["frames"][2]["dispose"], "background")
        self.assertEqual(report["frames"][2]["blend"], "over")
        # SHA-256 must match the per-frame concatenated payload.
        animation = parse_apng(blob)
        for frame, entry in zip(animation.frames, report["frames"]):
            self.assertEqual(
                entry["compressed_data_sha256"],
                hashlib.sha256(frame.data).hexdigest(),
            )
            self.assertEqual(len(entry["compressed_data_sha256"]), 64)

    def test_corrupt_sequence_returns_422_with_chunk(self):
        blob = build_apng(
            frames=[
                {"width": 4, "height": 4},
                {"width": 4, "height": 4, "seq": 42},
            ]
        )
        status, report = _post(self.port, blob)
        self.assertEqual(status, 422)
        self.assertIn("error", report)
        self.assertEqual(report["chunk"], 4)
        self.assertNotIn("frames", report)  # never a partial frame list

    def test_bad_crc_returns_422(self):
        blob = build_apng(corrupt_crc_at=3)  # IDAT of first frame
        status, report = _post(self.port, blob)
        self.assertEqual(status, 422)
        self.assertEqual(report["chunk"], 3)

    def test_trailing_data_returns_422(self):
        status, report = _post(self.port, build_apng(trailing=b"XX"))
        self.assertEqual(status, 422)
        self.assertIsNotNone(report["chunk"])

    def test_wrong_content_type(self):
        status, report = _post(self.port, build_apng(), "application/octet-stream")
        self.assertEqual(status, 415)
        self.assertNotIn("frames", report)

    def test_oversize_body(self):
        # Build a Content-Length lie via a raw socket request so the server
        # rejects before reading 8 MiB+.
        import socket

        size = MAX_BYTES + 1
        request = (
            f"POST {AUDIT_PATH} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: image/apng\r\n"
            f"Content-Length: {size}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(request)
            s.sendall(b"\x00" * 4096)
            data = b""
            while True:
                block = s.recv(65536)
                if not block:
                    break
                data += block
        head, _, _ = data.partition(b"\r\n\r\n")
        self.assertIn(b"413", head.split(b"\r\n", 1)[0])

    def test_health_endpoint(self):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/health", timeout=5
        ) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read()), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
