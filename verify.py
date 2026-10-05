"""One-shot acceptance check for the APNG audit service.

Runs, in order, and summarizes the result in its process exit code:

  1. the unit/integration test suite,
  2. a byte-compile ("build") check of every application module,
  3. a valid animation submitted to POST /api/apng/audit (expects HTTP 200
     with a stable, ordered frame report and SHA-256 digests),
  4. an animation with a corrupted sequence number (expects HTTP 422 with a
     ``chunk`` locator and no partial frame list).

Exits 0 only when every step succeeds; exits 1 otherwise. Intended to be
run as a one-shot Compose service (``verify``) against a cleanly started
stack.
"""

from __future__ import annotations

import hashlib
import json
import os
import py_compile
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVICE_URL = os.environ.get("SERVICE_URL", "http://web:8080").rstrip("/")
AUDIT_URL = f"{SERVICE_URL}/api/apng/audit"
HEALTH_URL = f"{SERVICE_URL}/health"

RESULTS: list[tuple[str, bool, str]] = []


def step(name: str):
    def decorator(fn):
        def wrapper():
            try:
                detail = fn() or ""
                RESULTS.append((name, True, detail))
                print(f"[PASS] {name} {detail}".rstrip())
            except Exception as exc:  # noqa: BLE001
                RESULTS.append((name, False, str(exc)))
                print(f"[FAIL] {name}: {exc}")
        return wrapper
    return decorator


@step("unit and integration tests")
def run_tests() -> str:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise RuntimeError(
            f"{len(result.failures)} failure(s), {len(result.errors)} error(s)"
        )
    return f"({result.testsRun} tests)"


@step("byte-compile build")
def run_build() -> str:
    failed = []
    for module in (ROOT / "app").glob("*.py"):
        try:
            py_compile.compile(str(module), doraise=True)
        except py_compile.PyCompileError as exc:
            failed.append(f"{module.name}: {exc}")
    py_compile.compile(str(ROOT / "verify.py"), doraise=True)
    if failed:
        raise RuntimeError("; ".join(failed))
    return "(app package + verify.py)"


def _post(body: bytes) -> tuple[int, dict]:
    req = urllib.request.Request(
        AUDIT_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "image/apng"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@step("valid animation accepted")
def submit_valid() -> str:
    from app.apng import parse_apng
    from app.apng_build import build_apng

    blob = build_apng(num_plays=3)
    status, report = _post(blob)
    if status != 200:
        raise RuntimeError(f"expected 200, got {status}: {report}")
    if report["canvas"]["width"] != 16 or report["canvas"]["height"] != 16:
        raise RuntimeError(f"unexpected canvas: {report['canvas']}")
    if report["num_frames"] != 3 or report["num_plays"] != 3:
        raise RuntimeError("num_frames/num_plays mismatch")
    frames = report.get("frames")
    if not isinstance(frames, list) or len(frames) != 3:
        raise RuntimeError("ordered frame list missing or wrong length")
    expected = parse_apng(blob)
    for order, (entry, frame) in enumerate(zip(frames, expected.frames)):
        if entry["index"] != order:
            raise RuntimeError(f"frame {order} out of order")
        want = hashlib.sha256(frame.data).hexdigest()
        if entry["compressed_data_sha256"] != want:
            raise RuntimeError(f"frame {order} SHA-256 mismatch")
        if entry["delay"]["den"] != 100:
            raise RuntimeError("normalized delay denominator wrong")
    rects = [f["rect"] for f in frames]
    if rects[0]["x"] != 0 or rects[1]["x"] != 8:
        raise RuntimeError("frame rectangles not reported in stream order")
    return "(3 frames, 200, digests verified)"


@step("corrupted sequence rejected with chunk locator")
def submit_corrupt() -> str:
    from app.apng_build import build_apng

    # Second fcTL gets sequence number 42 instead of 1.
    blob = build_apng(
        frames=[
            {"width": 4, "height": 4},
            {"width": 4, "height": 4, "seq": 42},
        ]
    )
    status, report = _post(blob)
    if status != 422:
        raise RuntimeError(f"expected 422, got {status}: {report}")
    if not isinstance(report.get("chunk"), int):
        raise RuntimeError(f"error response lacks chunk ordinal: {report}")
    if "frames" in report:
        raise RuntimeError("422 response must not contain a frame list")
    return f"(422 at chunk {report['chunk']}, no partial frames)"


@step("service healthy")
def wait_for_healthy(timeout: float | None = None) -> str:
    if timeout is None:
        timeout = float(os.environ.get("HEALTH_TIMEOUT", "30"))
    deadline = time.monotonic() + timeout
    last_error = "not started"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=3) as resp:
                if resp.status == 200:
                    return f"({HEALTH_URL})"
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(0.5)
    raise RuntimeError(f"service did not become healthy: {last_error}")


def main() -> int:
    print(f"verify: target service = {SERVICE_URL}")
    run_tests()
    run_build()
    wait_for_healthy()
    if all(ok for _, ok, _ in RESULTS):
        submit_valid()
        submit_corrupt()

    print("\n--- verify summary ---")
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name} {detail}".rstrip())
    failed = [name for name, ok, _ in RESULTS if not ok]
    if failed:
        print(f"\nverify FAILED: {len(failed)}/{len(RESULTS)} step(s)")
        return 1
    print(f"\nverify OK: all {len(RESULTS)} steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
