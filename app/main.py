"""Flask front-end for the APNG audit service."""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

from .parser import MAX_BYTES, APNGValidationError, audit_apng

app = Flask(__name__)


@app.get("/health")
def health() -> tuple:
    return jsonify(status="ok"), 200


@app.post("/api/apng/audit")
def audit() -> tuple:
    content_type = (request.content_type or "").split(";", 1)[0].strip().lower()
    if content_type != "image/apng":
        return (
            jsonify(
                error="Content-Type must be image/apng",
                reason="bad_content_type",
            ),
            415,
        )

    data = request.get_data(cache=False, as_text=False)
    if not data:
        return jsonify(error="empty request body", reason="empty_body"), 400

    content_length = request.content_length
    if (content_length is not None and content_length > MAX_BYTES) or len(data) > MAX_BYTES:
        return (
            jsonify(
                error=f"file exceeds maximum size of {MAX_BYTES} bytes",
                reason="too_large",
                max_bytes=MAX_BYTES,
            ),
            413,
        )

    try:
        report = audit_apng(data)
    except APNGValidationError as exc:
        return jsonify(exc.to_response()), 422

    return jsonify(report), 200


@app.errorhandler(404)
def not_found(_err) -> tuple:
    return jsonify(error="not found", reason="not_found"), 404


@app.errorhandler(405)
def method_not_allowed(_err) -> tuple:
    return jsonify(error="method not allowed", reason="method_not_allowed"), 405


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
    )
