"""Helpers + tests for the strict APNG auditor.

The builders here construct APNG byte streams chunk-by-chunk so that
individual tests can scramble ordering, CRCs and sequence numbers.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from app.main import app as flask_app
from app.parser import MAX_BYTES, APNGValidationError, audit_apng

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def chunk(ctype: bytes, body: bytes, data: bytes | None = None) -> bytes:
    payload = body if data is None else data
    crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)


def ihdr(w: int = 4, h: int = 4, depth: int = 8, color: int = 6) -> bytes:
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, color, 0, 0, 0))


def actl(num_frames: int, num_plays: int = 0) -> bytes:
    return chunk(b"acTL", struct.pack(">II", num_frames, num_plays))


def fctl(
    seq: int,
    w: int = 4,
    h: int = 4,
    x: int = 0,
    y: int = 0,
    dnum: int = 1,
    dden: int = 10,
    dispose: int = 0,
    blend: int = 0,
) -> bytes:
    return chunk(
        b"fcTL",
        struct.pack(">IIIIIHHBB", seq, w, h, x, y, dnum, dden, dispose, blend),
    )


def idat(payload: bytes) -> bytes:
    return chunk(b"IDAT", payload)


def fdat(seq: int, payload: bytes) -> bytes:
    return chunk(b"fdAT", struct.pack(">I", seq) + payload)


def raw_rgba(w: int, h: int, pixel: bytes = b"\xff\x00\x00\xff") -> bytes:
    return (b"\x00" + pixel * w) * h


def zpayload(w: int = 4, h: int = 4) -> bytes:
    return zlib.compress(raw_rgba(w, h))


def iend() -> bytes:
    return chunk(b"IEND", b"")


def build_valid(
    specs: list[dict] | None = None,
    canvas=(4, 4),
    num_plays: int = 3,
    include_actl: bool = True,
    actl_frames: int | None = None,
    trailing: bytes = b"",
    signature: bytes = PNG_SIG,
) -> bytes:
    """Build a valid multi-frame APNG; specs override frame geometry."""
    if specs is None:
        specs = [
            dict(w=4, h=4, x=0, y=0, dnum=1, dden=10, dispose=0, blend=0),
            dict(w=2, h=2, x=1, y=1, dnum=2, dden=10, dispose=1, blend=1),
            dict(w=4, h=2, x=0, y=2, dnum=5, dden=0, dispose=2, blend=0),
        ]
    out = signature + ihdr(canvas[0], canvas[1])
    if include_actl:
        out += actl(actl_frames if actl_frames is not None else len(specs), num_plays)

    seq = 0
    for i, spec in enumerate(specs):
        out += fctl(
            seq,
            spec["w"],
            spec["h"],
            spec.get("x", 0),
            spec.get("y", 0),
            spec.get("dnum", 1),
            spec.get("dden", 10),
            spec.get("dispose", 0),
            spec.get("blend", 0),
        )
        seq += 1
        payload = zpayload(spec["w"], spec["h"])
        parts = spec.get("parts", [payload])
        if i == 0:
            for part in parts:
                out += idat(part)
        else:
            for part in parts:
                out += fdat(seq, part)
                seq += 1
    out += iend()
    return out + trailing


# --------------------------------------------------------------------- valid


def test_valid_three_frames_report():
    report = audit_apng(build_valid())
    assert report["canvas"] == {"width": 4, "height": 4}
    assert report["play_count"] == 3
    assert len(report["frames"]) == 3

    r0 = report["frames"][0]
    assert r0["index"] == 1
    assert r0["rect"] == {"x": 0, "y": 0, "width": 4, "height": 4}
    assert r0["delay"] == {"numerator": 1, "denominator": 10, "seconds": 0.1}
    assert r0["dispose"] == "none"
    assert r0["blend"] == "source"
    assert len(r0["sha256"]) == 64

    r1 = report["frames"][1]
    assert r1["rect"] == {"x": 1, "y": 1, "width": 2, "height": 2}
    assert r1["dispose"] == "background"
    assert r1["blend"] == "over"

    # delay denominator 0 is interpreted as 100.
    assert report["frames"][2]["delay"] == {
        "numerator": 5,
        "denominator": 100,
        "seconds": 0.05,
    }
    assert report["frames"][2]["dispose"] == "previous"


def test_sha256_is_of_concatenated_payload_and_stable():
    data = build_valid(
        specs=[
            dict(w=4, h=4, parts=[b"AAAA", b"BBBB"]),
            dict(w=4, h=4, parts=[b"CC"]),
        ]
    )
    import hashlib

    r1 = audit_apng(data)
    r2 = audit_apng(data)
    assert r1["frames"][0]["sha256"] == hashlib.sha256(b"AAAABBBB").hexdigest()
    assert r1["frames"][1]["sha256"] == hashlib.sha256(b"CC").hexdigest()
    assert r1 == r2


def test_single_frame_animation():
    data = build_valid(specs=[dict(w=2, h=2, x=0, y=0, dnum=1, dden=1)])
    report = audit_apng(data)
    assert len(report["frames"]) == 1
    assert report["frames"][0]["delay"]["seconds"] == 1.0


def test_infinite_play_count_zero_preserved():
    report = audit_apng(build_valid(num_plays=0))
    assert report["play_count"] == 0


# ------------------------------------------------------------------ invalid


def expect_error(data: bytes, reason: str | None = None) -> APNGValidationError:
    with pytest.raises(APNGValidationError) as excinfo:
        audit_apng(data)
    if reason is not None:
        assert excinfo.value.reason == reason, excinfo.value.reason
    return excinfo.value


def test_bad_signature():
    err = expect_error(b"NOT A PNG FILE AT ALL" + build_valid()[8:], "bad_signature")
    assert err.chunk_index is None


def test_ihdr_not_first():
    # Prepend a tEXt ancillary chunk before IHDR.
    data = PNG_SIG + chunk(b"tEXt", b"k\x00v") + ihdr() + actl(1)
    data += fctl(0) + idat(zpayload()) + iend()
    err = expect_error(data, "ihdr_not_first")
    assert err.chunk_index == 0


def test_bad_ihdr_dimensions():
    data = PNG_SIG + ihdr(w=0) + actl(1)
    data += fctl(0, w=4, h=4) + idat(zpayload()) + iend()
    expect_error(data, "bad_ihdr_dimensions")


def test_bad_ihdr_color_depth_combo():
    data = PNG_SIG + ihdr(depth=1, color=6) + actl(1)
    data += fctl(0) + idat(zpayload()) + iend()
    expect_error(data, "bad_ihdr_bit_depth")


def test_bad_crc_points_to_chunk_index():
    good = build_valid()
    # Corrupt one byte inside the second frame's fcTL body.
    target_pos = good.index(b"fcTL", good.index(b"IDAT")) - 4
    corrupted = bytearray(good)
    corrupted[target_pos + 8 + 3] ^= 0xFF
    err = expect_error(bytes(corrupted), "bad_crc")
    assert err.chunk_type == "fcTL"
    assert isinstance(err.chunk_index, int)


def test_truncated_chunk_length_beyond_eof():
    data = build_valid()
    # Drop the last 10 bytes (IEND tail) -> IEND length can't be satisfied.
    expect_error(data[:-10], "bad_length")


def test_truncated_header():
    expect_error(PNG_SIG + ihdr()[:12], "truncated_chunk")


def test_trailing_bytes_after_iend():
    err = expect_error(build_valid(trailing=b"EXTRA"), "data_after_iend")
    assert err.chunk_type == "EXTR" or err.reason == "data_after_iend"


def test_missing_iend():
    data = build_valid()[: -len(iend())]
    expect_error(data, "missing_iend")


def test_static_png_without_actl_rejected():
    data = PNG_SIG + ihdr() + idat(zpayload()) + iend()
    expect_error(data, "missing_actl")


def test_duplicate_actl():
    data = (
        PNG_SIG
        + ihdr()
        + actl(1)
        + actl(1)
        + fctl(0)
        + idat(zpayload())
        + iend()
    )
    expect_error(data, "duplicate_actl")


def test_actl_after_idat_rejected():
    data = PNG_SIG + ihdr() + fctl(0) + idat(zpayload()) + actl(1) + iend()
    expect_error(data, "actl_after_idat")


def test_first_fctl_after_first_idat_rejected():
    # IHDR, acTL, IDAT, fcTL, IEND
    data = PNG_SIG + ihdr() + actl(1) + idat(zpayload()) + fctl(0) + iend()
    expect_error(data, "idat_without_fctl")


def test_num_frames_over_limit():
    data = PNG_SIG + ihdr() + actl(513, 0)
    data += fctl(0) + idat(zpayload()) + iend()
    expect_error(data, "bad_num_frames")


def test_num_frames_zero_rejected():
    data = PNG_SIG + ihdr() + actl(0) + fctl(0) + idat(zpayload()) + iend()
    expect_error(data, "bad_num_frames")


def test_fctl_sequence_gap():
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(zpayload())
        + fctl(5)  # expected seq 1
        + fdat(6, zpayload())
        + iend()
    )
    err = expect_error(data, "bad_sequence")
    assert err.chunk_type == "fcTL"


def test_fdat_sequence_gap():
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(zpayload())
        + fctl(1)
        + fdat(9, zpayload())  # expected seq 2
        + iend()
    )
    err = expect_error(data, "bad_sequence")
    assert err.chunk_type == "fdAT"


def test_fdat_duplicate_sequence():
    data = (
        PNG_SIG
        + ihdr()
        + actl(3)
        + fctl(0)
        + idat(zpayload())
        + fctl(1)
        + fdat(2, zpayload())
        + fctl(2)
        + fdat(2, zpayload())  # seq 2 already used, expected 4
        + iend()
    )
    expect_error(data, "bad_sequence")


def test_frame_rect_outside_canvas():
    specs = [
        dict(w=4, h=4, x=0, y=0),
        dict(w=4, h=4, x=1, y=1),  # x+w = 5 > 4
    ]
    err = expect_error(build_valid(specs=specs), "frame_outside_canvas")
    assert err.chunk_type == "fcTL"


def test_frame_rect_zero_size():
    data = (
        PNG_SIG
        + ihdr()
        + actl(1)
        + fctl(0, w=0, h=4)
        + idat(zpayload(1, 1))
        + iend()
    )
    expect_error(data, "bad_frame_rect")


def test_frame_without_data_two_fctl_in_a_row():
    data = (
        PNG_SIG + ihdr() + actl(2) + fctl(0) + fctl(1)
        + fdat(2, zpayload()) + iend()
    )
    expect_error(data, "frame_without_data")


def test_last_frame_missing_fdat():
    data = (
        PNG_SIG
        + ihdr()
        + actl(3)
        + fctl(0)
        + idat(zpayload())
        + fctl(1)
        + fdat(2, zpayload())
        + fctl(3)  # no fdAT follows
        + iend()
    )
    expect_error(data, "frame_without_data")


def test_default_image_without_idat():
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + fctl(1)
        + fdat(2, zpayload())
        + iend()
    )
    # The empty first frame is caught first when fctl(1) arrives.
    expect_error(data, "frame_without_data")


def test_nonconsecutive_idat_chunks():
    data = (
        PNG_SIG
        + ihdr()
        + actl(1)
        + fctl(0)
        + idat(b"AAAA")
        + chunk(b"tEXt", b"k\x00v")
        + idat(b"BBBB")
        + iend()
    )
    expect_error(data, "nonconsecutive_idat")


def test_idat_after_fdat_rejected():
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(zpayload())
        + fctl(1)
        + fdat(2, zpayload())
        + idat(b"late")
        + iend()
    )
    expect_error(data, "idat_after_frame")


def test_frame_count_mismatch():
    data = build_valid(actl_frames=5)
    expect_error(data, "frame_count_mismatch")


def test_illegal_dispose_op():
    data = (
        PNG_SIG
        + ihdr()
        + actl(1)
        + fctl(0, dispose=9)
        + idat(zpayload())
        + iend()
    )
    expect_error(data, "bad_dispose_op")


def test_illegal_blend_op():
    data = (
        PNG_SIG
        + ihdr()
        + actl(1)
        + fctl(0, blend=7)
        + idat(zpayload())
        + iend()
    )
    expect_error(data, "bad_blend_op")


def test_invalid_zlib_payload():
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(b"this is not a zlib stream")
        + fctl(1)
        + fdat(2, zpayload())
        + iend()
    )
    err = expect_error(data, "bad_zlib_payload")
    assert err.chunk_type == "IDAT"


def test_invalid_fdat_zlib_payload():
    payload = zlib.compress(b"")
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(payload)
        + fctl(1)
        + fdat(2, b"garbage-not-zlib")
        + iend()
    )
    err = expect_error(data, "bad_zlib_payload")
    assert err.chunk_type == "fdAT"


def test_multiple_consecutive_fdat_per_frame_ok():
    payload = zpayload()
    half = len(payload) // 2
    specs = [
        dict(w=4, h=4, parts=[payload[:half], payload[half:]]),
        dict(w=4, h=4, parts=[b"x", b"y", b"z"]),
    ]
    # "x"/"y"/"z" are not individually valid zlib; concatenation must be.
    import zlib as _z

    stream = _z.compress(raw_rgba(4, 4))
    specs[1] = dict(
        w=4, h=4, parts=[stream[:3], stream[3:7], stream[7:]]
    )
    report = audit_apng(build_valid(specs=specs))
    assert len(report["frames"]) == 2
    assert report["frames"][1]["sha256"] == __import__("hashlib").sha256(stream).hexdigest()


def test_oversize_rejected_by_size_limit():
    assert MAX_BYTES == 8 * 1024 * 1024


# --------------------------------------------------------------- HTTP layer


@pytest.fixture()
def client():
    flask_app.testing = True
    return flask_app.test_client()


def test_http_valid(client):
    resp = client.post(
        "/api/apng/audit",
        data=build_valid(),
        content_type="image/apng",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["canvas"] == {"width": 4, "height": 4}
    assert len(body["frames"]) == 3


def test_http_content_type_with_charset_accepted(client):
    resp = client.post(
        "/api/apng/audit",
        data=build_valid(),
        content_type="image/apng; charset=binary",
    )
    assert resp.status_code == 200


def test_http_wrong_content_type(client):
    resp = client.post("/api/apng/audit", data=b"x", content_type="image/png")
    assert resp.status_code == 415


def test_http_empty_body(client):
    resp = client.post("/api/apng/audit", content_type="image/apng")
    assert resp.status_code == 400


def test_http_oversized(client):
    resp = client.post(
        "/api/apng/audit",
        data=b"x" * (MAX_BYTES + 1),
        content_type="image/apng",
    )
    assert resp.status_code == 413


def test_http_422_locates_chunk_and_has_no_partial_frames(client):
    data = (
        PNG_SIG
        + ihdr()
        + actl(2)
        + fctl(0)
        + idat(zpayload())
        + fctl(1)
        + fdat(99, zpayload())  # broken sequence number
        + iend()
    )
    resp = client.post("/api/apng/audit", data=data, content_type="image/apng")
    assert resp.status_code == 422
    body = resp.get_json()
    assert body["reason"] == "bad_sequence"
    assert isinstance(body["chunk_index"], int)
    assert body["chunk_type"] == "fdAT"
    # No partial frame list may ever be emitted on failure.
    assert "frames" not in body


def test_http_crc_error_shape(client):
    good = bytearray(build_valid())
    good[8 + 12] ^= 0x01  # flip a byte inside IHDR body
    resp = client.post(
        "/api/apng/audit", data=bytes(good), content_type="image/apng"
    )
    assert resp.status_code == 422
    body = resp.get_json()
    assert body["reason"] == "bad_crc"
    assert body["chunk_index"] == 0
    assert "frames" not in body


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
