"""Minimal APNG builder used by tests and the one-shot verification service.

It produces structurally valid animation streams; individual keyword
arguments let callers corrupt exactly one aspect (sequence numbers, CRC,
frame rectangles, trailing bytes, ...).
"""

from __future__ import annotations

import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(ctype: bytes, data: bytes, corrupt_crc: bool = False) -> bytes:
    crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 0xFFFFFFFF
    return (
        len(data).to_bytes(4, "big")
        + ctype
        + data
        + crc.to_bytes(4, "big")
    )


def ihdr(
    width: int,
    height: int,
    *,
    bit_depth: int = 8,
    color_type: int = 6,
) -> bytes:
    data = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes([bit_depth, color_type, 0, 0, 0])
    )
    return chunk(b"IHDR", data)


def actl(num_frames: int, num_plays: int = 0) -> bytes:
    return chunk(b"acTL", num_frames.to_bytes(4, "big") + num_plays.to_bytes(4, "big"))


def fctl(
    seq: int,
    *,
    width: int,
    height: int,
    x_offset: int = 0,
    y_offset: int = 0,
    delay_num: int = 1,
    delay_den: int = 100,
    dispose_op: int = 0,
    blend_op: int = 0,
) -> bytes:
    data = (
        seq.to_bytes(4, "big")
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + x_offset.to_bytes(4, "big")
        + y_offset.to_bytes(4, "big")
        + delay_num.to_bytes(2, "big")
        + delay_den.to_bytes(2, "big")
        + bytes([dispose_op, blend_op])
    )
    return chunk(b"fcTL", data)


def fdat(seq: int, payload: bytes) -> bytes:
    return chunk(b"fdAT", seq.to_bytes(4, "big") + payload)


def _zlib_blob(seed: int) -> bytes:
    # Deterministic, valid zlib stream; the auditor never decodes it.
    return zlib.compress(bytes((i * seed) & 0xFF for i in range(96)))


def build_apng(
    *,
    width: int = 16,
    height: int = 16,
    frames: list[dict] | None = None,
    num_plays: int = 3,
    num_frames_override: int | None = None,
    delay_den: int = 100,
    trailing: bytes = b"",
    corrupt_crc_at: int | None = None,
) -> bytes:
    """Build a multi-frame APNG.

    Each frame dict may set: width, height, x, y, delay_num, delay_den,
    dispose, blend, seq (explicit sequence override) and extra payload
    chunks. The default is three valid 8x8 frames.
    """
    if frames is None:
        frames = [
            {"width": 8, "height": 8, "x": 0, "y": 0},
            {"width": 8, "height": 8, "x": 8, "y": 0},
            {"width": 16, "height": 16, "x": 0, "y": 0,
             "delay_num": 2, "dispose": 1, "blend": 1},
        ]

    out = bytearray(PNG_SIGNATURE)
    declared = len(frames) if num_frames_override is None else num_frames_override
    out += ihdr(width, height)
    out += actl(declared, num_plays)

    seq = 0
    for order, spec in enumerate(frames):
        frame_seq = spec.get("seq", seq)
        kw = dict(
            width=spec.get("width", width),
            height=spec.get("height", height),
            x_offset=spec.get("x", 0),
            y_offset=spec.get("y", 0),
            delay_num=spec.get("delay_num", 1),
            delay_den=spec.get("delay_den", delay_den),
            dispose_op=spec.get("dispose", 0),
            blend_op=spec.get("blend", 0),
        )
        out += fctl(frame_seq, **kw)
        seq += 1
        payloads = spec.get("payloads")
        if payloads is None:
            payloads = [_zlib_blob(seed=order + 1)]
        for payload in payloads:
            if order == 0:
                out += chunk(b"IDAT", payload)
            else:
                payload_seq = spec.get("data_seq", seq)
                out += fdat(payload_seq, payload)
                seq += 1

    out += chunk(b"IEND", b"")
    out += trailing

    if corrupt_crc_at is not None:
        out = bytearray(_corrupt_crc(bytes(out), corrupt_crc_at))
    return bytes(out)


def _corrupt_crc(blob: bytes, target_index: int) -> bytes:
    """Flip the CRC of the chunk with the given 0-based ordinal."""
    pos = 8
    index = 0
    while pos + 8 <= len(blob):
        length = int.from_bytes(blob[pos : pos + 4], "big")
        ctype = blob[pos + 4 : pos + 8]
        crc_pos = pos + 8 + length
        if index == target_index:
            crc = int.from_bytes(blob[crc_pos : crc_pos + 4], "big") ^ 1
            return (
                blob[:crc_pos]
                + crc.to_bytes(4, "big")
                + blob[crc_pos + 4 :]
            )
        pos = crc_pos + 4
        index += 1
        if ctype == b"IEND":
            break
    raise ValueError(f"chunk ordinal {target_index} not found")
