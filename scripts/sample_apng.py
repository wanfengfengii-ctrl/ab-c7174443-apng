"""Generate minimal APNG sample byte streams for the verify job."""

from __future__ import annotations

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(ctype: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)


def _ihdr(width: int, height: int) -> bytes:
    return _chunk(
        b"IHDR",
        struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0),
    )


def _actl(frames: int, plays: int = 0) -> bytes:
    return _chunk(b"acTL", struct.pack(">II", frames, plays))


def _fctl(
    seq: int, width: int, height: int, x: int = 0, y: int = 0,
    dnum: int = 1, dden: int = 10, dispose: int = 0, blend: int = 0,
) -> bytes:
    return _chunk(
        b"fcTL",
        struct.pack(
            ">IIIIIHHBB", seq, width, height, x, y, dnum, dden, dispose, blend
        ),
    )


def _idat(payload: bytes) -> bytes:
    return _chunk(b"IDAT", payload)


def _fdat(seq: int, payload: bytes) -> bytes:
    return _chunk(b"fdAT", struct.pack(">I", seq) + payload)


def _iend() -> bytes:
    return _chunk(b"IEND", b"")


def _rgba_payload(width: int, height: int, pixel: bytes) -> bytes:
    scanline = b"\x00" + pixel * width
    return zlib.compress(scanline * height)


def valid_apng() -> bytes:
    """A correct two-frame 8x4 APNG."""
    p0 = _rgba_payload(8, 4, b"\x10\x20\x30\xff")
    p1 = _rgba_payload(4, 2, b"\xf0\x80\x10\xff")
    return (
        PNG_SIGNATURE
        + _ihdr(8, 4)
        + _actl(2, 3)
        + _fctl(0, 8, 4, 0, 0, 1, 10, 0, 0)
        + _idat(p0)
        + _fctl(1, 4, 2, 2, 1, 2, 10, 1, 1)
        + _fdat(2, p1)
        + _iend()
    )


def corrupt_sequence_apng() -> bytes:
    """Same geometry but the fdAT sequence number jumps to 9 (expected 2).

    The CRC is recomputed so the failure is purely the sequence relation.
    """
    p0 = _rgba_payload(8, 4, b"\x10\x20\x30\xff")
    p1 = _rgba_payload(4, 2, b"\xf0\x80\x10\xff")
    return (
        PNG_SIGNATURE
        + _ihdr(8, 4)
        + _actl(2, 3)
        + _fctl(0, 8, 4, 0, 0, 1, 10, 0, 0)
        + _idat(p0)
        + _fctl(1, 4, 2, 2, 1, 2, 10, 1, 1)
        + _fdat(9, p1)  # sequence broken: 2 expected, 9 present
        + _iend()
    )
