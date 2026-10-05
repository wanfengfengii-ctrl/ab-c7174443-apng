"""Strict APNG (Animated PNG) structural auditor.

Every check performed here is chunk-level strict: PNG signature, IHDR
validity, per-chunk length boundaries, CRC-32 verification, IEND
termination, acTL/fcTL/IDAT/fdAT ordering, sequence-number continuity,
frame-rectangle containment and per-frame zlib payload integrity.

Any failure raises :class:`APNGValidationError` carrying the index of the
offending chunk so callers can return a locatable 422 response.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import List, Optional

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_BYTES = 8 * 1024 * 1024
MAX_FRAMES = 512
MAX_DIMENSION = 0x7FFFFFFF

DISPOSE_NAMES = {0: "none", 1: "background", 2: "previous"}
BLEND_NAMES = {0: "source", 1: "over"}

_BIT_DEPTHS_BY_COLOR_TYPE = {
    0: {1, 2, 4, 8, 16},
    2: {4, 8, 16},
    3: {1, 2, 4, 8},
    4: {8, 16},
    6: {8, 16},
}


class APNGValidationError(Exception):
    """Raised when the APNG fails a structural integrity rule."""

    def __init__(
        self,
        message: str,
        chunk_index: Optional[int] = None,
        chunk_type: Optional[bytes] = None,
        reason: str = "invalid",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.chunk_index = chunk_index
        self.chunk_type = chunk_type
        self.reason = reason

    def to_response(self) -> dict:
        body = {"error": self.message, "reason": self.reason}
        if self.chunk_index is not None:
            body["chunk_index"] = self.chunk_index
        if self.chunk_type is not None:
            body["chunk_type"] = self.chunk_type.decode("latin-1")
        return body


@dataclass
class Chunk:
    index: int
    ctype: bytes
    data: bytes


def _err(
    message: str,
    chunk_index: Optional[int] = None,
    chunk_type: Optional[bytes] = None,
    reason: str = "invalid",
) -> APNGValidationError:
    return APNGValidationError(message, chunk_index, chunk_type, reason)


def _parse_chunks(data: bytes) -> List[Chunk]:
    """Split the byte stream into chunks, checking length and CRC-32."""
    if len(data) < 8 or data[:8] != PNG_SIGNATURE:
        raise _err(
            "missing or invalid PNG signature",
            reason="bad_signature",
        )

    chunks: List[Chunk] = []
    pos = 8
    index = 0
    total = len(data)
    while pos < total:
        if total - pos < 8:
            raise _err(
                "truncated chunk header (length/type)",
                chunk_index=index,
                reason="truncated_chunk",
            )
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body_end = pos + 8 + length
        crc_end = body_end + 4
        if crc_end > total:
            raise _err(
                "chunk length exceeds available data (truncated body or CRC)",
                chunk_index=index,
                chunk_type=ctype if _is_ascii_type(ctype) else None,
                reason="bad_length",
            )
        if not _is_ascii_type(ctype):
            raise _err(
                "chunk type is not composed of A-Z/a-z ASCII letters",
                chunk_index=index,
                reason="bad_chunk_type",
            )
        body = data[pos + 8:body_end]
        stored_crc = struct.unpack(">I", data[body_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            raise _err(
                "CRC-32 mismatch",
                chunk_index=index,
                chunk_type=ctype,
                reason="bad_crc",
            )
        chunks.append(Chunk(index, ctype, body))
        pos = crc_end
        index += 1
    return chunks


def _is_ascii_type(ctype: bytes) -> bool:
    return len(ctype) == 4 and all(65 <= b <= 90 or 97 <= b <= 122 for b in ctype)


def audit_apng(data: bytes) -> dict:
    """Validate ``data`` and return the audit report.

    Raises :class:`APNGValidationError` on the first structural violation.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _err("request body must be raw bytes", reason="bad_request")
    if len(data) > MAX_BYTES:
        raise _err(
            f"file exceeds {MAX_BYTES} bytes",
            reason="too_large",
        )

    chunks = _parse_chunks(bytes(data))
    if not chunks:
        raise _err("file contains no chunks after PNG signature", reason="no_chunks")

    # ---- IHDR (must be the first chunk, 13 bytes) -------------------------
    ihdr = chunks[0]
    if ihdr.ctype != b"IHDR":
        raise _err(
            "first chunk must be IHDR",
            chunk_index=ihdr.index,
            chunk_type=ihdr.ctype,
            reason="ihdr_not_first",
        )
    if len(ihdr.data) != 13:
        raise _err(
            "IHDR length must be 13",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_length",
        )
    width, height, bit_depth, color_type, compression, filterm, interlace = (
        struct.unpack(">IIBBBBB", ihdr.data)
    )
    if not (1 <= width <= MAX_DIMENSION and 1 <= height <= MAX_DIMENSION):
        raise _err(
            "IHDR width/height must be in 1..2^31-1",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_dimensions",
        )
    if color_type not in _BIT_DEPTHS_BY_COLOR_TYPE:
        raise _err(
            f"unsupported IHDR color type {color_type}",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_color_type",
        )
    if bit_depth not in _BIT_DEPTHS_BY_COLOR_TYPE[color_type]:
        raise _err(
            f"bit depth {bit_depth} illegal for color type {color_type}",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_bit_depth",
        )
    if compression != 0 or filterm != 0:
        raise _err(
            "IHDR compression/filter method must be 0",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_method",
        )
    if interlace not in (0, 1):
        raise _err(
            f"unsupported IHDR interlace method {interlace}",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="bad_ihdr_interlace",
        )

    # ---- Ordered walk ------------------------------------------------------
    actl = None  # (index, num_frames, num_plays)
    plte_index: Optional[int] = None
    first_idat_index: Optional[int] = None
    idat_run_open = False
    saw_iend = False

    # frame state
    frames: List[dict] = []
    open_frame: Optional[dict] = None
    expected_seq = 0

    for ch in chunks[1:]:
        ctype = ch.ctype

        if saw_iend:
            raise _err(
                "no data or chunks are allowed after IEND",
                chunk_index=ch.index,
                chunk_type=ctype,
                reason="data_after_iend",
            )

        if ctype == b"IEND":
            if ch.data:
                raise _err(
                    "IEND data field must be empty",
                    chunk_index=ch.index,
                    chunk_type=b"IEND",
                    reason="bad_iend",
                )
            saw_iend = True
            continue

        if ctype == b"acTL":
            if actl is not None:
                raise _err(
                    "duplicate acTL chunk",
                    chunk_index=ch.index,
                    chunk_type=b"acTL",
                    reason="duplicate_actl",
                )
            if first_idat_index is not None:
                raise _err(
                    "acTL must appear before the first IDAT",
                    chunk_index=ch.index,
                    chunk_type=b"acTL",
                    reason="actl_after_idat",
                )
            if len(ch.data) != 8:
                raise _err(
                    "acTL length must be 8",
                    chunk_index=ch.index,
                    chunk_type=b"acTL",
                    reason="bad_actl_length",
                )
            num_frames, num_plays = struct.unpack(">II", ch.data)
            if not (1 <= num_frames <= MAX_FRAMES):
                raise _err(
                    f"acTL num_frames {num_frames} outside 1..{MAX_FRAMES}",
                    chunk_index=ch.index,
                    chunk_type=b"acTL",
                    reason="bad_num_frames",
                )
            actl = (ch.index, num_frames, num_plays)
            continue

        if ctype == b"fcTL":
            if actl is None:
                raise _err(
                    "fcTL must not appear before acTL",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="fctl_before_actl",
                )
            if open_frame is not None and not open_frame["has_data"]:
                raise _err(
                    "fcTL closes a frame that has no image data",
                    chunk_index=open_frame["fctl_index"],
                    chunk_type=b"fcTL",
                    reason="frame_without_data",
                )
            if len(ch.data) != 26:
                raise _err(
                    "fcTL length must be 26",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="bad_fctl_length",
                )
            (
                seq,
                fw,
                fh,
                fx,
                fy,
                delay_num,
                delay_den,
                dispose_op,
                blend_op,
            ) = struct.unpack(">IIIIIHHBB", ch.data)

            if seq != expected_seq:
                raise _err(
                    f"fcTL sequence_number {seq} out of order; expected {expected_seq}",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="bad_sequence",
                )
            expected_seq += 1

            if fw < 1 or fh < 1:
                raise _err(
                    "fcTL frame width/height must be >= 1",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="bad_frame_rect",
                )
            if fx + fw > width or fy + fh > height:
                raise _err(
                    "frame rectangle extends outside the IHDR canvas",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="frame_outside_canvas",
                )
            if fx > width or fy > height:
                raise _err(
                    "frame offset is outside the IHDR canvas",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="frame_outside_canvas",
                )
            if dispose_op not in DISPOSE_NAMES:
                raise _err(
                    f"illegal dispose_op {dispose_op}",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="bad_dispose_op",
                )
            if blend_op not in BLEND_NAMES:
                raise _err(
                    f"illegal blend_op {blend_op}",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="bad_blend_op",
                )

            if not frames and first_idat_index is not None:
                raise _err(
                    "first fcTL must appear before the first IDAT",
                    chunk_index=ch.index,
                    chunk_type=b"fcTL",
                    reason="fctl_after_idat",
                )

            frame = {
                "seq": seq,
                "fctl_index": ch.index,
                "rect": {"x": fx, "y": fy, "width": fw, "height": fh},
                "delay_num": delay_num,
                "delay_den": delay_den,
                "dispose_op": dispose_op,
                "blend_op": blend_op,
                "data_chunks": [],
                "payload": bytearray(),
                "has_data": False,
            }
            frames.append(frame)
            open_frame = frame
            continue

        if ctype == b"IDAT":
            idat_index = ch.index
            if actl is None:
                raise _err(
                    "IDAT encountered before acTL",
                    chunk_index=idat_index,
                    chunk_type=b"IDAT",
                    reason="idat_before_actl",
                )
            if not frames or frames[0]["seq"] != 0:
                raise _err(
                    "first IDAT must be preceded by the first fcTL (seq 0)",
                    chunk_index=idat_index,
                    chunk_type=b"IDAT",
                    reason="idat_without_fctl",
                )
            if first_idat_index is None:
                first_idat_index = idat_index
                open_frame = frames[0]
            elif not idat_run_open:
                raise _err(
                    "IDAT chunks of the default image must be consecutive",
                    chunk_index=idat_index,
                    chunk_type=b"IDAT",
                    reason="nonconsecutive_idat",
                )
            if open_frame is not frames[0]:
                raise _err(
                    "IDAT is not allowed once subsequent frames have started",
                    chunk_index=idat_index,
                    chunk_type=b"IDAT",
                    reason="idat_after_frame",
                )
            frames[0]["payload"].extend(ch.data)
            frames[0]["data_chunks"].append(idat_index)
            frames[0]["has_data"] = True
            idat_run_open = True
            continue

        if ctype == b"fdAT":
            idat_run_open = False
            if len(ch.data) < 5:
                raise _err(
                    "fdAT must carry a 4-byte sequence number plus frame data",
                    chunk_index=ch.index,
                    chunk_type=b"fdAT",
                    reason="bad_fdat_length",
                )
            if open_frame is None or open_frame is frames[0]:
                raise _err(
                    "fdAT encountered without a preceding frame fcTL",
                    chunk_index=ch.index,
                    chunk_type=b"fdAT",
                    reason="fdat_without_fctl",
                )
            seq = struct.unpack(">I", ch.data[:4])[0]
            if seq != expected_seq:
                raise _err(
                    f"fdAT sequence_number {seq} out of order; expected {expected_seq}",
                    chunk_index=ch.index,
                    chunk_type=b"fdAT",
                    reason="bad_sequence",
                )
            expected_seq += 1
            open_frame["payload"].extend(ch.data[4:])
            open_frame["data_chunks"].append(ch.index)
            open_frame["has_data"] = True
            continue

        if ctype == b"PLTE":
            if plte_index is not None:
                raise _err(
                    "duplicate PLTE chunk",
                    chunk_index=ch.index,
                    chunk_type=b"PLTE",
                    reason="duplicate_plte",
                )
            if first_idat_index is not None:
                raise _err(
                    "PLTE must appear before the first IDAT",
                    chunk_index=ch.index,
                    chunk_type=b"PLTE",
                    reason="plte_after_idat",
                )
            if frames:
                raise _err(
                    "PLTE must appear before the first fcTL",
                    chunk_index=ch.index,
                    chunk_type=b"PLTE",
                    reason="plte_after_fctl",
                )
            if color_type in (0, 4):
                raise _err(
                    "PLTE is forbidden for grayscale color types",
                    chunk_index=ch.index,
                    chunk_type=b"PLTE",
                    reason="plte_forbidden",
                )
            if not (3 <= len(ch.data) <= 3 * 256) or len(ch.data) % 3 != 0:
                raise _err(
                    "PLTE length must be 3..768 and a multiple of 3",
                    chunk_index=ch.index,
                    chunk_type=b"PLTE",
                    reason="bad_plte_length",
                )
            plte_index = ch.index
            continue

        # Unknown / ancillary chunks.
        critical = not (ctype[0] & 0x20)
        if critical:
            raise _err(
                f"unknown critical chunk {ctype.decode('latin-1')}",
                chunk_index=ch.index,
                chunk_type=ctype,
                reason="unknown_critical_chunk",
            )
        # An ancillary chunk terminates the (required-consecutive) IDAT run.
        idat_run_open = False

    if not saw_iend:
        raise _err(
            "file does not end with IEND",
            chunk_index=chunks[-1].index,
            chunk_type=chunks[-1].ctype,
            reason="missing_iend",
        )

    if actl is None:
        raise _err(
            "acTL chunk is required",
            chunk_index=None,
            reason="missing_actl",
        )
    actl_index, num_frames, num_plays = actl

    if color_type == 3 and plte_index is None:
        raise _err(
            "indexed color (type 3) requires a PLTE chunk",
            chunk_index=ihdr.index,
            chunk_type=b"IHDR",
            reason="missing_plte",
        )

    if open_frame is not None and not open_frame["has_data"]:
        raise _err(
            "last fcTL has no associated frame data",
            chunk_index=open_frame["fctl_index"],
            chunk_type=b"fcTL",
            reason="frame_without_data",
        )

    if not frames or not frames[0]["has_data"]:
        raise _err(
            "default image must consist of at least one IDAT",
            chunk_index=first_idat_index if first_idat_index is not None else None,
            chunk_type=b"IDAT",
            reason="missing_default_image",
        )

    if len(frames) != num_frames:
        raise _err(
            f"acTL declares {num_frames} frames but {len(frames)} fcTL frames exist",
            chunk_index=actl_index,
            chunk_type=b"acTL",
            reason="frame_count_mismatch",
        )

    # ---- Per-frame payload verification + digest --------------------------
    report_frames = []
    for i, frame in enumerate(frames, start=1):
        payload = bytes(frame["payload"])
        try:
            dec = zlib.decompressobj()
            dec.decompress(payload)
            dec.flush()
            if dec.unused_data:
                raise zlib.error("trailing bytes after zlib stream")
        except zlib.error as exc:
            raise _err(
                f"frame {i} compressed payload is not a valid zlib stream: {exc}",
                chunk_index=frame["data_chunks"][0],
                chunk_type=b"IDAT" if i == 1 else b"fdAT",
                reason="bad_zlib_payload",
            ) from exc

        delay_den = frame["delay_den"] if frame["delay_den"] != 0 else 100
        delay_num = frame["delay_num"]
        report_frames.append(
            {
                "index": i,
                "rect": frame["rect"],
                "delay": {
                    "numerator": delay_num,
                    "denominator": delay_den,
                    "seconds": delay_num / delay_den,
                },
                "dispose": DISPOSE_NAMES[frame["dispose_op"]],
                "blend": BLEND_NAMES[frame["blend_op"]],
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    return {
        "canvas": {"width": width, "height": height},
        "play_count": num_plays,
        "frames": report_frames,
    }
