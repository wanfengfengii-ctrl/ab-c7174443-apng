"""Strict APNG (Animated PNG) structure parser.

Only structural validation is performed here: PNG signature, IHDR, per-chunk
length/CRC, the animation chunk grammar, sequence numbers, frame geometry and
per-frame compressed payload assembly. Image data itself is *not* decoded.

The parser is deliberately strict: player tolerance, which often hides
truncation, reordering or out-of-bounds frames, must never mask an invalid
file.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

MAX_BYTES = 8 * 1024 * 1024
MAX_NUM_FRAMES = 512

# dispose_op values (fcTL)
DISPOSE_OP_NONE = 0
DISPOSE_OP_BACKGROUND = 1
DISPOSE_OP_PREVIOUS = 2

# blend_op values (fcTL)
BLEND_OP_SOURCE = 0
BLEND_OP_OVER = 1

_DISPOSE_NAMES = {
    DISPOSE_OP_NONE: "none",
    DISPOSE_OP_BACKGROUND: "background",
    DISPOSE_OP_PREVIOUS: "previous",
}

_BLEND_NAMES = {
    BLEND_OP_SOURCE: "source",
    BLEND_OP_OVER: "over",
}

_COLOR_TYPE_NAMES = {
    0: "grayscale",
    2: "truecolor",
    3: "indexed",
    4: "grayscale_alpha",
    6: "truecolor_alpha",
}

# Chunk grammar accepted between IHDR and IEND. Besides the animation-
# critical chunks, PLTE is accepted for indexed-colour images and only in its
# mandated position (before any image data); any other chunk type makes the
# structure unverifiable for the archive and is rejected.
_ANIMATION_CHUNKS = frozenset({b"acTL", b"fcTL", b"IDAT", b"fdAT"})


class APNGError(Exception):
    """Structural validation failure.

    ``chunk`` is the 0-based ordinal number of the offending chunk in the
    chunk stream (IHDR is chunk 0), or ``None`` when the failure is located
    before any chunk could be attributed (bad signature, missing acTL, ...).
    """

    def __init__(self, message: str, chunk: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.chunk = chunk


@dataclass
class Frame:
    width: int
    height: int
    x_offset: int
    y_offset: int
    delay_num: int
    delay_den_raw: int
    dispose_op: int
    blend_op: int
    fctl_index: int
    data_chunks: list[int] = field(default_factory=list)
    data: bytes = b""

    @property
    def delay_den(self) -> int:
        # APNG spec: a denominator of zero must be treated as 100.
        return self.delay_den_raw if self.delay_den_raw != 0 else 100

    @property
    def delay_seconds(self) -> float:
        return self.delay_num / self.delay_den

    def to_dict(self, order: int) -> dict:
        return {
            "index": order,
            "rect": {
                "x": self.x_offset,
                "y": self.y_offset,
                "width": self.width,
                "height": self.height,
            },
            "delay": {
                "num": self.delay_num,
                "den": self.delay_den,
                "den_was_zero": self.delay_den_raw == 0,
                "seconds": self.delay_seconds,
            },
            "dispose": _DISPOSE_NAMES[self.dispose_op],
            "blend": _BLEND_NAMES[self.blend_op],
        }


@dataclass
class APNG:
    width: int
    height: int
    bit_depth: int
    color_type: int
    num_frames: int
    num_plays: int
    frames: list[Frame]


def _u32(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "big")


def _u16(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 2], "big")


def _chunk_name(ctype: bytes) -> str:
    return ctype.decode("ascii", "replace")


def _validate_ihdr(data: bytes, chunk: int) -> tuple[int, int, int, int]:
    if len(data) != 13:
        raise APNGError("IHDR chunk data must be exactly 13 bytes", chunk)
    width = _u32(data, 0)
    height = _u32(data, 4)
    bit_depth = data[8]
    color_type = data[9]
    compression = data[10]
    filter_method = data[11]
    interlace = data[12]
    if width == 0 or height == 0:
        raise APNGError("IHDR width and height must be non-zero", chunk)
    if width > 2**31 - 1 or height > 2**31 - 1:
        raise APNGError("IHDR dimensions exceed the PNG maximum", chunk)
    if compression != 0:
        raise APNGError(f"unsupported compression method {compression}", chunk)
    if filter_method != 0:
        raise APNGError(f"unsupported filter method {filter_method}", chunk)
    if interlace not in (0, 1):
        raise APNGError(f"unsupported interlace method {interlace}", chunk)
    allowed_depths = {
        0: (1, 2, 4, 8, 16),
        2: (8, 16),
        3: (1, 2, 4, 8),
        4: (8, 16),
        6: (8, 16),
    }
    if color_type not in allowed_depths:
        raise APNGError(f"unsupported color type {color_type}", chunk)
    if bit_depth not in allowed_depths[color_type]:
        raise APNGError(
            f"bit depth {bit_depth} is illegal for color type {color_type}",
            chunk,
        )
    return width, height, bit_depth, color_type


def _split_chunks(buf: bytes) -> list[tuple[bytes, bytes, int]]:
    """Walk the stream, validating every chunk boundary and CRC.

    Returns ``(type, data, ordinal)`` tuples in stream order. Raises with the
    offending chunk ordinal on truncated headers/data, illegal type bytes,
    CRC mismatch or trailing bytes after IEND.
    """
    if len(buf) < 8 or buf[:8] != PNG_SIGNATURE:
        raise APNGError("missing or invalid PNG signature", None)

    chunks: list[tuple[bytes, bytes, int]] = []
    pos = 8
    index = 0
    while True:
        if pos + 8 > len(buf):
            raise APNGError(
                "truncated chunk: length and type cannot be read", index
            )
        length = _u32(buf, pos)
        ctype = bytes(buf[pos + 4 : pos + 8])
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(buf):
            raise APNGError(
                f"truncated chunk {_chunk_name(ctype)!r}: declared data "
                f"length {length} exceeds the remaining stream",
                index,
            )
        if not all(65 <= b <= 90 or 97 <= b <= 122 for b in ctype):
            raise APNGError(
                f"invalid chunk type {ctype!r}: type bytes must be ASCII "
                "letters",
                index,
            )
        data = bytes(buf[data_start:data_end])
        stored_crc = _u32(buf, data_end)
        actual_crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            raise APNGError(
                f"CRC mismatch in chunk {_chunk_name(ctype)}: stored "
                f"{stored_crc:08x}, computed {actual_crc:08x}",
                index,
            )
        chunks.append((ctype, data, index))
        pos = crc_end
        index += 1
        if ctype == b"IEND":
            if pos != len(buf):
                raise APNGError(
                    f"trailing data after IEND: {len(buf) - pos} byte(s)",
                    index - 1,
                )
            break
    return chunks


def _parse_fctl(data: bytes, chunk: int) -> dict:
    if len(data) != 26:
        raise APNGError("fcTL chunk data must be exactly 26 bytes", chunk)
    info = {
        "sequence_number": _u32(data, 0),
        "width": _u32(data, 4),
        "height": _u32(data, 8),
        "x_offset": _u32(data, 12),
        "y_offset": _u32(data, 16),
        "delay_num": _u16(data, 20),
        "delay_den": _u16(data, 22),
        "dispose_op": data[24],
        "blend_op": data[25],
    }
    if info["width"] == 0 or info["height"] == 0:
        raise APNGError("fcTL frame dimensions must be non-zero", chunk)
    if info["dispose_op"] not in _DISPOSE_NAMES:
        raise APNGError(
            f"invalid dispose_op {info['dispose_op']}", chunk
        )
    if info["blend_op"] not in _BLEND_NAMES:
        raise APNGError(f"invalid blend_op {info['blend_op']}", chunk)
    return info


def parse_apng(buf: bytes) -> APNG:
    """Parse and strictly validate an APNG byte string.

    Raises :class:`APNGError` on the first structural violation.
    """
    if len(buf) > MAX_BYTES:
        # Defensive; the HTTP layer enforces the same limit first.
        raise APNGError(f"file exceeds {MAX_BYTES} bytes", None)

    chunks = _split_chunks(buf)

    first_type, first_data, first_index = chunks[0]
    if first_type != b"IHDR" or first_index != 0:
        raise APNGError("the first chunk must be IHDR", 0)
    width, height, bit_depth, color_type = _validate_ihdr(first_data, 0)

    end_type, end_data, end_index = chunks[-1]
    if end_type != b"IEND":
        raise APNGError("the last chunk must be IEND", end_index)
    if len(end_data) != 0:
        raise APNGError("IEND chunk data must be empty", end_index)

    # Grammar states:
    #   head:         after IHDR, expecting acTL then the first fcTL
    #   first_frame:  inside the default frame (IDAT run)
    #   later_frames: inside frame >= 1 (fdAT runs)
    state = "head"
    actl_seen = False
    plte_seen = False
    data_started = False
    num_frames_declared = 0
    num_plays = 0
    actl_index: int | None = None
    frames: list[Frame] = []
    current: Frame | None = None
    expected_seq = 0

    for ctype, data, idx in chunks[1:-1]:
        if ctype == b"PLTE":
            if data_started or plte_seen:
                raise APNGError(
                    "PLTE must appear exactly once and before the first "
                    "IDAT chunk",
                    idx,
                )
            if color_type in (0, 4):
                raise APNGError(
                    f"PLTE is forbidden for color type {color_type}", idx
                )
            if len(data) % 3 != 0 or not 3 <= len(data) <= 768:
                raise APNGError(
                    "PLTE length must be 3..768 bytes and a multiple of 3",
                    idx,
                )
            if len(data) // 3 > 2**bit_depth:
                raise APNGError(
                    f"PLTE has {len(data) // 3} entries but bit depth "
                    f"{bit_depth} allows at most {2**bit_depth}",
                    idx,
                )
            plte_seen = True
            continue

        if ctype not in _ANIMATION_CHUNKS:
            raise APNGError(
                f"unexpected chunk {_chunk_name(ctype)!r}: only PLTE, acTL, "
                "fcTL, IDAT and fdAT may appear between IHDR and IEND",
                idx,
            )

        if ctype == b"acTL":
            if state != "head" or actl_seen:
                raise APNGError(
                    "the single acTL chunk must appear after IHDR and before "
                    "the first fcTL",
                    idx,
                )
            if len(data) != 8:
                raise APNGError(
                    "acTL chunk data must be exactly 8 bytes", idx
                )
            num_frames_declared = _u32(data, 0)
            num_plays = _u32(data, 4)
            if num_frames_declared == 0:
                raise APNGError("acTL num_frames must be non-zero", idx)
            if num_frames_declared > MAX_NUM_FRAMES:
                raise APNGError(
                    f"acTL num_frames {num_frames_declared} exceeds the "
                    f"maximum of {MAX_NUM_FRAMES}",
                    idx,
                )
            actl_seen = True
            actl_index = idx
            continue

        if ctype == b"fcTL":
            if not actl_seen:
                raise APNGError(
                    "acTL must appear before the first fcTL", idx
                )
            info = _parse_fctl(data, idx)
            if info["sequence_number"] != expected_seq:
                raise APNGError(
                    "sequence number discontinuity at fcTL: expected "
                    f"{expected_seq}, found {info['sequence_number']}",
                    idx,
                )
            expected_seq += 1
            if info["x_offset"] + info["width"] > width:
                raise APNGError(
                    "frame rectangle extends beyond the canvas width", idx
                )
            if info["y_offset"] + info["height"] > height:
                raise APNGError(
                    "frame rectangle extends beyond the canvas height", idx
                )
            if state == "head":
                state = "first_frame"
            else:
                state = "later_frames"
            current = Frame(
                width=info["width"],
                height=info["height"],
                x_offset=info["x_offset"],
                y_offset=info["y_offset"],
                delay_num=info["delay_num"],
                delay_den_raw=info["delay_den"],
                dispose_op=info["dispose_op"],
                blend_op=info["blend_op"],
                fctl_index=idx,
            )
            frames.append(current)
            continue

        if ctype == b"IDAT":
            if state == "head":
                if actl_seen:
                    raise APNGError(
                        "the first fcTL must occur before the first IDAT", idx
                    )
                raise APNGError(
                    "missing acTL: the file is a plain PNG, not an APNG", idx
                )
            if state == "later_frames":
                raise APNGError(
                    "IDAT chunks are only permitted for the first frame", idx
                )
            assert current is not None
            current.data_chunks.append(idx)
            current.data += data
            data_started = True
            continue

        # ctype == b"fdAT"
        if state != "later_frames":
            raise APNGError(
                "fdAT chunks are only permitted for frames after the first",
                idx,
            )
        if len(data) < 4:
            raise APNGError(
                "fdAT chunk must start with a 4-byte sequence number", idx
            )
        seq = _u32(data, 0)
        if seq != expected_seq:
            raise APNGError(
                "sequence number discontinuity at fdAT: expected "
                f"{expected_seq}, found {seq}",
                idx,
            )
        expected_seq += 1
        if len(data) == 4:
            raise APNGError(
                "fdAT chunk carries no compressed image data", idx
            )
        assert current is not None
        current.data_chunks.append(idx)
        current.data += data[4:]

    if not actl_seen:
        raise APNGError("missing acTL chunk: not an animated PNG", None)

    if color_type == 3 and not plte_seen:
        raise APNGError(
            "indexed-colour image (color type 3) must contain a PLTE chunk",
            0,
        )

    if num_frames_declared != len(frames):
        raise APNGError(
            f"acTL declares {num_frames_declared} frames but "
            f"{len(frames)} fcTL chunk(s) are present",
            actl_index,
        )

    # Per-frame payload relationships: first frame = consecutive IDAT run,
    # every later frame = consecutive fdAT run, each carrying data.
    for order, frame in enumerate(frames):
        want_type = b"IDAT" if order == 0 else b"fdAT"
        if not frame.data_chunks:
            raise APNGError(
                f"frame {order} has no compressed data chunks",
                frame.fctl_index,
            )
        expected_indices = [
            frame.fctl_index + 1 + i for i in range(len(frame.data_chunks))
        ]
        if frame.data_chunks != expected_indices:
            raise APNGError(
                f"frame {order} {_chunk_name(want_type)} chunks must be "
                "consecutive and directly follow its fcTL",
                frame.fctl_index,
            )
        for chunk_idx in frame.data_chunks:
            if chunks[chunk_idx][0] != want_type:
                raise APNGError(
                    f"frame {order} must use {_chunk_name(want_type)} chunks",
                    chunk_idx,
                )
        if not frame.data:
            raise APNGError(
                f"frame {order} has an empty compressed payload",
                frame.fctl_index,
            )

    # One sequence number per fcTL and per fdAT; continuity proves they run
    # from zero with neither gaps nor duplicates.
    expected_total = len(frames) + sum(
        len(f.data_chunks) for f in frames[1:]
    )
    if expected_seq != expected_total:  # pragma: no cover - defensive
        raise APNGError(
            f"sequence numbers run 0..{expected_seq - 1}, expected "
            f"0..{expected_total - 1}",
            None,
        )

    return APNG(
        width=width,
        height=height,
        bit_depth=bit_depth,
        color_type=color_type,
        num_frames=num_frames_declared,
        num_plays=num_plays,
        frames=frames,
    )
