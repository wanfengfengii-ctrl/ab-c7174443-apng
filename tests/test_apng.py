"""Tests for the strict APNG parser."""

import hashlib
import unittest
import zlib

from app.apng import (
    MAX_NUM_FRAMES,
    APNGError,
    parse_apng,
)
from app.apng_build import (
    PNG_SIGNATURE,
    actl,
    build_apng,
    chunk,
    fdat,
    fctl,
    ihdr,
)


def _payload(seed: int) -> bytes:
    return zlib.compress(bytes((i * seed) & 0xFF for i in range(64)))


def valid_stream(num_frames: int = 3) -> bytes:
    out = bytearray(PNG_SIGNATURE)
    out += ihdr(16, 16)
    out += actl(num_frames, 2)
    seq = 0
    for i in range(num_frames):
        out += fctl(
            seq,
            width=8,
            height=8,
            x_offset=(i % 2) * 8,
            y_offset=0,
            delay_num=1,
            delay_den=100,
        )
        seq += 1
        if i == 0:
            out += chunk(b"IDAT", _payload(i + 1))
        else:
            out += fdat(seq, _payload(i + 1))
            seq += 1
    out += chunk(b"IEND", b"")
    return bytes(out)


class ParseValidTests(unittest.TestCase):
    def test_valid_three_frames(self):
        apng = parse_apng(valid_stream())
        self.assertEqual((apng.width, apng.height), (16, 16))
        self.assertEqual(apng.num_frames, 3)
        self.assertEqual(apng.num_plays, 2)
        self.assertEqual(len(apng.frames), 3)
        for i, frame in enumerate(apng.frames):
            self.assertEqual((frame.width, frame.height), (8, 8))
            self.assertEqual(
                hashlib.sha256(frame.data).hexdigest(),
                hashlib.sha256(_payload(i + 1)).hexdigest(),
            )

    def test_default_builder_is_valid(self):
        apng = parse_apng(build_apng())
        self.assertEqual(apng.num_frames, 3)
        self.assertEqual(apng.frames[0].x_offset, 0)
        self.assertEqual(apng.frames[1].x_offset, 8)

    def test_delay_denominator_zero_becomes_100(self):
        stream = build_apng(
            frames=[
                {"width": 4, "height": 4, "delay_num": 3, "delay_den": 0},
                {"width": 4, "height": 4},
            ]
        )
        apng = parse_apng(stream)
        first = apng.frames[0]
        self.assertEqual(first.delay_den_raw, 0)
        self.assertEqual(first.delay_den, 100)
        self.assertAlmostEqual(first.delay_seconds, 3 / 100)
        d = first.to_dict(0)
        self.assertTrue(d["delay"]["den_was_zero"])
        self.assertEqual(d["delay"]["den"], 100)

    def test_dispose_and_blend_names(self):
        stream = build_apng(
            frames=[
                {"width": 2, "height": 2, "dispose": 2, "blend": 1},
                {"width": 2, "height": 2},
            ]
        )
        first = parse_apng(stream).frames[0]
        d = first.to_dict(0)
        self.assertEqual(d["dispose"], "previous")
        self.assertEqual(d["blend"], "over")

    def test_multiple_consecutive_payload_chunks(self):
        stream = build_apng(
            frames=[
                {"width": 2, "height": 2,
                 "payloads": [_payload(1), _payload(2)]},
                {"width": 2, "height": 2,
                 "payloads": [_payload(3), _payload(4), _payload(5)]},
            ]
        )
        apng = parse_apng(stream)
        self.assertEqual(len(apng.frames[0].data_chunks), 2)
        self.assertEqual(len(apng.frames[1].data_chunks), 3)
        self.assertEqual(
            apng.frames[1].data, _payload(3) + _payload(4) + _payload(5)
        )

    def test_512_frames_allowed(self):
        stream = valid_stream(MAX_NUM_FRAMES)
        apng = parse_apng(stream)
        self.assertEqual(apng.num_frames, MAX_NUM_FRAMES)


class SignatureAndChunkTests(unittest.TestCase):
    def test_bad_signature(self):
        with self.assertRaises(APNGError) as ctx:
            parse_apng(b"not a png at all" + b"\x00" * 32)
        self.assertIsNone(ctx.exception.chunk)

    def test_truncated_chunk_header(self):
        blob = PNG_SIGNATURE + ihdr(4, 4)[:-6]
        with self.assertRaises(APNGError) as ctx:
            parse_apng(blob)
        self.assertEqual(ctx.exception.chunk, 0)

    def test_declared_length_exceeds_stream(self):
        good = ihdr(4, 4)
        tampered = good[:8] + b"\xff\xff\xff\xff" + good[12:]
        with self.assertRaises(APNGError) as ctx:
            parse_apng(PNG_SIGNATURE + tampered)
        self.assertEqual(ctx.exception.chunk, 0)

    def test_crc_mismatch_locates_chunk(self):
        # Ordinal layout of the default stream: 0 IHDR, 1 acTL, 2 fcTL#1,
        # 3 IDAT, 4 fcTL#2, 5 fdAT#1 ...
        stream = build_apng()
        with self.assertRaises(APNGError) as ctx:
            parse_apng(_flip_crc(stream, 5))
        self.assertEqual(ctx.exception.chunk, 5)
        self.assertIn("CRC", ctx.exception.message)

    def test_trailing_bytes_after_iend(self):
        blob = valid_stream() + b"junk"
        with self.assertRaises(APNGError) as ctx:
            parse_apng(blob)
        self.assertIn("IEND", ctx.exception.message)

    def test_first_chunk_not_ihdr(self):
        out = PNG_SIGNATURE + actl(1) + ihdr(2, 2) + chunk(b"IEND", b"")
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertEqual(ctx.exception.chunk, 0)

    def test_iend_must_be_empty(self):
        out = (
            PNG_SIGNATURE
            + ihdr(2, 2)
            + actl(1)
            + fctl(0, width=2, height=2)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"x")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertIn("IEND", ctx.exception.message)


class GrammarTests(unittest.TestCase):
    def test_plain_png_without_actl_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError):
            parse_apng(out)

    def test_first_fctl_must_precede_first_idat(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            + chunk(b"IDAT", _payload(1))
            + fctl(0, width=4, height=4)
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertIn("fcTL", ctx.exception.message)

    def test_fctl_after_idat_is_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(2)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IDAT", _payload(2))
            + fctl(1, width=4, height=4)
            + chunk(b"IEND", b"")
        )
        # Second frame has no fdAT, and the trailing fcTL order is odd;
        # the parser must reject because frame 1 lacks fdAT data.
        with self.assertRaises(APNGError):
            parse_apng(out)

    def test_idat_in_later_frame_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(2)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + fctl(1, width=4, height=4)
            + chunk(b"IDAT", _payload(2))  # must be fdAT
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertEqual(ctx.exception.chunk, 5)

    def test_fdat_for_first_frame_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            + fctl(0, width=4, height=4)
            + fdat(1, _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertEqual(ctx.exception.chunk, 3)

    def test_unknown_ancillary_chunk_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            + chunk(b"tEXt", b"key\x00val")
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertEqual(ctx.exception.chunk, 2)

    def test_duplicate_actl(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            + actl(1)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertEqual(ctx.exception.chunk, 2)


class SequenceTests(unittest.TestCase):
    def test_fctl_sequence_gap(self):
        stream = build_apng(
            frames=[
                {"width": 4, "height": 4},
                {"width": 4, "height": 4, "seq": 5},
            ]
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(stream)
        self.assertEqual(ctx.exception.chunk, 4)
        self.assertIn("sequence", ctx.exception.message)

    def test_fdat_sequence_gap(self):
        stream = build_apng(
            frames=[
                {"width": 4, "height": 4},
                {"width": 4, "height": 4, "data_seq": 9},
            ]
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(stream)
        self.assertEqual(ctx.exception.chunk, 5)

    def test_swapped_frames_detected(self):
        # Frame 2 fcTL gets sequence number of frame 3 -> discontinuity.
        stream = build_apng(
            frames=[
                {"width": 4, "height": 4},
                {"width": 4, "height": 4, "seq": 2},
                {"width": 4, "height": 4, "seq": 1},
            ]
        )
        with self.assertRaises(APNGError):
            parse_apng(stream)

    def test_frame_count_exceeds_512(self):
        with self.assertRaises(APNGError) as ctx:
            parse_apng(build_apng(num_frames_override=513))
        self.assertIn("512", ctx.exception.message)

    def test_declared_frame_count_mismatch(self):
        stream = build_apng(num_frames_override=2)  # 3 fcTL actually present
        with self.assertRaises(APNGError) as ctx:
            parse_apng(stream)
        self.assertIn("declares 2", ctx.exception.message)

    def test_zero_declared_frames(self):
        stream = build_apng(num_frames_override=0)
        with self.assertRaises(APNGError):
            parse_apng(stream)


class RectangleTests(unittest.TestCase):
    def test_frame_wider_than_canvas(self):
        stream = build_apng(
            width=8,
            frames=[
                {"width": 8, "height": 8},
                {"width": 8, "height": 8, "x": 4},  # x+w = 12 > 8
            ],
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(stream)
        self.assertIn("canvas", ctx.exception.message)

    def test_frame_taller_than_canvas(self):
        stream = build_apng(
            width=8,
            height=8,
            frames=[
                {"width": 8, "height": 8},
                {"width": 4, "height": 6, "y": 4},  # y+h = 10 > 8
            ],
        )
        with self.assertRaises(APNGError):
            parse_apng(stream)

    def test_zero_dimension_frame(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            # width=0, crafted directly
            + chunk(
                b"fcTL",
                (0).to_bytes(4, "big")
                + (0).to_bytes(4, "big")
                + (4).to_bytes(4, "big")
                + (0).to_bytes(8, "big")
                + (100).to_bytes(4, "big")
                + bytes([0, 0]),
            )
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError):
            parse_apng(out)


class PaletteTests(unittest.TestCase):
    @staticmethod
    def _indexed_stream(*, plte: bytes | None = b"\xff\x00\x00" * 4,
                        color_type: int = 3, bit_depth: int = 8,
                        second_plte: bytes | None = None):
        out = bytearray(PNG_SIGNATURE)
        out += ihdr(4, 4, bit_depth=bit_depth, color_type=color_type)
        if plte is not None:
            out += chunk(b"PLTE", plte)
        out += actl(2)
        if second_plte is not None:
            out += chunk(b"PLTE", second_plte)
        out += fctl(0, width=4, height=4)
        out += chunk(b"IDAT", _payload(1))
        out += fctl(1, width=2, height=2)
        out += fdat(2, _payload(2))
        out += chunk(b"IEND", b"")
        return bytes(out)

    def test_indexed_apng_with_plte_accepted(self):
        apng = parse_apng(self._indexed_stream())
        self.assertEqual(apng.color_type, 3)
        self.assertEqual(apng.num_frames, 2)

    def test_indexed_apng_without_plte_rejected(self):
        with self.assertRaises(APNGError) as ctx:
            parse_apng(self._indexed_stream(plte=None))
        self.assertIn("PLTE", ctx.exception.message)

    def test_plte_forbidden_for_grayscale(self):
        with self.assertRaises(APNGError) as ctx:
            parse_apng(self._indexed_stream(color_type=0))
        self.assertEqual(ctx.exception.chunk, 1)

    def test_duplicate_plte_rejected(self):
        with self.assertRaises(APNGError) as ctx:
            parse_apng(
                self._indexed_stream(second_plte=b"\x00\xff\x00" * 2)
            )
        self.assertIn("PLTE", ctx.exception.message)

    def test_plte_too_many_entries_for_depth(self):
        # bit depth 2 allows at most 4 entries (12 bytes); give it 5.
        with self.assertRaises(APNGError) as ctx:
            parse_apng(
                self._indexed_stream(
                    plte=b"\x00" * 15, bit_depth=2
                )
            )
        self.assertIn("PLTE", ctx.exception.message)

    def test_plte_after_idat_rejected(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4, color_type=3)
            + actl(1)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + chunk(b"PLTE", b"\xff\xff\xff")
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertIn("PLTE", ctx.exception.message)


class PayloadTests(unittest.TestCase):
    def test_frame_without_any_data(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(2)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + fctl(1, width=4, height=4)
            # no fdAT
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
            # should fail at declared-count mismatch or empty payload
        self.assertTrue(
            "frame" in ctx.exception.message.lower()
            or "declares" in ctx.exception.message
        )

    def test_empty_fdat_payload(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(2)
            + fctl(0, width=4, height=4)
            + chunk(b"IDAT", _payload(1))
            + fctl(1, width=4, height=4)
            + chunk(b"fdAT", (2).to_bytes(4, "big"))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError) as ctx:
            parse_apng(out)
        self.assertIn("no compressed image data", ctx.exception.message)

    def test_invalid_dispose_op(self):
        out = (
            PNG_SIGNATURE
            + ihdr(4, 4)
            + actl(1)
            + chunk(
                b"fcTL",
                (0).to_bytes(4, "big")
                + (4).to_bytes(4, "big") * 2
                + (0).to_bytes(8, "big")
                + (100).to_bytes(4, "big")
                + bytes([9, 0]),
            )
            + chunk(b"IDAT", _payload(1))
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(APNGError):
            parse_apng(out)


def _flip_crc(blob: bytes, target_index: int) -> bytes:
    pos = 8
    index = 0
    while True:
        length = int.from_bytes(blob[pos : pos + 4], "big")
        crc_pos = pos + 8 + length
        if index == target_index:
            crc = int.from_bytes(blob[crc_pos : crc_pos + 4], "big") ^ 1
            return blob[:crc_pos] + crc.to_bytes(4, "big") + blob[crc_pos + 4 :]
        pos = crc_pos + 4
        index += 1


if __name__ == "__main__":
    unittest.main()
