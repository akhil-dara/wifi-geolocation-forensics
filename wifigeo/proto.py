"""
Minimal hand-rolled Protocol Buffers codec.

We deliberately avoid the `protobuf` package.  Two reasons:

1.  It is the single largest dependency the reference tools pull in, and it
    would dominate the size of the portable build.
2.  For evidence work it is preferable to be able to point at ~120 lines of
    readable code and say "this is exactly how the bytes were interpreted"
    rather than at a generated descriptor blob.

Only the wire types Apple's location service actually uses are implemented:
varint (0) and length-delimited (2).  Fixed64 (1) and fixed32 (5) are skipped
correctly if they ever appear, so an unexpected schema change degrades to
"field ignored" rather than "parser explodes".
"""

from __future__ import annotations

from typing import Dict, Iterator, List, Tuple

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5


class ProtoError(ValueError):
    """Raised when a buffer is not decodable as protobuf."""


# --------------------------------------------------------------------------
# varint
# --------------------------------------------------------------------------
def encode_varint(value: int) -> bytes:
    """Encode a non-negative int as a base-128 varint."""
    if value < 0:
        raise ProtoError("encode_varint expects a non-negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0x00))
        if not value:
            return bytes(out)


def decode_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Decode a varint at `pos`.  Returns (value, new_pos)."""
    result = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ProtoError("truncated varint at offset %d" % start)
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ProtoError("varint too long at offset %d" % start)


def as_signed64(value: int) -> int:
    """
    Reinterpret an unsigned varint as a two's-complement int64.

    Apple declares latitude/longitude as protobuf `int64` (NOT `sint64`), so
    they are *not* zigzag encoded.  Negative coordinates therefore arrive as
    very large unsigned varints.  Getting this wrong silently teleports every
    result in the southern and western hemispheres, so it gets its own
    function and its own test.
    """
    return value - (1 << 64) if value >= (1 << 63) else value


# --------------------------------------------------------------------------
# message encoding
# --------------------------------------------------------------------------
def tag(field: int, wire: int) -> bytes:
    return encode_varint((field << 3) | wire)


def field_varint(field: int, value: int) -> bytes:
    return tag(field, WIRE_VARINT) + encode_varint(value)


def field_bytes(field: int, value: bytes) -> bytes:
    return tag(field, WIRE_LEN) + encode_varint(len(value)) + value


def field_string(field: int, value: str) -> bytes:
    return field_bytes(field, value.encode("utf-8"))


# --------------------------------------------------------------------------
# message decoding
# --------------------------------------------------------------------------
def iter_fields(buf: bytes) -> Iterator[Tuple[int, int, object]]:
    """
    Walk a protobuf message.

    Yields (field_number, wire_type, value) where value is an int for varint /
    fixed types and bytes for length-delimited types.
    """
    pos = 0
    end = len(buf)
    while pos < end:
        key, pos = decode_varint(buf, pos)
        field, wire = key >> 3, key & 0x07
        if field == 0:
            raise ProtoError("field number 0 is invalid")
        if wire == WIRE_VARINT:
            value, pos = decode_varint(buf, pos)
            yield field, wire, value
        elif wire == WIRE_LEN:
            length, pos = decode_varint(buf, pos)
            if pos + length > end:
                raise ProtoError("length-delimited field overruns buffer")
            yield field, wire, buf[pos:pos + length]
            pos += length
        elif wire == WIRE_FIXED64:
            if pos + 8 > end:
                raise ProtoError("truncated fixed64")
            yield field, wire, int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
        elif wire == WIRE_FIXED32:
            if pos + 4 > end:
                raise ProtoError("truncated fixed32")
            yield field, wire, int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
        else:
            raise ProtoError("unsupported wire type %d for field %d" % (wire, field))


def to_dict(buf: bytes) -> Dict[int, List[object]]:
    """Collect a message into {field_number: [values...]}."""
    out: Dict[int, List[object]] = {}
    for field, _wire, value in iter_fields(buf):
        out.setdefault(field, []).append(value)
    return out
