#!/usr/bin/env python3
"""Recover the 32-character hexadecimal entry from Imaginizer's decoded string table.

The input can be either:
  * the LZMA buffer dumped from the protected string-loader routine; or
  * the already decompressed, length-prefixed string table (--raw-table).

No challenge secret is hard-coded in this script.
"""

from __future__ import annotations

import argparse
import lzma
import re
import struct
import sys
from pathlib import Path

HEX_KEY = re.compile(r"[0-9a-f]{32}\Z")


def decompress_lzma_buffer(data: bytes) -> bytes:
    """Decode an LZMA-Alone-style buffer with a known output size.

    Imaginizer's buffer has the 13-byte LZMA header, followed by a raw LZMA1
    stream. The packed data is zero-padded and does not include an EOS marker,
    so FORMAT_RAW is used and the header's uncompressed-size field is checked.
    """
    if len(data) < 13:
        raise ValueError("Input is too short to contain the 13-byte LZMA header")

    properties = data[0]
    dictionary_size = struct.unpack_from("<I", data, 1)[0]
    expected_size = struct.unpack_from("<Q", data, 5)[0]

    if properties >= 9 * 5 * 5:
        raise ValueError("Invalid LZMA properties byte")
    if dictionary_size == 0:
        raise ValueError("Invalid LZMA dictionary size")
    if expected_size == 0 or expected_size > 64 * 1024 * 1024:
        raise ValueError(f"Unreasonable decompressed size: {expected_size}")

    lc = properties % 9
    remainder = properties // 9
    lp = remainder % 5
    pb = remainder // 5

    filters = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": dictionary_size,
        "lc": lc,
        "lp": lp,
        "pb": pb,
    }]

    # The stream is padded with zero bytes for alignment and has no end marker.
    packed = data[13:].rstrip(b"\x00")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    decoded = decoder.decompress(packed, max_length=expected_size + 1)

    if len(decoded) != expected_size:
        raise ValueError(
            f"LZMA size check failed: expected {expected_size} bytes, "
            f"decoded {len(decoded)} bytes"
        )

    return decoded


def parse_string_table(table: bytes) -> list[str]:
    """Read DWORD-length-prefixed UTF-8 strings, aligned to four-byte offsets."""
    values: list[str] = []
    offset = 0

    while offset < len(table):
        # Accept only zero-filled trailing alignment/padding.
        if table[offset:] and not any(table[offset:]):
            break
        if offset + 4 > len(table):
            raise ValueError(f"Truncated length field at offset 0x{offset:x}")

        (length,) = struct.unpack_from("<I", table, offset)
        start = offset + 4
        end = start + length
        if end > len(table):
            raise ValueError(
                f"String at offset 0x{offset:x} extends beyond the table"
            )

        raw_value = table[start:end]
        try:
            values.append(raw_value.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"Non-UTF-8 string at table offset 0x{start:x}"
            ) from exc

        # Each record begins at a four-byte boundary.
        offset = (end + 3) & ~3

    return values


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract the hidden 32-character hexadecimal value from Imaginizer."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="LZMA buffer dumped from the application, or a decoded string table",
    )
    parser.add_argument(
        "--raw-table",
        action="store_true",
        help="Treat input as an already decompressed string table",
    )
    args = parser.parse_args()

    try:
        data = args.input.read_bytes()
        table = data if args.raw_table else decompress_lzma_buffer(data)
        strings = parse_string_table(table)
        matches = [value for value in strings if HEX_KEY.fullmatch(value)]

        if len(matches) != 1:
            raise ValueError(
                f"Expected exactly one 32-character lowercase hex entry; found {len(matches)}"
            )

        print(matches[0])
        return 0
    except (OSError, ValueError, lzma.LZMAError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
