#!/usr/bin/env python3
"""Decrypt saved mRemoteNG AES-GCM connection passwords (v1.75+ format).

The supported format is:
    Base64(16-byte PBKDF2 salt | 16-byte GCM nonce | ciphertext | 16-byte tag)

For this mRemoteNG format, the first 16 bytes (salt) are also supplied as GCM
associated data. The default master password used by mRemoteNG is commonly
"mR3m"; pass --master-password if the configuration uses a custom one.

Use only on configuration files you are authorized to inspect. Decrypted
credentials are secrets; avoid copying them into public reports.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

def decrypt_value(encoded: str, master_password: str, iterations: int = 1000) -> str:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover - environment-specific guidance
        raise RuntimeError(
            "Missing PyCryptodome. Install it in a virtual environment with: "
            "python3 -m venv .venv && source .venv/bin/activate && "
            "python -m pip install pycryptodome"
        ) from exc

    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
    except Exception as exc:
        raise ValueError("The supplied value is not valid Base64") from exc

    # 16-byte salt + 16-byte nonce + at least one ciphertext byte + 16-byte tag.
    if len(raw) < 49:
        raise ValueError(f"Encrypted value is too short ({len(raw)} bytes)")

    salt = raw[:16]
    nonce = raw[16:32]
    ciphertext = raw[32:-16]
    tag = raw[-16:]

    key = hashlib.pbkdf2_hmac(
        "sha1", master_password.encode("utf-8"), salt, iterations, dklen=32
    )

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)  # AAD required by this mRemoteNG AES-GCM format.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def local_name(tag: str) -> str:
    """Return an XML element's local name, handling optional namespaces."""
    return tag.rsplit("}", 1)[-1]


def decrypt_xml(path: Path, master_password: str, iterations: int) -> int:
    root = ET.parse(path).getroot()
    found = 0

    for node in root.iter():
        if local_name(node.tag) != "Node":
            continue
        encrypted = node.attrib.get("Password", "").strip()
        if not encrypted:
            continue

        found += 1
        name = node.attrib.get("Name", "")
        username = node.attrib.get("Username", "")
        try:
            plaintext = decrypt_value(encrypted, master_password, iterations)
            print(f"[+] Node={name!r} | Username={username!r} | Password={plaintext}")
        except Exception as exc:
            print(f"[-] Node={name!r} | Username={username!r} | Decryption failed: {exc}")

    if not found:
        print("[-] No <Node> elements with a non-empty Password attribute were found.")
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decrypt mRemoteNG Password attributes from XML or a Base64 value."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--xml", type=Path, help="Path to confCons.xml")
    source.add_argument("--value", help="One Base64-encrypted Password value")
    parser.add_argument("--master-password", default="mR3m",
                        help="mRemoteNG master password (default: mR3m)")
    parser.add_argument("--iterations", type=int, default=1000,
                        help="PBKDF2 iterations (default: 1000)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.iterations < 1:
        print("[-] Iterations must be a positive integer.", file=sys.stderr)
        return 2

    if args.xml:
        if not args.xml.is_file():
            print(f"[-] XML file not found: {args.xml}", file=sys.stderr)
            return 2
        return decrypt_xml(args.xml, args.master_password, args.iterations)

    try:
        print(decrypt_value(args.value, args.master_password, args.iterations))
        return 0
    except Exception as exc:
        print(f"[-] Decryption failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
