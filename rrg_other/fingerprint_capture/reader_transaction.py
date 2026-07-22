#!/usr/bin/env python3
"""Generate one repeatable ACR122T MIFARE Classic transaction per PM3 capture.

This program performs read-only card operations.  It prompts before every
transaction so the operator can wait until the PM3 Lua script prints [ARMED].
The sector key is prompted without echo and is never written to logs.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path
from typing import Any, Sequence


SUCCESS = (0x90, 0x00)
KEY_TYPE = {"A": 0x60, "B": 0x61}


class ReaderError(RuntimeError):
    """Raised when PC/SC or a fixed reader transaction fails."""


def _load_pcsc() -> tuple[Any, int]:
    try:
        from smartcard.System import readers  # type: ignore[import-not-found]
        from smartcard.scard import SCARD_UNPOWER_CARD  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ReaderError(
            "pyscard is not installed; install rrg_other/requirements.txt first"
        ) from exc
    return readers, SCARD_UNPOWER_CARD


def list_readers() -> list[str]:
    readers, _ = _load_pcsc()
    return [str(reader) for reader in readers()]


def select_reader(name_contains: str) -> Any:
    readers, _ = _load_pcsc()
    available = list(readers())
    matches = [
        reader for reader in available if name_contains.lower() in str(reader).lower()
    ]
    if not matches:
        names = ", ".join(str(reader) for reader in available) or "<none>"
        raise ReaderError(f"reader containing {name_contains!r} not found; available: {names}")
    if len(matches) > 1:
        raise ReaderError(
            "reader name is ambiguous: " + ", ".join(str(reader) for reader in matches)
        )
    return matches[0]


def parse_key(text: str) -> bytes:
    normalized = text.replace(" ", "").replace(":", "").replace("-", "")
    if len(normalized) != 12:
        raise ReaderError("MIFARE Classic key must contain exactly 12 hex characters")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ReaderError("key contains a non-hex character") from exc


def transmit(connection: Any, apdu: list[int], operation: str) -> list[int]:
    try:
        data, sw1, sw2 = connection.transmit(apdu)
    except Exception as exc:
        raise ReaderError(f"{operation} transport failed: {type(exc).__name__}: {exc}") from exc
    if (sw1, sw2) != SUCCESS:
        raise ReaderError(f"{operation} failed with SW={sw1:02X}{sw2:02X}")
    return list(data)


def fixed_transaction(connection: Any, block: int, key_type: str, key: bytes) -> None:
    """Load one volatile key, authenticate once, and read one 16-byte block."""

    slot = 0
    transmit(
        connection,
        [0xFF, 0x82, 0x00, slot, 0x06, *key],
        "load volatile key",
    )
    transmit(
        connection,
        [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, KEY_TYPE[key_type], slot],
        "authenticate",
    )
    data = transmit(connection, [0xFF, 0xB0, 0x00, block, 0x10], "read block")
    if len(data) != 16:
        raise ReaderError(f"read block returned {len(data)} bytes instead of 16")


def wait_for_card(reader: Any, timeout: float, unpower_card: int) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        connection = reader.createConnection()
        try:
            connection.connect(disposition=unpower_card)
            return connection
        except Exception as exc:
            last_error = exc
            try:
                connection.release()
            except Exception:
                pass
            time.sleep(0.05)
    suffix = f": {last_error}" if last_error else ""
    raise ReaderError(f"timed out waiting for a card after {timeout:.1f}s{suffix}")


def close_connection(connection: Any, unpower_card: int) -> None:
    try:
        connection.disconnect(disposition=unpower_card)
    except TypeError:
        try:
            connection.disconnect()
        except Exception:
            pass
    except Exception:
        pass
    try:
        connection.release()
    except Exception:
        pass


def run(args: argparse.Namespace) -> int:
    if args.list_readers:
        names = list_readers()
        if not names:
            print("No PC/SC readers found.")
            return 1
        for index, name in enumerate(names):
            print(f"[{index}] {name}")
        return 0

    if not 0 <= args.block <= 63:
        raise ReaderError("block must be between 0 and 63 for MIFARE Classic 1K")
    if args.block % 4 == 3:
        raise ReaderError("choose a data block, not a sector trailer block")
    key = parse_key(getpass.getpass(f"Enter Key {args.key_type} (12 hex characters): "))
    reader = select_reader(args.reader)
    _, unpower_card = _load_pcsc()
    print(f"Reader: {reader}")
    print(f"Fixed transaction: authenticate block {args.block} with Key {args.key_type}, then read once")
    print("The key and block contents are not logged.")

    for trial in range(1, args.count + 1):
        try:
            input(
                f"\n[{trial}/{args.count}] Wait for PM3 [ARMED], keep RF area empty, "
                "then press Enter and present the card..."
            )
        except EOFError as exc:
            raise ReaderError("interactive input ended") from exc
        connection = wait_for_card(reader, args.timeout, unpower_card)
        try:
            fixed_transaction(connection, args.block, args.key_type, key)
            print(f"[{trial}/{args.count}] transaction OK; remove the card now")
        finally:
            close_connection(connection, unpower_card)
    print("All requested transactions completed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a repeatable read-only ACR122T transaction for PM3 capture"
    )
    parser.add_argument("--list-readers", action="store_true")
    parser.add_argument("--reader", default="ACR122", help="unique reader-name substring")
    parser.add_argument("--block", type=int, default=4, help="data block 0..63 (default: 4)")
    parser.add_argument("--key-type", choices=("A", "B"), default="A")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.count < 1:
            raise ReaderError("count must be positive")
        return run(args)
    except ReaderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
