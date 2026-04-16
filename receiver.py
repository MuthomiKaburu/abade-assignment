"""
receiver.py — Message receiver module
Reads a transmitted packet, splits it into message + MAC, and verifies integrity.
"""

import sys
import json
from pathlib import Path

from config import load_secret, MESSAGE_MAC_SEPARATOR
from mac import verify_mac


OUTBOX_FILE = Path("transmitted_message.txt")


def receive_packet(source: Path = OUTBOX_FILE) -> tuple[str, float]:
    """
    'Receive' a packet from the shared file.
    Returns (packet_string, timestamp).
    Replace this with real I/O as needed.
    """
    if not source.exists():
        raise FileNotFoundError(
            f"No transmission found at '{source}'. Run sender.py first."
        )
    raw = json.loads(source.read_text(encoding="utf-8"))
    return raw["packet"], raw["timestamp"]


def parse_packet(packet: str) -> tuple[str, str]:
    """
    Split a packet string into (message, mac).
    Raises ValueError if the separator is missing.
    """
    parts = packet.split(MESSAGE_MAC_SEPARATOR, maxsplit=1)
    if len(parts) != 2:
        raise ValueError(
            f"Malformed packet — separator '{MESSAGE_MAC_SEPARATOR}' not found."
        )
    return parts[0], parts[1]


def main() -> None:
    secret = load_secret()

    try:
        packet, timestamp = receive_packet()
    except FileNotFoundError as exc:
        print(f"[Receiver] ERROR: {exc}")
        sys.exit(1)

    print(f"[Receiver] Raw packet received: {packet}")

    try:
        message, received_mac = parse_packet(packet)
    except ValueError as exc:
        print(f"[Receiver] ERROR: {exc}")
        sys.exit(1)

    print(f"[Receiver] Message      : {message}")
    print(f"[Receiver] Received MAC : {received_mac}")

    is_valid = verify_mac(message, secret, received_mac)

    if is_valid:
        print("[Receiver] ✅ MAC VALID — Message integrity confirmed.")
        print(f"[Receiver] Accepted message: '{message}'")
    else:
        print("[Receiver] ❌ MAC INVALID — Message may have been tampered with!")
        print("[Receiver] Message REJECTED.")
        sys.exit(2)


if __name__ == "__main__":
    main()
