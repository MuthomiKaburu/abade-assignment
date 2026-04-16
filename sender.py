"""
sender.py — Message sender module
Composes a message, computes its HMAC-SHA256 MAC, and transmits both.

In a real deployment the "transmission" would be a network socket, HTTP POST,
message queue, etc.  Here we simulate it by writing to a shared file
(transmitted_message.txt) so the receiver can pick it up independently.
"""

import sys
import json
import time
from pathlib import Path

from config import load_secret, MESSAGE_MAC_SEPARATOR
from mac import generate_mac


OUTBOX_FILE = Path("transmitted_message.txt")


def compose_packet(message: str, secret: bytes) -> str:
    """
    Build a transmission packet: <message><SEPARATOR><mac>

    The receiver will split on SEPARATOR to recover both parts.
    """
    mac = generate_mac(message, secret)
    return f"{message}{MESSAGE_MAC_SEPARATOR}{mac}"


def transmit(packet: str, destination: Path = OUTBOX_FILE) -> None:
    """
    'Transmit' the packet by writing it to a file.
    Replace this function body with real I/O (socket.send, requests.post, …)
    """
    payload = {
        "timestamp": time.time(),
        "packet": packet,
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[Sender] Packet written to '{destination}'")


def main() -> None:
    secret = load_secret()

    if len(sys.argv) > 1:
        message = " ".join(sys.argv[1:])
    else:
        message = input("Enter message to send: ").strip()

    if not message:
        print("[Sender] Empty message — nothing sent.")
        sys.exit(1)

    packet = compose_packet(message, secret)
    print(f"[Sender] Message : {message}")
    print(f"[Sender] Packet  : {packet}")

    transmit(packet)
    print("[Sender] Transmission complete.")


if __name__ == "__main__":
    main()
