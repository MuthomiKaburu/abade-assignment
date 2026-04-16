"""
demo_send.py — Role 2 deliverable
Demonstrates sending: a valid message, a tampered packet, and a replayed message.
"""
import json
import time
from pathlib import Path
from config import load_secret
from sender import compose_packet, transmit

OUTBOX = Path("transmitted_message.txt")

def send_valid():
    """Normal case — legitimate message with correct MAC."""
    secret = load_secret()
    message = "Transfer £500 to account 98765"
    packet = compose_packet(message, secret)
    print("\n--- DEMO 1: Valid message ---")
    print(f"  Message : {message}")
    print(f"  Packet  : {packet}")
    transmit(packet, OUTBOX)
    print("  >> Now run receiver.py — should see MAC VALID")

def send_tampered():
    """
    Attack simulation — message is changed after MAC is computed.
    The MAC in the packet was generated for a different message,
    so the receiver's recomputed MAC will not match.
    """
    secret = load_secret()
    original_message = "Transfer £500 to account 98765"
    packet = compose_packet(original_message, secret)

    # Attacker intercepts and changes the message but keeps the original MAC
    mac_part = packet.split("||")[1]
    tampered_packet = f"Transfer £5000 to account 11111||{mac_part}"

    print("\n--- DEMO 2: Tampered message ---")
    print(f"  Original : {original_message}")
    print(f"  Tampered : {tampered_packet}")

    payload = {"timestamp": time.time(), "packet": tampered_packet}
    OUTBOX.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("  >> Now run receiver.py — should see MAC INVALID")

def send_wrong_secret():
    """
    Wrong key simulation — MAC was generated with a different secret.
    Models what happens if sender and receiver don't share the same key.
    """
    from mac import generate_mac
    message = "Hello from sender"
    wrong_mac = generate_mac(message, "completely-wrong-secret")
    packet = f"{message}||{wrong_mac}"

    print("\n--- DEMO 3: Wrong secret ---")
    print(f"  Message     : {message}")
    print(f"  MAC (wrong) : {wrong_mac[:20]}...")

    payload = {"timestamp": time.time(), "packet": packet}
    OUTBOX.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("  >> Now run receiver.py — should see MAC INVALID")

if __name__ == "__main__":
    print("=== Role 2 Demo — Scheme C Sender Scenarios ===")
    send_valid()
    input("\nPress Enter to demo tampered message...")
    send_tampered()
    input("\nPress Enter to demo wrong secret...")
    send_wrong_secret()
    print("\nAll demo packets sent.")