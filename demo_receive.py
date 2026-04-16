"""
demo_receive.py — Role 3 deliverable
Runs the receiver and prints a detailed, annotated verification report.
"""
import sys
from pathlib import Path
from config import load_secret, MESSAGE_MAC_SEPARATOR
from mac import verify_mac, generate_mac
from receiver import receive_packet, parse_packet

def detailed_verify(source: Path) -> None:
    secret = load_secret()

    try:
        packet, timestamp = receive_packet(source)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  RECEIVER VERIFICATION REPORT")
    print(f"{'='*55}")
    print(f"  Timestamp       : {timestamp}")
    print(f"  Raw packet      : {packet[:60]}{'...' if len(packet)>60 else ''}")

    try:
        message, received_mac = parse_packet(packet)
    except ValueError as e:
        print(f"  [ERROR] Malformed packet: {e}")
        sys.exit(1)

    # Recompute expected MAC independently
    expected_mac = generate_mac(message, secret)

    print(f"\n  Message         : {message}")
    print(f"  Received MAC    : {received_mac[:20]}...")
    print(f"  Recomputed MAC  : {expected_mac[:20]}...")
    print(f"  MACs match      : {received_mac == expected_mac}")

    is_valid = verify_mac(message, secret, received_mac)

    print(f"\n  Comparison used : hmac.compare_digest() [timing-safe]")
    print(f"{'='*55}")
    if is_valid:
        print(f"  RESULT: ✅  MAC VALID — integrity confirmed")
        print(f"  Accepted message: '{message}'")
    else:
        print(f"  RESULT: ❌  MAC INVALID — message REJECTED")
        print(f"  Possible causes: tampered message, wrong key, corrupted packet")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    from pathlib import Path
    detailed_verify(Path("transmitted_message.txt"))