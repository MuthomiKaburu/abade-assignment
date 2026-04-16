"""
attack_simulations.py — Security attack demonstrations
Role 4: Tester & Security Analyst

Demonstrates:
1. Replay attack (system is vulnerable)
2. Timing side-channel (why compare_digest matters)
3. MAC forgery infeasibility
"""

import time
import json
import statistics
from pathlib import Path
from hmac import compare_digest

from config import load_secret, MESSAGE_MAC_SEPARATOR
from mac import generate_mac, verify_mac
from sender import compose_packet, transmit
from receiver import receive_packet, parse_packet

OUTBOX = Path("transmitted_message.txt")


# ============================================================================
# ATTACK 1: REPLAY ATTACK (VULNERABILITY DEMONSTRATION)
# ============================================================================

def replay_attack():
    """
    Demonstrates that the system accepts replayed packets.
    Since no timestamp/nonce is included in the MAC calculation,
    an attacker can capture a valid packet and resend it later.
    """
    print("\n" + "="*60)
    print("  ATTACK 1: REPLAY ATTACK")
    print("="*60)
    
    secret = load_secret()
    message = "Transfer £500 to account 98765"
    
    # Capture a legitimate packet
    print(f"\n[Step 1] Legitimate sender transmits: '{message}'")
    packet = compose_packet(message, secret)
    transmit(packet, OUTBOX)
    
    # Receiver processes it first time
    received1, ts1 = receive_packet(OUTBOX)
    msg1, mac1 = parse_packet(received1)
    valid1 = verify_mac(msg1, secret, mac1)
    print(f"[Step 2] First receipt: {'✅ VALID' if valid1 else '❌ INVALID'}")
    
    # Attacker replays the SAME packet
    print(f"\n[Step 3] Attacker replays captured packet (no modification)")
    transmit(packet, OUTBOX)
    
    # Receiver processes it again
    received2, ts2 = receive_packet(OUTBOX)
    msg2, mac2 = parse_packet(received2)
    valid2 = verify_mac(msg2, secret, mac2)
    print(f"[Step 4] Second receipt: {'✅ VALID' if valid2 else '❌ INVALID'}")
    
    print("\n" + "="*60)
    print("  VULNERABILITY CONFIRMED")
    print("="*60)
    print("  System accepts replayed packets — no replay protection.")
    print("  Recommendation: Include timestamp or nonce in message.")
    print("  Example: message = f'{original}|{timestamp}|{nonce}'")
    print("="*60)
    
    return valid2  # Should be True (vulnerability)


# ============================================================================
# ATTACK 2: TIMING SIDE-CHANNEL DEMONSTRATION
# ============================================================================

def insecure_compare(a: str, b: str) -> bool:
    """
    VULNERABLE comparison — leaks timing information.
    Returns early on first mismatch, allowing timing attacks.
    """
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def timing_side_channel_demo():
    """
    Demonstrates why hmac.compare_digest() is necessary.
    Shows that plain == (or manual loop) leaks timing information.
    """
    print("\n" + "="*60)
    print("  ATTACK 2: TIMING SIDE-CHANNEL DEMONSTRATION")
    print("="*60)
    
    # Create two MACs that differ only in the last byte
    mac1 = "a1b2c3d4e5f67890" * 8  # 64 chars (valid SHA256 hex length)
    mac2 = mac1[:-1] + "f"  # Different only in last character
    
    print(f"\nMAC1: {mac1[:20]}... (length: {len(mac1)})")
    print(f"MAC2: {mac2[:20]}... (differs only in last byte)")
    
    # Test insecure comparison (early exit)
    print("\n[1] Measuring INSECURE comparison (early exit on mismatch)...")
    insecure_times = []
    for _ in range(10000):
        start = time.perf_counter()
        insecure_compare(mac1, mac2)
        insecure_times.append(time.perf_counter() - start)
    
    avg_insecure = statistics.mean(insecure_times) * 1_000_000  # microseconds
    
    # Test secure comparison (constant time)
    print("[2] Measuring SECURE comparison (hmac.compare_digest)...")
    secure_times = []
    mac1_bytes = mac1.encode()
    mac2_bytes = mac2.encode()
    for _ in range(10000):
        start = time.perf_counter()
        compare_digest(mac1_bytes, mac2_bytes)
        secure_times.append(time.perf_counter() - start)
    
    avg_secure = statistics.mean(secure_times) * 1_000_000
    
    print(f"\n{'='*60}")
    print(f"  RESULTS (microseconds, 10,000 iterations)")
    print(f"{'='*60}")
    print(f"  Insecure comparison (early exit):  {avg_insecure:.2f} μs")
    print(f"  Secure comparison (constant-time): {avg_secure:.2f} μs")
    print(f"  Difference: {avg_secure - avg_insecure:.2f} μs")
    
    print(f"\n{'='*60}")
    print("  SECURITY ANALYSIS")
    print("="*60)
    print("  ✅ System uses hmac.compare_digest() — timing-safe")
    print("  ❌ Plain '==' would leak timing information")
    print("  → Attacker could measure response time to guess MAC")
    print("="*60)


# ============================================================================
# ATTACK 3: MAC FORGERY ATTEMPT (SHOULD FAIL)
# ============================================================================

def mac_forgery_attempt():
    """
    Attempts to forge a valid MAC for a target message.
    Should be computationally infeasible.
    """
    import secrets
    
    print("\n" + "="*60)
    print("  ATTACK 3: MAC FORGERY ATTEMPT")
    print("="*60)
    
    secret = load_secret()
    target_message = "Transfer £1,000,000 to attacker account"
    
    print(f"\nTarget message: {target_message}")
    print(f"Attempting to find valid MAC (256-bit key space)...")
    
    attempts = 10000  # Tiny fraction of 2^256 space
    found = False
    
    for i in range(attempts):
        # Generate random 32-byte MAC (256 bits)
        forged_mac = secrets.token_hex(32)
        
        if verify_mac(target_message, secret, forged_mac):
            found = True
            print(f"\n✅ SUCCESS! Forged MAC: {forged_mac}")
            break
        
        if (i + 1) % 1000 == 0:
            print(f"  Attempted {i+1} random MACs... no success yet")
    
    print("\n" + "="*60)
    if not found:
        print("  RESULT: FORGERY FAILED (as expected)")
        print("="*60)
        print(f"  Attempts: {attempts}")
        print(f"  Key space size: 2^256 ≈ 1.16e77")
        print(f"  Probability of success: {attempts / 2**256:.2e}")
        print("  ✅ HMAC provides strong forgery resistance")
    else:
        print("  ⚠️ FORGERY SUCCEEDED — SYSTEM VULNERABLE!")
    print("="*60)


# ============================================================================
# ATTACK 4: WRONG SECRET SIMULATION (FROM DEMO)
# ============================================================================

def wrong_secret_attack():
    """
    Demonstrates that using wrong secret causes verification failure.
    (Already shown in demo_send.py, but included for completeness)
    """
    print("\n" + "="*60)
    print("  ATTACK 4: WRONG SECRET ATTACK")
    print("="*60)
    
    secret = load_secret()
    wrong_secret = b"attacker_controlled_key"
    message = "Payment to attacker"
    
    # Attacker generates MAC with wrong secret
    attacker_mac = generate_mac(message, wrong_secret)
    packet = f"{message}{MESSAGE_MAC_SEPARATOR}{attacker_mac}"
    
    # Receiver uses correct secret
    is_valid = verify_mac(message, secret, attacker_mac)
    
    print(f"\nMessage: {message}")
    print(f"Attacker uses wrong secret to generate MAC")
    print(f"Receiver verifies with correct secret")
    print(f"Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    
    if not is_valid:
        print("\n✅ Attack failed — wrong secret detected")
    else:
        print("\n❌ VULNERABILITY: Wrong secret accepted!")


# ============================================================================
# RUN ALL ATTACKS
# ============================================================================

if __name__ == "__main__":
    print("\n" + "█"*60)
    print("  HMAC SECURITY ATTACK SIMULATIONS — Role 4")
    print("█"*60)
    
    # Run all attacks
    replay_attack()
    input("\nPress Enter to continue to timing attack...")
    
    timing_side_channel_demo()
    input("\nPress Enter to continue to forgery attempt...")
    
    mac_forgery_attempt()
    input("\nPress Enter to continue to wrong secret attack...")
    
    wrong_secret_attack()
    
    print("\n" + "█"*60)
    print("  ALL ATTACKS COMPLETED")
    print("█"*60)