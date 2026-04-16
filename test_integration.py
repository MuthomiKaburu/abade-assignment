"""
test_integration.py — End-to-end integration tests (No pytest required)
Role 4: Tester & Security Analyst

Run with: python test_integration_standalone.py
"""

import json
import time
from pathlib import Path

from config import load_secret, MESSAGE_MAC_SEPARATOR
from sender import compose_packet, transmit
from receiver import receive_packet, parse_packet, verify_mac
from mac import generate_mac


OUTBOX = Path("transmitted_message.txt")


def clean_outbox():
    """Remove test file"""
    if OUTBOX.exists():
        OUTBOX.unlink()


def print_test_result(test_name, passed, message=""):
    """Pretty print test results"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} - {test_name}")
    if message and not passed:
        print(f"        {message}")


def test_valid_message_round_trip():
    """Complete valid flow: sender → receiver → verification"""
    clean_outbox()
    secret = load_secret()
    message = "Integration test message"
    
    try:
        # Sender side
        packet = compose_packet(message, secret)
        transmit(packet, OUTBOX)
        
        # Receiver side
        received, timestamp = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        is_valid = verify_mac(msg, secret, mac)
        
        assert is_valid is True, "MAC verification failed"
        assert msg == message, f"Message mismatch: {msg} != {message}"
        assert isinstance(timestamp, float), "Timestamp not a float"
        
        print_test_result("Valid message round trip", True)
        return True
    except Exception as e:
        print_test_result("Valid message round trip", False, str(e))
        return False


def test_tampered_message_rejected():
    """Attacker modifies message in transit → rejection"""
    clean_outbox()
    secret = load_secret()
    original_msg = "Pay $100"
    
    try:
        # Send legitimate packet
        packet = compose_packet(original_msg, secret)
        transmit(packet, OUTBOX)
        
        # Attacker intercepts and modifies message
        received, _ = receive_packet(OUTBOX)
        original_msg_received, mac = parse_packet(received)
        
        # Create tampered packet
        tampered_msg = "Pay $10000"
        tampered_packet = f"{tampered_msg}{MESSAGE_MAC_SEPARATOR}{mac}"
        
        # Write tampered packet back (simulating network tampering)
        payload = {"timestamp": time.time(), "packet": tampered_packet}
        OUTBOX.write_text(json.dumps(payload))
        
        # Receiver processes tampered packet
        received2, _ = receive_packet(OUTBOX)
        msg2, mac2 = parse_packet(received2)
        is_valid = verify_mac(msg2, secret, mac2)
        
        assert is_valid is False, "Tampered message was accepted!"
        assert msg2 == tampered_msg, f"Message mismatch: {msg2} != {tampered_msg}"
        
        print_test_result("Tampered message rejected", True)
        return True
    except Exception as e:
        print_test_result("Tampered message rejected", False, str(e))
        return False


def test_malformed_packet_no_separator():
    """Packet missing separator should raise ValueError"""
    clean_outbox()
    
    try:
        malformed = "no_separator_here"
        payload = {"timestamp": time.time(), "packet": malformed}
        OUTBOX.write_text(json.dumps(payload))
        
        received, _ = receive_packet(OUTBOX)
        
        try:
            parse_packet(received)
            print_test_result("Malformed packet (no separator)", False, "Should have raised ValueError")
            return False
        except ValueError:
            print_test_result("Malformed packet (no separator)", True)
            return True
    except Exception as e:
        print_test_result("Malformed packet (no separator)", False, str(e))
        return False


def test_malformed_packet_extra_separators():
    """Packet with multiple separators should still parse (first split only)"""
    clean_outbox()
    
    try:
        packet_with_extra = "message||mac||extra||data"
        payload = {"timestamp": time.time(), "packet": packet_with_extra}
        OUTBOX.write_text(json.dumps(payload))
        
        received, _ = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        
        # parse_packet splits on first separator only
        assert msg == "message", f"Expected 'message', got '{msg}'"
        assert mac == "mac||extra||data", f"Expected 'mac||extra||data', got '{mac}'"
        
        print_test_result("Malformed packet (extra separators)", True)
        return True
    except Exception as e:
        print_test_result("Malformed packet (extra separators)", False, str(e))
        return False


def test_replay_attack_vulnerability():
    """
    DEMONSTRATES VULNERABILITY: Same packet accepted twice.
    This test PASSES (showing the vulnerability) — not a bug in test.
    """
    clean_outbox()
    secret = load_secret()
    message = "Replay test"
    
    try:
        packet = compose_packet(message, secret)
        
        # First transmission
        transmit(packet, OUTBOX)
        received1, _ = receive_packet(OUTBOX)
        msg1, mac1 = parse_packet(received1)
        valid1 = verify_mac(msg1, secret, mac1)
        
        # Second transmission (replay)
        transmit(packet, OUTBOX)
        received2, _ = receive_packet(OUTBOX)
        msg2, mac2 = parse_packet(received2)
        valid2 = verify_mac(msg2, secret, mac2)
        
        # Both should be valid (this is the vulnerability)
        assert valid1 is True, "First message should be valid"
        assert valid2 is True, "Replayed message should also be valid (vulnerability)"
        
        print_test_result("Replay attack vulnerability", True)
        print("\n        ⚠️  VULNERABILITY CONFIRMED: System accepts replayed packets")
        print("        → No timestamp/nonce protection")
        return True
    except Exception as e:
        print_test_result("Replay attack vulnerability", False, str(e))
        return False


def test_empty_message_handling():
    """Empty message should work"""
    clean_outbox()
    secret = load_secret()
    message = ""
    
    try:
        packet = compose_packet(message, secret)
        transmit(packet, OUTBOX)
        
        received, _ = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        is_valid = verify_mac(msg, secret, mac)
        
        assert is_valid is True, "Empty message verification failed"
        assert msg == "", f"Expected empty string, got '{msg}'"
        
        print_test_result("Empty message handling", True)
        return True
    except Exception as e:
        print_test_result("Empty message handling", False, str(e))
        return False


def test_unicode_message_handling():
    """Unicode characters should survive round trip"""
    clean_outbox()
    secret = load_secret()
    message = "Hello 世界 🌍 £ €"
    
    try:
        packet = compose_packet(message, secret)
        transmit(packet, OUTBOX)
        
        received, _ = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        is_valid = verify_mac(msg, secret, mac)
        
        assert is_valid is True, "Unicode message verification failed"
        assert msg == message, f"Message mismatch: {msg} != {message}"
        
        print_test_result("Unicode message handling", True)
        return True
    except Exception as e:
        print_test_result("Unicode message handling", False, str(e))
        return False


def test_long_message_handling():
    """Long message (10KB) should work"""
    clean_outbox()
    secret = load_secret()
    message = "A" * 10000
    
    try:
        packet = compose_packet(message, secret)
        transmit(packet, OUTBOX)
        
        received, _ = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        is_valid = verify_mac(msg, secret, mac)
        
        assert is_valid is True, "Long message verification failed"
        assert len(msg) == 10000, f"Expected length 10000, got {len(msg)}"
        
        print_test_result("Long message handling", True)
        return True
    except Exception as e:
        print_test_result("Long message handling", False, str(e))
        return False


def test_wrong_secret_rejection():
    """Sender using different secret should be rejected"""
    clean_outbox()
    correct_secret = load_secret()
    wrong_secret = b"attacker_secret"
    
    try:
        # Sender uses wrong secret
        message = "Secret message"
        wrong_mac = generate_mac(message, wrong_secret)
        packet = f"{message}{MESSAGE_MAC_SEPARATOR}{wrong_mac}"
        
        transmit(packet, OUTBOX)
        
        # Receiver uses correct secret
        received, _ = receive_packet(OUTBOX)
        msg, mac = parse_packet(received)
        is_valid = verify_mac(msg, correct_secret, mac)
        
        assert is_valid is False, "Wrong secret was accepted!"
        
        print_test_result("Wrong secret rejection", True)
        return True
    except Exception as e:
        print_test_result("Wrong secret rejection", False, str(e))
        return False


def test_json_corruption_detection():
    """Corrupted JSON file should raise appropriate error"""
    clean_outbox()
    secret = load_secret()
    
    try:
        message = "test"
        packet = compose_packet(message, secret)
        transmit(packet, OUTBOX)
        
        # Corrupt the JSON file
        OUTBOX.write_text("this is not valid json", encoding="utf-8")
        
        try:
            receive_packet(OUTBOX)
            print_test_result("JSON corruption detection", False, "Should have raised JSONDecodeError")
            return False
        except json.JSONDecodeError:
            print_test_result("JSON corruption detection", True)
            return True
    except Exception as e:
        print_test_result("JSON corruption detection", False, str(e))
        return False


def run_all_tests():
    """Run all integration tests and print summary"""
    print("\n" + "="*70)
    print("  INTEGRATION TESTS — Sender → Receiver Flow")
    print("="*70 + "\n")
    
    # Make sure secret exists
    try:
        load_secret()
    except RuntimeError as e:
        print(f"❌ Error: {e}")
        print("Run 'python secret_setup.py' first to generate a secret key.")
        return False
    
    # Run all tests
    tests = [
        ("Valid message round trip", test_valid_message_round_trip),
        ("Tampered message rejected", test_tampered_message_rejected),
        ("Malformed packet (no separator)", test_malformed_packet_no_separator),
        ("Malformed packet (extra separators)", test_malformed_packet_extra_separators),
        ("Replay attack vulnerability", test_replay_attack_vulnerability),
        ("Empty message handling", test_empty_message_handling),
        ("Unicode message handling", test_unicode_message_handling),
        ("Long message handling", test_long_message_handling),
        ("Wrong secret rejection", test_wrong_secret_rejection),
        ("JSON corruption detection", test_json_corruption_detection),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n  Running: {test_name}...")
        result = test_func()
        results.append(result)
        print("-" * 50)
    
    # Summary
    passed = sum(results)
    failed = len(results) - passed
    
    print("\n" + "="*70)
    print(f"  TEST SUMMARY: {passed} passed, {failed} failed")
    print("="*70)
    
    if failed == 0:
        print("\n✅ All integration tests passed!")
        print("   (Note: Replay vulnerability confirmed — this is expected)")
        return True
    else:
        print(f"\n❌ {failed} test(s) failed. Review errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)