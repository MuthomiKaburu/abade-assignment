"""
test_mac.py — Unit tests using only Python standard library
Run with: python test_mac_standalone.py
"""

from mac import generate_mac, verify_mac
from config import load_secret

def run_tests():
    """Run all tests and print results"""
    secret = load_secret()
    passed = 0
    failed = 0
    
    print("\n" + "="*60)
    print("  RUNNING MAC UNIT TESTS (standalone)")
    print("="*60 + "\n")
    
    # Test 1: generate_mac returns hex string
    try:
        mac = generate_mac("test", secret)
        assert isinstance(mac, str)
        assert all(c in "0123456789abcdef" for c in mac)
        print("✅ TEST 1: generate_mac returns hex string")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 1 FAILED: {e}")
        failed += 1
    
    # Test 2: Same input produces same MAC
    try:
        mac1 = generate_mac("hello", secret)
        mac2 = generate_mac("hello", secret)
        assert mac1 == mac2
        print("✅ TEST 2: Same input → same MAC")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 2 FAILED: {e}")
        failed += 1
    
    # Test 3: Valid MAC verifies as True
    try:
        msg = "Transfer £500"
        mac = generate_mac(msg, secret)
        assert verify_mac(msg, secret, mac) is True
        print("✅ TEST 3: Valid MAC verification passes")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 3 FAILED: {e}")
        failed += 1
    
    # Test 4: Tampered message fails
    try:
        msg = "Transfer £500"
        mac = generate_mac(msg, secret)
        tampered_msg = "Transfer £5000"
        assert verify_mac(tampered_msg, secret, mac) is False
        print("✅ TEST 4: Tampered message rejected")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 4 FAILED: {e}")
        failed += 1
    
    # Test 5: Wrong secret fails
    try:
        msg = "test"
        mac = generate_mac(msg, secret)
        wrong_secret = b"wrongkey123"
        assert verify_mac(msg, wrong_secret, mac) is False
        print("✅ TEST 5: Wrong secret rejected")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 5 FAILED: {e}")
        failed += 1
    
    # Test 6: Malformed MAC string fails safely
    try:
        msg = "test"
        assert verify_mac(msg, secret, "not-a-hex") is False
        print("✅ TEST 6: Malformed MAC rejected")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 6 FAILED: {e}")
        failed += 1
    
    # Test 7: Empty message works
    try:
        mac = generate_mac("", secret)
        assert verify_mac("", secret, mac) is True
        print("✅ TEST 7: Empty message works")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 7 FAILED: {e}")
        failed += 1
    
    # Test 8: Unicode message works
    try:
        msg = "Hello 世界 🌍"
        mac = generate_mac(msg, secret)
        assert verify_mac(msg, secret, mac) is True
        print("✅ TEST 8: Unicode message works")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 8 FAILED: {e}")
        failed += 1
    
    # Test 9: Long message (1KB) works
    try:
        msg = "A" * 1024
        mac = generate_mac(msg, secret)
        assert verify_mac(msg, secret, mac) is True
        print("✅ TEST 9: Long message (1KB) works")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 9 FAILED: {e}")
        failed += 1
    
    # Test 10: Different messages produce different MACs
    try:
        mac_a = generate_mac("hello", secret)
        mac_b = generate_mac("hello!", secret)
        assert mac_a != mac_b
        print("✅ TEST 10: Different messages → different MACs")
        passed += 1
    except Exception as e:
        print(f"❌ TEST 10 FAILED: {e}")
        failed += 1
    
    # Summary
    print("\n" + "="*60)
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)