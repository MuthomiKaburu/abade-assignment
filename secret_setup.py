"""
secret_setup.py — Shared secret key generation and storage
Project Lead & Architect Module

Usage
-----
    python secret_setup.py                  # Generate and save to secret.key
    python secret_setup.py --show           # Print the current key (for sharing)
    python secret_setup.py --env            # Print export command for shell / .env
    python secret_setup.py --length 64      # Generate a 64-byte (512-bit) key
"""

import os
import sys
import secrets
import argparse

from config import (
    SECRET_KEY_FILE,
    SECRET_KEY_ENV_VAR,
    SECRET_KEY_LENGTH,
)


def generate_key(length: int = SECRET_KEY_LENGTH) -> bytes:
    """
    Generate a cryptographically secure random key of *length* bytes.
    Uses ``secrets.token_bytes`` which reads from the OS CSPRNG.
    """
    return secrets.token_bytes(length)


def save_key_to_file(key: bytes, path: str = SECRET_KEY_FILE) -> None:
    """
    Persist the key to *path* as a hex string (one line, no newline issues).
    File permissions are set to owner-read-only (0o600) on POSIX systems.
    """
    hex_key = key.hex()
    with open(path, "w") as fh:
        fh.write(hex_key)

    # Restrict permissions on Unix/Linux/macOS
    if hasattr(os, "chmod"):
        os.chmod(path, 0o600)

    print(f"[✓] Secret key saved to '{path}' ({len(key)} bytes / {len(key)*8} bits)")
    print(f"    Permissions set to 600 (owner read/write only).")


def load_existing_key(path: str = SECRET_KEY_FILE) -> bytes | None:
    """Return the key from *path* as bytes, or None if file does not exist."""
    if not os.path.exists(path):
        return None
    with open(path, "r") as fh:
        hex_key = fh.read().strip()
    return bytes.fromhex(hex_key)


def print_env_export(key: bytes) -> None:
    """Print a shell export statement and a .env-style line for the key."""
    hex_key = key.hex()
    print("\n# ── Shell export (paste into terminal or add to .env) ──")
    print(f'export {SECRET_KEY_ENV_VAR}="{hex_key}"')
    print(f'\n# .env file entry:')
    print(f'{SECRET_KEY_ENV_VAR}="{hex_key}"')


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HMAC-SHA256 shared secret key manager"
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display the current key stored in secret.key",
    )
    parser.add_argument(
        "--env",
        action="store_true",
        help="Print shell export / .env line for the current key",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=SECRET_KEY_LENGTH,
        help=f"Key length in bytes (default: {SECRET_KEY_LENGTH})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key without prompting",
    )
    args = parser.parse_args()

    # ── --show ────────────────────────────────────────────────────────────────
    if args.show:
        key = load_existing_key()
        if key is None:
            print(f"[!] No key found at '{SECRET_KEY_FILE}'. Run without --show to generate one.")
            sys.exit(1)
        print(f"Current key ({len(key)} bytes / {len(key)*8} bits):")
        print(f"  HEX    : {key.hex()}")
        import base64
        print(f"  BASE64 : {base64.b64encode(key).decode()}")
        return

    # ── --env ─────────────────────────────────────────────────────────────────
    if args.env:
        key = load_existing_key()
        if key is None:
            print(f"[!] No key found at '{SECRET_KEY_FILE}'. Generate one first.")
            sys.exit(1)
        print_env_export(key)
        return

    # ── Generate (default) ────────────────────────────────────────────────────
    if os.path.exists(SECRET_KEY_FILE) and not args.force:
        answer = input(
            f"[!] '{SECRET_KEY_FILE}' already exists. Overwrite? (y/N): "
        ).strip().lower()
        if answer != "y":
            print("Aborted — existing key kept.")
            sys.exit(0)

    key = generate_key(args.length)
    save_key_to_file(key)
    print_env_export(key)
    print("\n[i] Share this secret securely (encrypted channel or secrets manager).")
    print("    Never commit secret.key to version control.")


if __name__ == "__main__":
    main()
