"""
config.py — Shared constants and secret key loader
Project Lead & Architect Module
"""

import os
from dotenv import load_dotenv

# ── Load .env file if present ──────────────────────────────────────────────────
load_dotenv()

# ── Cryptographic constants ────────────────────────────────────────────────────
HASH_ALGORITHM = "sha256"          # HMAC hash function
MAC_ENCODING   = "hex"             # Output encoding: "hex" or "base64"
MESSAGE_ENCODING = "utf-8"         # String → bytes encoding for messages
SECRET_ENCODING  = "utf-8"         # String → bytes encoding for secret key

# ── Secret key configuration ───────────────────────────────────────────────────
SECRET_KEY_ENV_VAR = "HMAC_SECRET_KEY"   # Environment variable name
SECRET_KEY_FILE    = "secret.key"        # Fallback file path (relative to project root)
SECRET_KEY_LENGTH  = 32                  # Bytes — 256-bit key (used during generation)

# ── Message format ─────────────────────────────────────────────────────────────
# Sender and receiver must agree on these delimiters
MESSAGE_MAC_SEPARATOR = "||"       # Separates payload from MAC in transmission


def load_secret() -> bytes:
    """
    Load the shared secret key using the following priority:
      1. HMAC_SECRET_KEY environment variable
      2. secret.key file on disk
    Raises RuntimeError if neither source is available.
    """
    # 1. Environment variable (highest priority — suitable for production/CI)
    env_secret = os.environ.get(SECRET_KEY_ENV_VAR)
    if env_secret:
        return env_secret.encode(SECRET_ENCODING)

    # 2. Key file (development / local fallback)
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "rb") as fh:
            key = fh.read().strip()
        if key:
            return key

    raise RuntimeError(
        f"Shared secret not found.\n"
        f"  • Set the environment variable  {SECRET_KEY_ENV_VAR}=<your-secret>\n"
        f"  • Or run `python secret_setup.py` to generate {SECRET_KEY_FILE}"
    )
