"""
VaultDB Authentication & Cryptographic Security Utilities
Implements salted PBKDF2-HMAC-SHA256 password hashing and secure API key generation.
"""

import os
import hmac
import hashlib
import secrets
from typing import Tuple


PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using PBKDF2-HMAC-SHA256 with a cryptographically secure 16-byte salt.
    Returns: 'salt_hex$hash_hex'
    """
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return f"{salt.hex()}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a 'salt_hex$hash_hex' string using timing-safe comparison.
    """
    if not stored_hash or "$" not in stored_hash:
        return False
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(hash_hex)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
            dklen=32,
        )
        return hmac.compare_digest(key, expected_key)
    except Exception:
        return False


def generate_api_key(prefix: str = "vlt") -> str:
    """
    Generates a high-entropy API key.
    Format: 'vlt_key_{prefix}_{32_hex_chars}'
    """
    random_token = secrets.token_hex(16)
    return f"{prefix}_key_{random_token}"
