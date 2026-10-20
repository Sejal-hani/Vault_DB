"""
VaultDB Application-Level Envelope Encryption (AES-256-GCM)
Protects sensitive columns (SSNs, PII) at rest in PostgreSQL.
Anyone with direct database access or disk backups only sees encrypted ciphertext.
"""

import base64
import hashlib
import os
from typing import Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config.settings import settings


class ColumnEncryption:
    """Provides authenticated AES-256-GCM encryption for columns at rest."""

    _PREFIX = "enc:gcm:"

    @classmethod
    def _get_key(cls) -> bytes:
        # Derives a deterministic 256-bit (32-byte) key from settings.SECRET_KEY
        secret = getattr(settings, "SECRET_KEY", "vaultdb-default-encryption-secret-key")
        return hashlib.sha256(secret.encode("utf-8")).digest()

    @classmethod
    def encrypt(cls, plaintext: Optional[str]) -> Optional[str]:
        """Encrypts plaintext string to AES-256-GCM ciphertext prefixed with 'enc:gcm:'."""
        if plaintext is None:
            return None
        text_str = str(plaintext).strip()
        if not text_str or text_str.startswith(cls._PREFIX):
            return text_str

        key = cls._get_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        ciphertext = aesgcm.encrypt(nonce, text_str.encode("utf-8"), None)
        encoded = base64.b64encode(nonce + ciphertext).decode("ascii")
        return f"{cls._PREFIX}{encoded}"

    @classmethod
    def decrypt(cls, val: Any) -> Any:
        """Decrypts an 'enc:gcm:' ciphertext string back to plaintext."""
        if not isinstance(val, str) or not val.startswith(cls._PREFIX):
            return val

        try:
            raw_b64 = val[len(cls._PREFIX):]
            payload = base64.b64decode(raw_b64)
            if len(payload) < 28:  # 12 nonce + 16 auth tag minimum
                return val
            nonce = payload[:12]
            ciphertext = payload[12:]
            key = cls._get_key()
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_bytes.decode("utf-8")
        except Exception:
            # If decryption fails, return original value safely
            return val

    @classmethod
    def is_encrypted(cls, val: Any) -> bool:
        """Returns True if the value is an AES-256-GCM ciphertext."""
        return isinstance(val, str) and val.startswith(cls._PREFIX)


encrypt_field = ColumnEncryption.encrypt
decrypt_field = ColumnEncryption.decrypt
