"""
VaultDB JWT Token Handler
Implements RFC 7519 compliant HMAC-SHA256 (HS256) JSON Web Tokens.
"""

import json
import hmac
import hashlib
import base64
import time
from typing import Any, Dict, Optional
from config.settings import settings

JWT_SECRET_KEY = getattr(settings, "SECRET_KEY", "vaultdb-enterprise-merkle-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600  # 1 hour


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def create_access_token(data: Dict[str, Any], expires_seconds: int = JWT_EXPIRATION_SECONDS) -> str:
    """
    Creates a signed HS256 JWT token with an expiration timestamp.
    """
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    now = int(time.time())
    payload = dict(data)
    payload["iat"] = now
    payload["exp"] = now + expires_seconds

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    encoded_header = _base64url_encode(header_bytes)
    encoded_payload = _base64url_encode(payload_bytes)

    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _base64url_encode(signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Verifies the cryptographic HMAC-SHA256 signature and expiration of a JWT token.
    Raises ValueError if invalid, tampered, or expired.
    """
    if not token or token.count(".") != 2:
        raise ValueError("Malformed token format.")

    encoded_header, encoded_payload, encoded_signature = token.split(".")

    # Verify signature
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    expected_signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided_signature = _base64url_decode(encoded_signature)

    if not hmac.compare_digest(expected_signature, provided_signature):
        raise ValueError("Invalid cryptographic token signature.")

    # Parse payload
    payload_bytes = _base64url_decode(encoded_payload)
    payload = json.loads(payload_bytes.decode("utf-8"))

    # Check expiration
    exp = payload.get("exp")
    if exp and int(time.time()) > int(exp):
        raise ValueError("Token has expired. Please re-authenticate.")

    return payload
