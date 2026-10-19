"""
VaultDB - Cryptographically Immutable Database Middleware
"""

from .core.engine import VaultEngine
from .vault_client import connect, VaultConnection, VaultClient, AuthenticationError

__all__ = ["VaultEngine", "connect", "VaultConnection", "VaultClient", "AuthenticationError"]
