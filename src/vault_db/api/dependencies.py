"""
VaultDB API Shared Dependencies and Serialization Utilities
Provides singleton access to VaultEngine and data serialization helpers.
"""

import logging
from decimal import Decimal
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Any, Optional

from src.vault_db.core.engine import VaultEngine

logger = logging.getLogger(__name__)

IST_TZ = ZoneInfo("Asia/Kolkata")

# Global singleton engine instance
_engine: Optional[VaultEngine] = None


def get_engine() -> VaultEngine:
    """Returns the singleton VaultEngine instance, initializing if needed."""
    global _engine
    if _engine is None:
        _engine = VaultEngine()
    return _engine


def set_engine(engine: Optional[VaultEngine]) -> None:
    """Sets or overrides the singleton VaultEngine instance."""
    global _engine
    _engine = engine


def close_engine() -> None:
    """Closes connections and clears the singleton VaultEngine instance."""
    global _engine
    if _engine is not None:
        try:
            _engine.close()
        except Exception as e:
            logger.warning(f"Error closing VaultEngine: {e}")
        finally:
            _engine = None


def serialize_item(item: Any) -> Any:
    """Serializes special database types (Decimal, datetime) into JSON-compatible primitives."""
    if isinstance(item, Decimal):
        return float(item)
    if isinstance(item, datetime):
        try:
            dt = item.astimezone(IST_TZ) if item.tzinfo else item.replace(tzinfo=ZoneInfo("UTC")).astimezone(IST_TZ)
            return dt.strftime("%Y-%m-%d %H:%M:%S IST")
        except Exception:
            return item.strftime("%Y-%m-%d %H:%M:%S IST")
    return item
