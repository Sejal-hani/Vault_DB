"""
VaultDB Core Security & Middleware Engine Package
Encapsulates query parsing, zero-trust RBAC, Merkle cryptography, and compliance pipelines.
"""

from .merkle import MerkleTree
from .rbac import RBACManager, AccessDeniedError, QueryExecutionError
from .parser import SQLParser, QueryAnalysis
from .crypto import ColumnEncryption, encrypt_field, decrypt_field
from .masking import mask_tabular_results, mask_query_text, mask_ssn
from .rls import apply_row_level_security
from .anomaly import AnomalyDetector
from .alerts import AlertDispatcher
from .approval import ApprovalManager
from .engine import VaultEngine

__all__ = [
    "VaultEngine",
    "MerkleTree",
    "RBACManager",
    "AccessDeniedError",
    "QueryExecutionError",
    "SQLParser",
    "QueryAnalysis",
    "ColumnEncryption",
    "encrypt_field",
    "decrypt_field",
    "mask_tabular_results",
    "mask_query_text",
    "mask_ssn",
    "apply_row_level_security",
    "AnomalyDetector",
    "AlertDispatcher",
    "ApprovalManager",
]
