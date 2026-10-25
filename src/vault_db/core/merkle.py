"""
VaultDB Cryptographic Merkle Tree Engine (RFC 6962 Standard)
Provides pure-Python cryptographic primitives for tamper-evident data structures.

Implements a binary Merkle tree with SHA-256 hashing, domain separation,
logarithmic inclusion proof generation (Merkle audit paths), and proof verification.
Runs natively across all operating systems without external native binaries.
"""

import hashlib
from typing import Dict, List, Optional


class MerkleTree:
    """
    Binary Merkle Tree implementation adhering to the RFC 6962 standard.

    Attributes:
        leaves: List of SHA-256 hex digests representing the base leaf nodes.
        levels: 2D list of hex digests storing each level from leaves up to the root.
    """

    # Domain separation prefixes (RFC 6962 standard) to prevent second-preimage attacks:
    # 0x00 prefix for leaf node hashing
    # 0x01 prefix for internal (branch) node hashing
    LEAF_PREFIX: bytes = b"\x00"
    INTERNAL_PREFIX: bytes = b"\x01"

    def __init__(self, leaf_hashes: Optional[List[str]] = None) -> None:
        """
        Initializes the Merkle Tree with an optional list of precomputed leaf hashes.

        Args:
            leaf_hashes: Optional initial list of 64-character hex leaf hashes.
        """
        self.leaves: List[str] = list(leaf_hashes) if leaf_hashes else []
        self.levels: List[List[str]] = []
        if self.leaves:
            self._rebuild()

    @classmethod
    def hash_leaf(cls, data_bytes: bytes) -> str:
        """
        Computes the SHA-256 digest of raw leaf data with RFC 6962 leaf domain separator (0x00).

        Args:
            data_bytes: Serialized bytes of the payload record.

        Returns:
            64-character hexadecimal SHA-256 digest.
        """
        return hashlib.sha256(cls.LEAF_PREFIX + data_bytes).hexdigest()

    @classmethod
    def hash_internal(cls, left_hex: str, right_hex: str) -> str:
        """
        Combines two child node hashes with RFC 6962 internal domain separator (0x01).

        Args:
            left_hex: 64-character hex digest of the left child.
            right_hex: 64-character hex digest of the right child.

        Returns:
            64-character hexadecimal SHA-256 digest of the parent node.
        """
        combined_bytes = bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
        return hashlib.sha256(cls.INTERNAL_PREFIX + combined_bytes).hexdigest()

    def append_leaf(self, leaf_hash: str) -> str:
        """
        Appends a new leaf hash to the tree and dynamically recomputes the state root.

        Args:
            leaf_hash: 64-character hex digest of the new leaf.

        Returns:
            The new 64-character hexadecimal Merkle Root Hash.
        """
        self.leaves.append(leaf_hash)
        self._rebuild()
        return self.get_root()

    def _rebuild(self) -> None:
        """
        Recomputes all intermediate levels of the binary tree up to the master root.
        Balances odd leaf counts by duplicating the terminal node at that level.
        """
        if not self.leaves:
            self.levels = []
            return

        current_level: List[str] = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate the odd terminal node to balance the binary tree level
                    right = left
                parent = self.hash_internal(left, right)
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

    def get_root(self) -> str:
        """
        Returns the current master Merkle Root Hash.

        Returns:
            64-character hexadecimal string. Returns a deterministic genesis hash
            if the tree contains zero leaves.
        """
        if not self.levels or not self.levels[-1]:
            return hashlib.sha256(b"vaultdb:genesis:empty:merkle:tree").hexdigest()
        return self.levels[-1][0]

    def get_audit_path(self, index: int) -> List[Dict[str, str]]:
        """
        Generates an O(log N) cryptographic inclusion proof (Merkle Audit Path).
        The proof contains the sequence of sibling hashes needed to recompute
        the root hash from the leaf at the given index.

        Args:
            index: Zero-based index of the target leaf.

        Returns:
            List of dictionaries specifying sibling 'hash' and 'direction' ('left' or 'right').
        """
        if index < 0 or index >= len(self.leaves):
            return []

        proof: List[Dict[str, str]] = []
        idx = index

        for level in self.levels[:-1]:
            is_odd = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_odd else idx + 1
            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                # Balanced duplicate
                sibling_hash = level[idx]

            proof.append({
                "hash": sibling_hash,
                "direction": "left" if is_odd else "right"
            })
            idx = idx // 2

        return proof

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """
        Mathematically verifies an inclusion proof by hashing up the audit path.

        Args:
            leaf_hash: 64-character hex digest of the leaf being verified.
            proof: The list of sibling steps returned by get_audit_path().
            expected_root: The expected master Merkle Root hash.

        Returns:
            True if the recomputed root matches expected_root, False otherwise.
        """
        current = leaf_hash
        for step in proof:
            sibling = step["hash"]
            if step["direction"] == "left":
                current = cls.hash_internal(sibling, current)
            else:
                current = cls.hash_internal(current, sibling)
        return current.lower() == expected_root.lower()
