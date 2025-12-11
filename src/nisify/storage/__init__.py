"""
Evidence storage engine.

This module provides persistent storage for collected evidence using a
hybrid approach: SQLite for structured metadata and queries, JSON files
for raw evidence artifacts.

Features:
    - SHA-256 integrity verification for tamper detection
    - Full audit trail of all collected evidence
    - Automatic retention and cleanup with archiving
    - Historical trend tracking via maturity snapshots
    - Atomic file writes to prevent corruption
    - Transaction safety for database operations

Storage Structure:
    data/
        nisify.db                           # SQLite database
        evidence/
            {platform}/
                {YYYY-MM-DD}/
                    {evidence_type}_{uuid}.json
        archives/
            evidence_before_{date}.json.gz  # Compressed archives

Usage:
    from nisify.storage import EvidenceStore

    store = EvidenceStore()
    run_id = store.save_collection_run(collection_result)
    evidence = store.get_evidence_by_type("mfa_status")
    history = store.get_maturity_history("PR.AC-01", days=90)
"""

from nisify.storage.evidence_store import (
    EvidenceNotFoundError,
    EvidenceStore,
    IntegrityError,
    StorageError,
)
from nisify.storage.models import (
    CollectionRun,
    ControlMapping,
    EvidenceQuery,
    MaturitySnapshot,
    StoredEvidence,
)

__all__ = [
    # Main store class
    "EvidenceStore",
    # Data models
    "CollectionRun",
    "StoredEvidence",
    "ControlMapping",
    "MaturitySnapshot",
    "EvidenceQuery",
    # Exceptions
    "StorageError",
    "IntegrityError",
    "EvidenceNotFoundError",
]
