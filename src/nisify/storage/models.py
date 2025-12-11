"""
Data models for evidence storage.

This module defines the dataclasses used to represent stored evidence,
collection runs, and maturity snapshots in the database.

Schema Design Decisions:
    - IDs are UUIDs stored as strings for portability
    - Timestamps are stored as ISO format strings in UTC
    - JSON data is stored as TEXT in SQLite for flexibility
    - File paths are relative to the data directory
    - Hashes are SHA-256 hex strings for integrity verification
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class CollectionRun:
    """
    Record of a single evidence collection run.

    A collection run represents one execution of a collector against a platform.
    Multiple evidence items may be collected during a single run.

    Attributes:
        id: Unique identifier for this collection run.
        platform: Platform that was collected (e.g., "aws", "okta").
        timestamp: When the collection started (UTC).
        success: True if collection completed without fatal errors.
        partial: True if some evidence types succeeded while others failed.
        duration_seconds: Total time taken for collection.
        evidence_count: Number of evidence items collected.
        error_count: Number of errors encountered.
        errors: List of error messages (if any).

    Database Table: collection_runs
        - id TEXT PRIMARY KEY
        - platform TEXT NOT NULL
        - timestamp TEXT NOT NULL
        - success INTEGER NOT NULL (0 or 1)
        - partial INTEGER NOT NULL (0 or 1)
        - duration_seconds REAL NOT NULL
        - evidence_count INTEGER NOT NULL
        - error_count INTEGER NOT NULL
        - errors_json TEXT
    """

    id: str
    platform: str
    timestamp: datetime
    success: bool
    partial: bool
    duration_seconds: float
    evidence_count: int
    error_count: int
    errors: list[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        platform: str,
        success: bool,
        partial: bool,
        duration_seconds: float,
        evidence_count: int,
        error_count: int,
        errors: list[str] | None = None,
    ) -> CollectionRun:
        """
        Create a new CollectionRun with auto-generated ID and timestamp.

        Args:
            platform: Platform identifier.
            success: Whether collection succeeded.
            partial: Whether collection was partial.
            duration_seconds: Collection duration.
            evidence_count: Number of evidence items.
            error_count: Number of errors.
            errors: List of error messages.

        Returns:
            New CollectionRun instance.
        """
        return cls(
            id=str(uuid.uuid4()),
            platform=platform,
            timestamp=datetime.now(UTC),
            success=success,
            partial=partial,
            duration_seconds=duration_seconds,
            evidence_count=evidence_count,
            error_count=error_count,
            errors=errors or [],
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "platform": self.platform,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "partial": self.partial,
            "duration_seconds": self.duration_seconds,
            "evidence_count": self.evidence_count,
            "error_count": self.error_count,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionRun:
        """Create from dictionary."""
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        return cls(
            id=data["id"],
            platform=data["platform"],
            timestamp=timestamp,
            success=data["success"],
            partial=data["partial"],
            duration_seconds=data["duration_seconds"],
            evidence_count=data["evidence_count"],
            error_count=data["error_count"],
            errors=data.get("errors", []),
        )


@dataclass
class StoredEvidence:
    """
    Record of a stored evidence item.

    Represents evidence that has been persisted to disk. The raw evidence
    data is stored in a JSON file, while this record tracks metadata and
    provides a reference to the file.

    Attributes:
        id: Unique identifier for this evidence item.
        collection_run_id: ID of the collection run that produced this evidence.
        platform: Platform that provided the evidence.
        evidence_type: Type of evidence (e.g., "mfa_status", "audit_logging").
        collected_at: When the evidence was collected (UTC).
        file_path: Relative path to the JSON file containing raw data.
        file_hash: SHA-256 hash of the file contents for integrity verification.
        metadata: Additional context about the evidence.
        item_count: Number of items in the evidence (e.g., number of users).

    Database Table: evidence_items
        - id TEXT PRIMARY KEY
        - collection_run_id TEXT NOT NULL REFERENCES collection_runs(id)
        - platform TEXT NOT NULL
        - evidence_type TEXT NOT NULL
        - collected_at TEXT NOT NULL
        - file_path TEXT NOT NULL
        - file_hash TEXT NOT NULL
        - metadata_json TEXT
        - item_count INTEGER

    Indexes:
        - idx_evidence_platform_type ON evidence_items(platform, evidence_type)
        - idx_evidence_collected_at ON evidence_items(collected_at)
        - idx_evidence_run_id ON evidence_items(collection_run_id)
    """

    id: str
    collection_run_id: str
    platform: str
    evidence_type: str
    collected_at: datetime
    file_path: str
    file_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)
    item_count: int | None = None

    @classmethod
    def create(
        cls,
        collection_run_id: str,
        platform: str,
        evidence_type: str,
        file_path: str,
        file_hash: str,
        metadata: dict[str, Any] | None = None,
        item_count: int | None = None,
    ) -> StoredEvidence:
        """
        Create a new StoredEvidence with auto-generated ID and timestamp.

        Args:
            collection_run_id: ID of the parent collection run.
            platform: Platform identifier.
            evidence_type: Type of evidence.
            file_path: Path to evidence JSON file.
            file_hash: SHA-256 hash of file.
            metadata: Additional context.
            item_count: Number of items in evidence.

        Returns:
            New StoredEvidence instance.
        """
        return cls(
            id=str(uuid.uuid4()),
            collection_run_id=collection_run_id,
            platform=platform,
            evidence_type=evidence_type,
            collected_at=datetime.now(UTC),
            file_path=file_path,
            file_hash=file_hash,
            metadata=metadata or {},
            item_count=item_count,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "collection_run_id": self.collection_run_id,
            "platform": self.platform,
            "evidence_type": self.evidence_type,
            "collected_at": self.collected_at.isoformat(),
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "metadata": self.metadata,
            "item_count": self.item_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredEvidence:
        """Create from dictionary."""
        collected_at = data["collected_at"]
        if isinstance(collected_at, str):
            collected_at = datetime.fromisoformat(collected_at)
        return cls(
            id=data["id"],
            collection_run_id=data["collection_run_id"],
            platform=data["platform"],
            evidence_type=data["evidence_type"],
            collected_at=collected_at,
            file_path=data["file_path"],
            file_hash=data["file_hash"],
            metadata=data.get("metadata", {}),
            item_count=data.get("item_count"),
        )


@dataclass
class ControlMapping:
    """
    Record of evidence mapped to a NIST control.

    Represents the relationship between an evidence item and a NIST CSF 2.0
    control. Multiple evidence items may map to the same control, and
    one evidence item may satisfy multiple controls.

    Attributes:
        id: Unique identifier for this mapping.
        evidence_id: ID of the evidence item.
        control_id: NIST control ID (e.g., "PR.AC-01").
        mapping_confidence: Confidence score (0.0 - 1.0).
        mapping_reason: Human-readable explanation of why this maps.
        created_at: When this mapping was created.

    Database Table: control_mappings
        - id TEXT PRIMARY KEY
        - evidence_id TEXT NOT NULL REFERENCES evidence_items(id)
        - control_id TEXT NOT NULL
        - mapping_confidence REAL NOT NULL
        - mapping_reason TEXT
        - created_at TEXT NOT NULL

    Indexes:
        - idx_mapping_evidence ON control_mappings(evidence_id)
        - idx_mapping_control ON control_mappings(control_id)
    """

    id: str
    evidence_id: str
    control_id: str
    mapping_confidence: float
    mapping_reason: str
    created_at: datetime

    @classmethod
    def create(
        cls,
        evidence_id: str,
        control_id: str,
        mapping_confidence: float,
        mapping_reason: str,
    ) -> ControlMapping:
        """
        Create a new ControlMapping with auto-generated ID and timestamp.

        Args:
            evidence_id: ID of the evidence item.
            control_id: NIST control ID.
            mapping_confidence: Confidence score (0.0 - 1.0).
            mapping_reason: Explanation for the mapping.

        Returns:
            New ControlMapping instance.
        """
        return cls(
            id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            control_id=control_id,
            mapping_confidence=mapping_confidence,
            mapping_reason=mapping_reason,
            created_at=datetime.now(UTC),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "evidence_id": self.evidence_id,
            "control_id": self.control_id,
            "mapping_confidence": self.mapping_confidence,
            "mapping_reason": self.mapping_reason,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ControlMapping:
        """Create from dictionary."""
        created_at = data["created_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        return cls(
            id=data["id"],
            evidence_id=data["evidence_id"],
            control_id=data["control_id"],
            mapping_confidence=data["mapping_confidence"],
            mapping_reason=data["mapping_reason"],
            created_at=created_at,
        )


@dataclass
class MaturitySnapshot:
    """
    Point-in-time snapshot of maturity level for a NIST control.

    Maturity snapshots are taken after each evidence collection and mapping
    run. They enable historical trend analysis and progress tracking.

    Attributes:
        id: Unique identifier for this snapshot.
        timestamp: When the snapshot was taken (UTC).
        function_id: NIST function ID (e.g., "GV", "ID", "PR").
        category_id: NIST category ID (e.g., "GV.OC", "PR.AC").
        subcategory_id: NIST subcategory ID (e.g., "PR.AC-01"), or None for rollup.
        maturity_level: Calculated maturity level (0-4).
        evidence_count: Number of evidence items supporting this level.
        confidence: Overall confidence in the maturity assessment (0.0 - 1.0).
        details: Additional details about the assessment.

    Database Table: maturity_snapshots
        - id TEXT PRIMARY KEY
        - timestamp TEXT NOT NULL
        - function_id TEXT NOT NULL
        - category_id TEXT
        - subcategory_id TEXT
        - maturity_level INTEGER NOT NULL
        - evidence_count INTEGER NOT NULL
        - confidence REAL NOT NULL
        - details_json TEXT

    Indexes:
        - idx_snapshot_timestamp ON maturity_snapshots(timestamp)
        - idx_snapshot_control ON maturity_snapshots(function_id, category_id, subcategory_id)

    Retention:
        Maturity snapshots are NEVER deleted, even during cleanup.
        They are essential for historical trend analysis and audit evidence.
    """

    id: str
    timestamp: datetime
    function_id: str
    category_id: str | None
    subcategory_id: str | None
    maturity_level: int
    evidence_count: int
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        function_id: str,
        maturity_level: int,
        evidence_count: int,
        confidence: float,
        category_id: str | None = None,
        subcategory_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> MaturitySnapshot:
        """
        Create a new MaturitySnapshot with auto-generated ID and timestamp.

        Args:
            function_id: NIST function ID.
            maturity_level: Maturity level (0-4).
            evidence_count: Number of supporting evidence items.
            confidence: Confidence score (0.0 - 1.0).
            category_id: NIST category ID (optional).
            subcategory_id: NIST subcategory ID (optional).
            details: Additional assessment details.

        Returns:
            New MaturitySnapshot instance.
        """
        return cls(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            function_id=function_id,
            category_id=category_id,
            subcategory_id=subcategory_id,
            maturity_level=maturity_level,
            evidence_count=evidence_count,
            confidence=confidence,
            details=details or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "function_id": self.function_id,
            "category_id": self.category_id,
            "subcategory_id": self.subcategory_id,
            "maturity_level": self.maturity_level,
            "evidence_count": self.evidence_count,
            "confidence": self.confidence,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MaturitySnapshot:
        """Create from dictionary."""
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        return cls(
            id=data["id"],
            timestamp=timestamp,
            function_id=data["function_id"],
            category_id=data.get("category_id"),
            subcategory_id=data.get("subcategory_id"),
            maturity_level=data["maturity_level"],
            evidence_count=data["evidence_count"],
            confidence=data["confidence"],
            details=data.get("details", {}),
        )


@dataclass
class EvidenceQuery:
    """
    Parameters for querying stored evidence.

    Used to filter evidence when retrieving from the store.

    Attributes:
        platform: Filter by platform (optional).
        evidence_type: Filter by evidence type (optional).
        start_date: Filter by collected_at >= start_date (optional).
        end_date: Filter by collected_at <= end_date (optional).
        control_id: Filter by mapped control ID (optional).
        limit: Maximum number of results (optional).
        offset: Number of results to skip (optional).
    """

    platform: str | None = None
    evidence_type: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    control_id: str | None = None
    limit: int | None = None
    offset: int | None = None
