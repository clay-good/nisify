"""
Evidence storage engine for Nisify.

This module provides the EvidenceStore class which manages persistent storage
of collected evidence using a hybrid approach:
    - SQLite database for structured metadata and efficient queries
    - JSON files for raw evidence artifacts

Storage Structure:
    data/
        nisify.db                           # SQLite database
        evidence/
            {platform}/
                {YYYY-MM-DD}/
                    {evidence_type}_{uuid}.json

Design Decisions:
    - SQLite is used for its simplicity, portability, and ACID compliance
    - JSON files preserve raw evidence in human-readable format
    - SHA-256 hashes provide tamper detection
    - Atomic file writes (temp file + rename) prevent corruption
    - Maturity snapshots are never deleted for audit trail

Thread Safety:
    The store uses SQLite's thread-safe mode and connection-per-operation
    pattern. Multiple processes should use separate EvidenceStore instances.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import sqlite3
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nisify.storage.models import (
    CollectionRun,
    ControlMapping,
    EvidenceQuery,
    MaturitySnapshot,
    StoredEvidence,
)

if TYPE_CHECKING:
    from nisify.collectors.base import CollectionResult, Evidence


logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for storage errors."""

    pass


class IntegrityError(StorageError):
    """Raised when evidence integrity verification fails."""

    pass


class EvidenceNotFoundError(StorageError):
    """Raised when requested evidence is not found."""

    pass


# Database schema version for migrations
SCHEMA_VERSION = 1


# SQL statements for creating tables
CREATE_TABLES_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Collection run records
CREATE TABLE IF NOT EXISTS collection_runs (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    success INTEGER NOT NULL,
    partial INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    evidence_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    errors_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_platform ON collection_runs(platform);
CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON collection_runs(timestamp);

-- Evidence item records
CREATE TABLE IF NOT EXISTS evidence_items (
    id TEXT PRIMARY KEY,
    collection_run_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    metadata_json TEXT,
    item_count INTEGER,
    FOREIGN KEY (collection_run_id) REFERENCES collection_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_platform_type ON evidence_items(platform, evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_collected_at ON evidence_items(collected_at);
CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence_items(collection_run_id);

-- Control to evidence mappings
CREATE TABLE IF NOT EXISTS control_mappings (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    mapping_confidence REAL NOT NULL,
    mapping_reason TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence_items(id)
);

CREATE INDEX IF NOT EXISTS idx_mapping_evidence ON control_mappings(evidence_id);
CREATE INDEX IF NOT EXISTS idx_mapping_control ON control_mappings(control_id);

-- Maturity snapshots (never deleted)
CREATE TABLE IF NOT EXISTS maturity_snapshots (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    function_id TEXT NOT NULL,
    category_id TEXT,
    subcategory_id TEXT,
    maturity_level INTEGER NOT NULL,
    evidence_count INTEGER NOT NULL,
    confidence REAL NOT NULL,
    details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_snapshot_timestamp ON maturity_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_snapshot_control ON maturity_snapshots(function_id, category_id, subcategory_id);
"""


class EvidenceStore:
    """
    Persistent storage for evidence and maturity data.

    Provides methods for saving, querying, and managing evidence collected
    from various platforms. Uses SQLite for metadata and JSON files for
    raw evidence artifacts.

    Example:
        store = EvidenceStore(data_dir=Path("./data"))

        # Save a collection run and its evidence
        run_id = store.save_collection_run(collection_result)

        # Query evidence
        evidence = store.get_evidence_by_type("mfa_status")
        latest = store.get_latest_evidence("aws")

        # Get maturity history
        history = store.get_maturity_history("PR.AC-01", days=90)

        # Cleanup old evidence
        store.cleanup(retention_days=365)

    Attributes:
        data_dir: Base directory for all data storage.
        db_path: Path to the SQLite database file.
        evidence_dir: Directory for evidence JSON files.
    """

    def __init__(self, data_dir: Path | str | None = None) -> None:
        """
        Initialize the evidence store.

        Args:
            data_dir: Base directory for data storage. Defaults to ~/.nisify/data
        """
        if data_dir is None:
            data_dir = Path.home() / ".nisify" / "data"
        elif isinstance(data_dir, str):
            data_dir = Path(data_dir)

        self.data_dir = data_dir
        self.db_path = data_dir / "nisify.db"
        self.evidence_dir = data_dir / "evidence"

        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            conn.executescript(CREATE_TABLES_SQL)

            # Check/set schema version
            cursor = conn.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            )
            row = cursor.fetchone()

            if row is None:
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now(UTC).isoformat()),
                )
                logger.info(f"Initialized database schema version {SCHEMA_VERSION}")
            elif row[0] < SCHEMA_VERSION:
                # Future: handle migrations here
                logger.warning(
                    f"Database schema version {row[0]} is older than "
                    f"expected version {SCHEMA_VERSION}"
                )

            conn.commit()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Get a database connection with proper settings.

        Yields:
            SQLite connection with row factory set.
        """
        conn = sqlite3.connect(
            str(self.db_path),
            isolation_level=None,  # Autocommit mode, we manage transactions manually
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _compute_file_hash(self, file_path: Path) -> str:
        """
        Compute SHA-256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hex-encoded SHA-256 hash.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _write_evidence_file(
        self,
        platform: str,
        evidence_type: str,
        data: dict[str, Any],
        evidence_id: str,
    ) -> tuple[str, str]:
        """
        Write evidence data to a JSON file atomically.

        Args:
            platform: Platform identifier.
            evidence_type: Type of evidence.
            data: Evidence data to write.
            evidence_id: Unique ID for the evidence.

        Returns:
            Tuple of (relative_file_path, file_hash).
        """
        # Create directory structure
        date_str = datetime.now(UTC).strftime("%Y-%m-%d")
        evidence_subdir = self.evidence_dir / platform / date_str
        evidence_subdir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        filename = f"{evidence_type}_{evidence_id}.json"
        file_path = evidence_subdir / filename

        # Write atomically using temp file + rename
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=".json",
            dir=str(evidence_subdir),
        )
        try:
            with os.fdopen(temp_fd, "w") as f:
                json.dump(data, f, indent=2, default=str)
            os.rename(temp_path, file_path)
        except Exception:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        # Compute hash
        file_hash = self._compute_file_hash(file_path)

        # Return relative path
        relative_path = str(file_path.relative_to(self.data_dir))
        return relative_path, file_hash

    def _read_evidence_file(self, file_path: str, expected_hash: str | None = None) -> dict[str, Any]:
        """
        Read evidence data from a JSON file with optional integrity check.

        Args:
            file_path: Relative path to the evidence file.
            expected_hash: Expected SHA-256 hash for verification.

        Returns:
            Evidence data dictionary.

        Raises:
            EvidenceNotFoundError: If the file does not exist.
            IntegrityError: If hash verification fails.
        """
        full_path = self.data_dir / file_path

        if not full_path.exists():
            raise EvidenceNotFoundError(f"Evidence file not found: {file_path}")

        # Verify integrity if hash provided
        if expected_hash:
            actual_hash = self._compute_file_hash(full_path)
            if actual_hash != expected_hash:
                raise IntegrityError(
                    f"Evidence file integrity check failed for {file_path}. "
                    f"Expected hash {expected_hash}, got {actual_hash}"
                )

        with open(full_path) as f:
            data: dict[str, Any] = json.load(f)
            return data

    # -------------------------------------------------------------------------
    # Collection Run Methods
    # -------------------------------------------------------------------------

    def save_collection_run(self, result: CollectionResult) -> str:
        """
        Save a collection run and all its evidence items.

        This is the main method for persisting collection results. It:
        1. Creates a collection_run record
        2. Writes each evidence item to a JSON file
        3. Creates evidence_item records in the database
        4. All operations are wrapped in a transaction

        Args:
            result: CollectionResult from a collector.

        Returns:
            The collection run ID.

        Raises:
            StorageError: If storage fails.
        """
        # Create collection run record
        run = CollectionRun.create(
            platform=result.platform,
            success=result.success,
            partial=result.partial,
            duration_seconds=result.duration_seconds,
            evidence_count=len(result.evidence_items),
            error_count=len(result.errors),
            errors=result.errors,
        )

        with self._get_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")

                # Insert collection run
                conn.execute(
                    """
                    INSERT INTO collection_runs (
                        id, platform, timestamp, success, partial,
                        duration_seconds, evidence_count, error_count, errors_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.id,
                        run.platform,
                        run.timestamp.isoformat(),
                        1 if run.success else 0,
                        1 if run.partial else 0,
                        run.duration_seconds,
                        run.evidence_count,
                        run.error_count,
                        json.dumps(run.errors) if run.errors else None,
                    ),
                )

                # Save each evidence item
                for evidence in result.evidence_items:
                    self._save_evidence_item(conn, evidence, run.id)

                conn.execute("COMMIT")
                logger.info(
                    f"Saved collection run {run.id} with "
                    f"{run.evidence_count} evidence items"
                )
                return run.id

            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to save collection run: {e}")
                raise StorageError(f"Failed to save collection run: {e}") from e

    def _save_evidence_item(
        self,
        conn: sqlite3.Connection,
        evidence: Evidence,
        run_id: str,
    ) -> str:
        """
        Save a single evidence item (internal helper).

        Args:
            conn: Database connection (within a transaction).
            evidence: Evidence item to save.
            run_id: Parent collection run ID.

        Returns:
            The evidence item ID.
        """
        # Write evidence file
        file_path, file_hash = self._write_evidence_file(
            platform=evidence.platform,
            evidence_type=evidence.evidence_type,
            data=evidence.raw_data,
            evidence_id=evidence.id,
        )

        # Determine item count from raw data
        item_count = None
        if isinstance(evidence.raw_data, dict):
            # Look for common count fields
            for key in ["total_count", "total_users", "total_devices", "total_events"]:
                if key in evidence.raw_data:
                    item_count = evidence.raw_data[key]
                    break
            # Or count items in a list field
            if item_count is None:
                for key in ["users", "devices", "events", "findings", "items"]:
                    if key in evidence.raw_data and isinstance(
                        evidence.raw_data[key], list
                    ):
                        item_count = len(evidence.raw_data[key])
                        break

        # Create stored evidence record
        stored = StoredEvidence.create(
            collection_run_id=run_id,
            platform=evidence.platform,
            evidence_type=evidence.evidence_type,
            file_path=file_path,
            file_hash=file_hash,
            metadata=evidence.metadata,
            item_count=item_count,
        )
        # Use the same ID as the original evidence
        stored.id = evidence.id
        stored.collected_at = evidence.collected_at

        # Insert into database
        conn.execute(
            """
            INSERT INTO evidence_items (
                id, collection_run_id, platform, evidence_type,
                collected_at, file_path, file_hash, metadata_json, item_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored.id,
                stored.collection_run_id,
                stored.platform,
                stored.evidence_type,
                stored.collected_at.isoformat(),
                stored.file_path,
                stored.file_hash,
                json.dumps(stored.metadata) if stored.metadata else None,
                stored.item_count,
            ),
        )

        return stored.id

    def get_collection_run(self, run_id: str) -> CollectionRun | None:
        """
        Get a collection run by ID.

        Args:
            run_id: Collection run ID.

        Returns:
            CollectionRun or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM collection_runs WHERE id = ?", (run_id,)
            )
            row = cursor.fetchone()
            if row is None:
                return None

            return CollectionRun(
                id=row["id"],
                platform=row["platform"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                success=bool(row["success"]),
                partial=bool(row["partial"]),
                duration_seconds=row["duration_seconds"],
                evidence_count=row["evidence_count"],
                error_count=row["error_count"],
                errors=json.loads(row["errors_json"]) if row["errors_json"] else [],
            )

    def get_recent_runs(
        self,
        platform: str | None = None,
        limit: int = 10,
    ) -> list[CollectionRun]:
        """
        Get recent collection runs.

        Args:
            platform: Filter by platform (optional).
            limit: Maximum number of runs to return.

        Returns:
            List of CollectionRun objects, most recent first.
        """
        with self._get_connection() as conn:
            if platform:
                cursor = conn.execute(
                    """
                    SELECT * FROM collection_runs
                    WHERE platform = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (platform, limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM collection_runs
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                )

            runs = []
            for row in cursor:
                runs.append(
                    CollectionRun(
                        id=row["id"],
                        platform=row["platform"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        success=bool(row["success"]),
                        partial=bool(row["partial"]),
                        duration_seconds=row["duration_seconds"],
                        evidence_count=row["evidence_count"],
                        error_count=row["error_count"],
                        errors=(
                            json.loads(row["errors_json"])
                            if row["errors_json"]
                            else []
                        ),
                    )
                )
            return runs

    # -------------------------------------------------------------------------
    # Single Evidence Storage Methods
    # -------------------------------------------------------------------------

    def store_evidence(self, evidence: Evidence) -> StoredEvidence:
        """
        Store a single evidence item directly.

        This is a convenience method for storing individual evidence items
        without creating a full collection run. Useful for testing and
        manual evidence ingestion.

        Args:
            evidence: Evidence item to store.

        Returns:
            StoredEvidence with file path and hash.
        """
        # Create a synthetic collection run for this single item
        run_id = f"direct-{evidence.id}"

        with self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                # Check if run already exists
                cursor = conn.execute(
                    "SELECT id FROM collection_runs WHERE id = ?", (run_id,)
                )
                if cursor.fetchone() is None:
                    # Create a minimal collection run record
                    conn.execute(
                        """
                        INSERT INTO collection_runs (
                            id, platform, timestamp, success, partial,
                            duration_seconds, evidence_count, error_count, errors_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            evidence.platform,
                            evidence.collected_at.isoformat(),
                            1,  # success
                            0,  # not partial
                            0.0,  # duration
                            1,  # evidence_count
                            0,  # error_count
                            None,  # no errors
                        ),
                    )

                # Save the evidence item
                stored_id = self._save_evidence_item(conn, evidence, run_id)
                conn.execute("COMMIT")

                # Get the stored evidence to return
                cursor = conn.execute(
                    "SELECT * FROM evidence_items WHERE id = ?", (stored_id,)
                )
                row = cursor.fetchone()
                return self._row_to_stored_evidence(row)

            except Exception as e:
                conn.execute("ROLLBACK")
                raise StorageError(f"Failed to store evidence: {e}") from e

    def get_storage_statistics(self) -> dict[str, Any]:
        """
        Alias for get_statistics() for backward compatibility.

        Returns:
            Dictionary with storage statistics.
        """
        stats = self.get_statistics()
        # Map to expected test format
        return {
            "total_evidence_count": stats.get("total_evidence", 0),
            "total_size_bytes": (
                stats.get("database_size_bytes", 0) +
                stats.get("evidence_size_bytes", 0)
            ),
            "by_platform": stats.get("evidence_by_platform", {}),
            **stats,
        }

    # -------------------------------------------------------------------------
    # Evidence Query Methods
    # -------------------------------------------------------------------------

    def get_evidence(self, evidence_id: str, verify: bool = True) -> tuple[StoredEvidence, dict[str, Any]]:
        """
        Get a single evidence item with its data.

        Args:
            evidence_id: Evidence item ID.
            verify: Whether to verify file integrity.

        Returns:
            Tuple of (StoredEvidence, raw_data).

        Raises:
            EvidenceNotFoundError: If evidence not found.
            IntegrityError: If integrity check fails.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_items WHERE id = ?", (evidence_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

            stored = StoredEvidence(
                id=row["id"],
                collection_run_id=row["collection_run_id"],
                platform=row["platform"],
                evidence_type=row["evidence_type"],
                collected_at=datetime.fromisoformat(row["collected_at"]),
                file_path=row["file_path"],
                file_hash=row["file_hash"],
                metadata=(
                    json.loads(row["metadata_json"]) if row["metadata_json"] else {}
                ),
                item_count=row["item_count"],
            )

            # Read and optionally verify the file
            expected_hash = stored.file_hash if verify else None
            data = self._read_evidence_file(stored.file_path, expected_hash)

            return stored, data

    def get_evidence_data(self, evidence_id: str) -> dict[str, Any]:
        """
        Get just the raw data for an evidence item.

        Args:
            evidence_id: Evidence item ID.

        Returns:
            Raw evidence data dictionary.

        Raises:
            EvidenceNotFoundError: If evidence not found.
        """
        stored, data = self.get_evidence(evidence_id, verify=False)
        return data

    def verify_integrity(self, evidence_id: str) -> bool:
        """
        Verify the integrity of stored evidence.

        Args:
            evidence_id: Evidence item ID.

        Returns:
            True if integrity is valid, False if tampered.

        Raises:
            EvidenceNotFoundError: If evidence not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT file_path, file_hash FROM evidence_items WHERE id = ?",
                (evidence_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

            file_path = self.data_dir / row["file_path"]
            expected_hash: str = row["file_hash"]

            if not file_path.exists():
                return False

            actual_hash = self._compute_file_hash(file_path)
            return bool(actual_hash == expected_hash)

    def delete_evidence(self, evidence_id: str) -> None:
        """
        Delete a stored evidence item.

        Args:
            evidence_id: Evidence item ID.

        Raises:
            EvidenceNotFoundError: If evidence not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT file_path FROM evidence_items WHERE id = ?",
                (evidence_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

            file_path = self.data_dir / row["file_path"]

            # Delete from database
            conn.execute("DELETE FROM evidence_items WHERE id = ?", (evidence_id,))
            conn.execute(
                "DELETE FROM control_mappings WHERE evidence_id = ?",
                (evidence_id,)
            )

            # Delete file
            if file_path.exists():
                file_path.unlink()

    def get_all_evidence(
        self,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[StoredEvidence]:
        """
        Get all stored evidence items.

        Args:
            limit: Maximum number of results (optional).
            offset: Number of results to skip (optional).

        Returns:
            List of StoredEvidence objects.
        """
        query = "SELECT * FROM evidence_items ORDER BY collected_at DESC"
        params: list[Any] = []

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
            if offset is not None:
                query += " OFFSET ?"
                params.append(offset)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_stored_evidence(row) for row in cursor]

    def get_evidence_by_type(
        self,
        evidence_type: str,
        platform: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int | None = None,
    ) -> list[StoredEvidence]:
        """
        Get evidence items by type.

        Args:
            evidence_type: Type of evidence to retrieve.
            platform: Filter by platform (optional).
            start_date: Filter by collected_at >= start_date (optional).
            end_date: Filter by collected_at <= end_date (optional).
            limit: Maximum number of results (optional).

        Returns:
            List of StoredEvidence objects.
        """
        query = "SELECT * FROM evidence_items WHERE evidence_type = ?"
        params: list[Any] = [evidence_type]

        if platform:
            query += " AND platform = ?"
            params.append(platform)

        if start_date:
            query += " AND collected_at >= ?"
            params.append(start_date.isoformat())

        if end_date:
            query += " AND collected_at <= ?"
            params.append(end_date.isoformat())

        query += " ORDER BY collected_at DESC"

        if limit:
            query += " LIMIT ?"
            params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_stored_evidence(row) for row in cursor]

    def get_evidence_for_control(self, control_id: str) -> list[StoredEvidence]:
        """
        Get all evidence items mapped to a control.

        Args:
            control_id: NIST control ID.

        Returns:
            List of StoredEvidence objects mapped to the control.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT e.* FROM evidence_items e
                JOIN control_mappings m ON e.id = m.evidence_id
                WHERE m.control_id = ?
                ORDER BY e.collected_at DESC
                """,
                (control_id,),
            )
            return [self._row_to_stored_evidence(row) for row in cursor]

    def get_evidence_by_id(self, evidence_id: str) -> StoredEvidence | None:
        """
        Get a specific evidence item by its ID.

        Args:
            evidence_id: Unique evidence ID.

        Returns:
            StoredEvidence if found, None otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidence_items WHERE id = ?",
                (evidence_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_stored_evidence(row)
            return None

    def get_mappings_for_evidence(self, evidence_id: str) -> list[ControlMapping]:
        """
        Get all control mappings for a specific evidence item.

        Args:
            evidence_id: Evidence ID to look up.

        Returns:
            List of ControlMapping objects.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM control_mappings
                WHERE evidence_id = ?
                ORDER BY mapping_confidence DESC
                """,
                (evidence_id,),
            )
            return [
                ControlMapping(
                    id=row["id"],
                    evidence_id=row["evidence_id"],
                    control_id=row["control_id"],
                    mapping_confidence=row["mapping_confidence"],
                    mapping_reason=row["mapping_reason"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
                for row in cursor
            ]

    def get_latest_evidence(
        self,
        platform: str,
        evidence_type: str | None = None,
    ) -> dict[str, StoredEvidence] | StoredEvidence | None:
        """
        Get the most recent evidence for a platform.

        Args:
            platform: Platform identifier.
            evidence_type: If provided, get only this type. Otherwise get all types.

        Returns:
            If evidence_type is provided: StoredEvidence or None.
            If evidence_type is None: Dictionary mapping evidence_type to latest StoredEvidence.
        """
        with self._get_connection() as conn:
            if evidence_type:
                # Get single latest evidence of specific type
                cursor = conn.execute(
                    """
                    SELECT * FROM evidence_items
                    WHERE platform = ? AND evidence_type = ?
                    ORDER BY collected_at DESC
                    LIMIT 1
                    """,
                    (platform, evidence_type),
                )
                row = cursor.fetchone()
                return self._row_to_stored_evidence(row) if row else None
            else:
                # Get latest of each type
                cursor = conn.execute(
                    """
                    SELECT * FROM evidence_items
                    WHERE platform = ?
                    AND collected_at = (
                        SELECT MAX(collected_at) FROM evidence_items e2
                        WHERE e2.platform = evidence_items.platform
                        AND e2.evidence_type = evidence_items.evidence_type
                    )
                    ORDER BY evidence_type
                    """,
                    (platform,),
                )

                result = {}
                for row in cursor:
                    evidence = self._row_to_stored_evidence(row)
                    result[evidence.evidence_type] = evidence
                return result

    def record_collection_run(self, run: CollectionRun) -> str:
        """
        Record a collection run directly (without evidence items).

        This is a convenience method for recording runs without using
        save_collection_run which expects a CollectionResult.

        Args:
            run: CollectionRun to record.

        Returns:
            The run ID.
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO collection_runs (
                    id, platform, timestamp, success, partial,
                    duration_seconds, evidence_count, error_count, errors_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.platform,
                    run.timestamp.isoformat(),
                    1 if run.success else 0,
                    1 if run.partial else 0,
                    run.duration_seconds,
                    run.evidence_count,
                    run.error_count,
                    json.dumps(run.errors) if run.errors else None,
                ),
            )
        return run.id

    def get_collection_runs(
        self,
        platform: str | None = None,
        limit: int = 100,
    ) -> list[CollectionRun]:
        """
        Get collection runs, optionally filtered by platform.

        Args:
            platform: Filter by platform (optional).
            limit: Maximum number of runs to return.

        Returns:
            List of CollectionRun objects, most recent first.
        """
        return self.get_recent_runs(platform=platform, limit=limit)

    def get_last_collection_run(self, platform: str) -> CollectionRun | None:
        """
        Get the most recent collection run for a platform.

        Args:
            platform: Platform identifier.

        Returns:
            Most recent CollectionRun or None if no runs exist.
        """
        runs = self.get_recent_runs(platform=platform, limit=1)
        return runs[0] if runs else None

    def query_evidence(self, query: EvidenceQuery) -> list[StoredEvidence]:
        """
        Query evidence with flexible filters.

        Args:
            query: EvidenceQuery with filter parameters.

        Returns:
            List of matching StoredEvidence objects.
        """
        sql = "SELECT e.* FROM evidence_items e"
        params: list[Any] = []
        conditions = []

        # Join with mappings if filtering by control
        if query.control_id:
            sql += " JOIN control_mappings m ON e.id = m.evidence_id"
            conditions.append("m.control_id = ?")
            params.append(query.control_id)

        if query.platform:
            conditions.append("e.platform = ?")
            params.append(query.platform)

        if query.evidence_type:
            conditions.append("e.evidence_type = ?")
            params.append(query.evidence_type)

        if query.start_date:
            conditions.append("e.collected_at >= ?")
            params.append(query.start_date.isoformat())

        if query.end_date:
            conditions.append("e.collected_at <= ?")
            params.append(query.end_date.isoformat())

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += " ORDER BY e.collected_at DESC"

        if query.limit:
            sql += " LIMIT ?"
            params.append(query.limit)

        if query.offset:
            sql += " OFFSET ?"
            params.append(query.offset)

        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            return [self._row_to_stored_evidence(row) for row in cursor]

    def _row_to_stored_evidence(self, row: sqlite3.Row) -> StoredEvidence:
        """Convert a database row to StoredEvidence."""
        return StoredEvidence(
            id=row["id"],
            collection_run_id=row["collection_run_id"],
            platform=row["platform"],
            evidence_type=row["evidence_type"],
            collected_at=datetime.fromisoformat(row["collected_at"]),
            file_path=row["file_path"],
            file_hash=row["file_hash"],
            metadata=json.loads(row["metadata_json"]) if row["metadata_json"] else {},
            item_count=row["item_count"],
        )

    # -------------------------------------------------------------------------
    # Control Mapping Methods
    # -------------------------------------------------------------------------

    def save_control_mapping(self, mapping: ControlMapping) -> None:
        """
        Save a control mapping.

        Args:
            mapping: ControlMapping to save.
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO control_mappings (
                    id, evidence_id, control_id, mapping_confidence,
                    mapping_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping.id,
                    mapping.evidence_id,
                    mapping.control_id,
                    mapping.mapping_confidence,
                    mapping.mapping_reason,
                    mapping.created_at.isoformat(),
                ),
            )

    def save_control_mappings(self, mappings: list[ControlMapping]) -> None:
        """
        Save multiple control mappings in a transaction.

        Args:
            mappings: List of ControlMapping objects to save.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                for mapping in mappings:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO control_mappings (
                            id, evidence_id, control_id, mapping_confidence,
                            mapping_reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            mapping.id,
                            mapping.evidence_id,
                            mapping.control_id,
                            mapping.mapping_confidence,
                            mapping.mapping_reason,
                            mapping.created_at.isoformat(),
                        ),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def get_mappings_for_control(self, control_id: str) -> list[ControlMapping]:
        """
        Get all mappings for a control.

        Args:
            control_id: NIST control ID.

        Returns:
            List of ControlMapping objects.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM control_mappings
                WHERE control_id = ?
                ORDER BY created_at DESC
                """,
                (control_id,),
            )
            return [
                ControlMapping(
                    id=row["id"],
                    evidence_id=row["evidence_id"],
                    control_id=row["control_id"],
                    mapping_confidence=row["mapping_confidence"],
                    mapping_reason=row["mapping_reason"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
                for row in cursor
            ]

    # -------------------------------------------------------------------------
    # Maturity Snapshot Methods
    # -------------------------------------------------------------------------

    def store_maturity_snapshot(self, snapshot: MaturitySnapshot) -> None:
        """Alias for save_maturity_snapshot for API consistency."""
        return self.save_maturity_snapshot(snapshot)

    def get_maturity_snapshots(
        self,
        function_id: str | None = None,
        category_id: str | None = None,
        subcategory_id: str | None = None,
        limit: int = 100,
    ) -> list[MaturitySnapshot]:
        """
        Get maturity snapshots with optional filters.

        Args:
            function_id: Filter by function (optional).
            category_id: Filter by category (optional).
            subcategory_id: Filter by subcategory (optional).
            limit: Maximum number of snapshots to return.

        Returns:
            List of MaturitySnapshot objects.
        """
        query = "SELECT * FROM maturity_snapshots WHERE 1=1"
        params: list[Any] = []

        if function_id:
            query += " AND function_id = ?"
            params.append(function_id)

        if category_id:
            query += " AND category_id = ?"
            params.append(category_id)

        if subcategory_id:
            query += " AND subcategory_id = ?"
            params.append(subcategory_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [
                MaturitySnapshot(
                    id=row["id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    function_id=row["function_id"],
                    category_id=row["category_id"],
                    subcategory_id=row["subcategory_id"],
                    maturity_level=row["maturity_level"],
                    evidence_count=row["evidence_count"],
                    confidence=row["confidence"],
                    details=(
                        json.loads(row["details_json"]) if row["details_json"] else {}
                    ),
                )
                for row in cursor
            ]

    def save_maturity_snapshot(self, snapshot: MaturitySnapshot) -> None:
        """
        Save a maturity snapshot.

        Maturity snapshots are never deleted, even during cleanup.

        Args:
            snapshot: MaturitySnapshot to save.
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO maturity_snapshots (
                    id, timestamp, function_id, category_id, subcategory_id,
                    maturity_level, evidence_count, confidence, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.id,
                    snapshot.timestamp.isoformat(),
                    snapshot.function_id,
                    snapshot.category_id,
                    snapshot.subcategory_id,
                    snapshot.maturity_level,
                    snapshot.evidence_count,
                    snapshot.confidence,
                    json.dumps(snapshot.details) if snapshot.details else None,
                ),
            )

    def save_maturity_snapshots(self, snapshots: list[MaturitySnapshot]) -> None:
        """
        Save multiple maturity snapshots in a transaction.

        Args:
            snapshots: List of MaturitySnapshot objects to save.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                for snapshot in snapshots:
                    conn.execute(
                        """
                        INSERT INTO maturity_snapshots (
                            id, timestamp, function_id, category_id, subcategory_id,
                            maturity_level, evidence_count, confidence, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            snapshot.id,
                            snapshot.timestamp.isoformat(),
                            snapshot.function_id,
                            snapshot.category_id,
                            snapshot.subcategory_id,
                            snapshot.maturity_level,
                            snapshot.evidence_count,
                            snapshot.confidence,
                            json.dumps(snapshot.details) if snapshot.details else None,
                        ),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def get_maturity_history(
        self,
        control_id: str | None = None,
        function_id: str | None = None,
        category_id: str | None = None,
        days: int = 90,
    ) -> list[MaturitySnapshot]:
        """
        Get maturity history for trend analysis.

        Args:
            control_id: Filter by subcategory ID (e.g., "PR.AC-01").
            function_id: Filter by function ID (e.g., "PR").
            category_id: Filter by category ID (e.g., "PR.AC").
            days: Number of days of history to retrieve.

        Returns:
            List of MaturitySnapshot objects, oldest first.
        """
        start_date = datetime.now(UTC) - timedelta(days=days)

        conditions = ["timestamp >= ?"]
        params: list[Any] = [start_date.isoformat()]

        if control_id:
            conditions.append("subcategory_id = ?")
            params.append(control_id)
        elif category_id:
            conditions.append("category_id = ?")
            params.append(category_id)
        elif function_id:
            conditions.append("function_id = ?")
            conditions.append("category_id IS NULL")
            conditions.append("subcategory_id IS NULL")
            params.append(function_id)

        query = f"""
            SELECT * FROM maturity_snapshots
            WHERE {' AND '.join(conditions)}
            ORDER BY timestamp ASC
        """

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [
                MaturitySnapshot(
                    id=row["id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    function_id=row["function_id"],
                    category_id=row["category_id"],
                    subcategory_id=row["subcategory_id"],
                    maturity_level=row["maturity_level"],
                    evidence_count=row["evidence_count"],
                    confidence=row["confidence"],
                    details=(
                        json.loads(row["details_json"])
                        if row["details_json"]
                        else {}
                    ),
                )
                for row in cursor
            ]

    def get_latest_maturity(
        self,
        function_id: str | None = None,
        category_id: str | None = None,
        subcategory_id: str | None = None,
    ) -> MaturitySnapshot | None:
        """
        Get the most recent maturity snapshot for a control.

        Args:
            function_id: Function ID.
            category_id: Category ID (optional).
            subcategory_id: Subcategory ID (optional).

        Returns:
            Most recent MaturitySnapshot or None.
        """
        conditions = ["function_id = ?"]
        params: list[Any] = [function_id]

        if subcategory_id:
            conditions.append("subcategory_id = ?")
            params.append(subcategory_id)
        elif category_id:
            conditions.append("category_id = ?")
            conditions.append("subcategory_id IS NULL")
            params.append(category_id)
        else:
            conditions.append("category_id IS NULL")
            conditions.append("subcategory_id IS NULL")

        query = f"""
            SELECT * FROM maturity_snapshots
            WHERE {' AND '.join(conditions)}
            ORDER BY timestamp DESC
            LIMIT 1
        """

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            row = cursor.fetchone()
            if row is None:
                return None

            return MaturitySnapshot(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                function_id=row["function_id"],
                category_id=row["category_id"],
                subcategory_id=row["subcategory_id"],
                maturity_level=row["maturity_level"],
                evidence_count=row["evidence_count"],
                confidence=row["confidence"],
                details=(
                    json.loads(row["details_json"]) if row["details_json"] else {}
                ),
            )

    # -------------------------------------------------------------------------
    # Cleanup and Retention Methods
    # -------------------------------------------------------------------------

    def cleanup(
        self,
        retention_days: int = 365,
        archive: bool = True,
    ) -> dict[str, int]:
        """
        Clean up old evidence while preserving maturity snapshots.

        This method:
        1. Identifies evidence older than retention_days
        2. Optionally archives old evidence to compressed files
        3. Deletes old evidence files and database records
        4. NEVER deletes maturity_snapshots (needed for trends)

        Args:
            retention_days: Days of evidence to retain.
            archive: Whether to archive before deleting.

        Returns:
            Dictionary with cleanup statistics.
        """
        cutoff_date = datetime.now(UTC) - timedelta(days=retention_days)
        stats = {
            "evidence_archived": 0,
            "evidence_deleted": 0,
            "runs_deleted": 0,
            "mappings_deleted": 0,
            "files_deleted": 0,
        }

        with self._get_connection() as conn:
            # Get evidence to delete
            cursor = conn.execute(
                """
                SELECT id, file_path FROM evidence_items
                WHERE collected_at < ?
                """,
                (cutoff_date.isoformat(),),
            )
            old_evidence = list(cursor)

            if not old_evidence:
                logger.info("No evidence to clean up")
                return stats

            # Archive if requested
            if archive:
                stats["evidence_archived"] = self._archive_evidence(
                    conn, old_evidence, cutoff_date
                )

            conn.execute("BEGIN TRANSACTION")
            try:
                # Delete control mappings for old evidence
                evidence_ids = [e["id"] for e in old_evidence]
                placeholders = ",".join("?" * len(evidence_ids))
                cursor = conn.execute(
                    f"DELETE FROM control_mappings WHERE evidence_id IN ({placeholders})",
                    evidence_ids,
                )
                stats["mappings_deleted"] = cursor.rowcount

                # Delete evidence items
                cursor = conn.execute(
                    f"DELETE FROM evidence_items WHERE id IN ({placeholders})",
                    evidence_ids,
                )
                stats["evidence_deleted"] = cursor.rowcount

                # Delete orphaned collection runs
                cursor = conn.execute(
                    """
                    DELETE FROM collection_runs
                    WHERE id NOT IN (SELECT DISTINCT collection_run_id FROM evidence_items)
                    AND timestamp < ?
                    """,
                    (cutoff_date.isoformat(),),
                )
                stats["runs_deleted"] = cursor.rowcount

                conn.execute("COMMIT")

                # Delete evidence files
                for evidence in old_evidence:
                    file_path = self.data_dir / evidence["file_path"]
                    if file_path.exists():
                        file_path.unlink()
                        stats["files_deleted"] += 1

                # Clean up empty directories
                self._cleanup_empty_dirs()

                logger.info(
                    f"Cleanup complete: {stats['evidence_deleted']} evidence items, "
                    f"{stats['files_deleted']} files deleted"
                )

            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Cleanup failed: {e}")
                raise StorageError(f"Cleanup failed: {e}") from e

        return stats

    def _archive_evidence(
        self,
        conn: sqlite3.Connection,
        evidence_list: list[sqlite3.Row],
        cutoff_date: datetime,
    ) -> int:
        """
        Archive old evidence to compressed files.

        Args:
            conn: Database connection.
            evidence_list: List of evidence rows to archive.
            cutoff_date: Cutoff date for the archive.

        Returns:
            Number of evidence items archived.
        """
        archive_dir = self.data_dir / "archives"
        archive_dir.mkdir(exist_ok=True)

        archive_name = f"evidence_before_{cutoff_date.strftime('%Y-%m-%d')}.json.gz"
        archive_path = archive_dir / archive_name

        archive_data = []
        for evidence in evidence_list:
            file_path = self.data_dir / evidence["file_path"]
            if file_path.exists():
                try:
                    with open(file_path) as f:
                        raw_data = json.load(f)
                    archive_data.append(
                        {
                            "id": evidence["id"],
                            "file_path": evidence["file_path"],
                            "data": raw_data,
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to read evidence for archive: {e}")

        if archive_data:
            with gzip.open(archive_path, "wt") as f:
                json.dump(archive_data, f)
            logger.info(f"Archived {len(archive_data)} evidence items to {archive_path}")

        return len(archive_data)

    def _cleanup_empty_dirs(self) -> None:
        """Remove empty directories in the evidence folder."""
        for dirpath, dirnames, filenames in os.walk(
            str(self.evidence_dir), topdown=False
        ):
            if not dirnames and not filenames:
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # Statistics Methods
    # -------------------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """
        Get storage statistics.

        Returns:
            Dictionary with storage statistics.
        """
        with self._get_connection() as conn:
            stats: dict[str, Any] = {}

            # Total collection runs
            cursor = conn.execute("SELECT COUNT(*) FROM collection_runs")
            stats["total_runs"] = cursor.fetchone()[0]

            # Total evidence items
            cursor = conn.execute("SELECT COUNT(*) FROM evidence_items")
            stats["total_evidence"] = cursor.fetchone()[0]

            # Total maturity snapshots
            cursor = conn.execute("SELECT COUNT(*) FROM maturity_snapshots")
            stats["total_snapshots"] = cursor.fetchone()[0]

            # Evidence by platform
            cursor = conn.execute(
                """
                SELECT platform, COUNT(*) as count
                FROM evidence_items
                GROUP BY platform
                """
            )
            stats["evidence_by_platform"] = {
                row["platform"]: row["count"] for row in cursor
            }

            # Evidence by type
            cursor = conn.execute(
                """
                SELECT evidence_type, COUNT(*) as count
                FROM evidence_items
                GROUP BY evidence_type
                """
            )
            stats["evidence_by_type"] = {
                row["evidence_type"]: row["count"] for row in cursor
            }

            # Last collection by platform
            cursor = conn.execute(
                """
                SELECT platform, MAX(timestamp) as last_run
                FROM collection_runs
                WHERE success = 1
                GROUP BY platform
                """
            )
            stats["last_collection"] = {
                row["platform"]: row["last_run"] for row in cursor
            }

            # Database size
            stats["database_size_bytes"] = self.db_path.stat().st_size

            # Evidence directory size
            total_size = 0
            for dirpath, _dirnames, filenames in os.walk(str(self.evidence_dir)):
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    total_size += file_path.stat().st_size
            stats["evidence_size_bytes"] = total_size

            return stats

    def get_cleanup_candidates(self, retention_days: int) -> dict[str, Any]:
        """
        Get information about evidence that would be cleaned up.

        This method identifies evidence older than the retention period
        without actually deleting anything. Useful for dry-run previews.

        Args:
            retention_days: Days of evidence to retain.

        Returns:
            Dictionary with cleanup candidates information including:
            - files: List of file info dicts with path, age_days, size
            - file_count: Total number of files
            - total_size_bytes: Total size of files
        """
        cutoff_date = datetime.now(UTC) - timedelta(days=retention_days)
        candidates: dict[str, Any] = {
            "files": [],
            "file_count": 0,
            "total_size_bytes": 0,
        }

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, file_path, collected_at FROM evidence_items
                WHERE collected_at < ?
                ORDER BY collected_at
                """,
                (cutoff_date.isoformat(),),
            )

            for row in cursor:
                file_path = self.data_dir / row["file_path"]
                collected_at = datetime.fromisoformat(row["collected_at"])
                age_days = (datetime.now(UTC) - collected_at).days

                file_info = {
                    "id": row["id"],
                    "path": str(file_path),
                    "relative_path": row["file_path"],
                    "collected_at": collected_at.isoformat(),
                    "age_days": age_days,
                    "size_bytes": 0,
                }

                if file_path.exists():
                    file_info["size_bytes"] = file_path.stat().st_size
                    candidates["total_size_bytes"] += file_info["size_bytes"]

                candidates["files"].append(file_info)
                candidates["file_count"] += 1

        return candidates

    def cleanup_old_evidence(
        self,
        retention_days: int,
        archive: bool = True,
    ) -> dict[str, Any]:
        """
        Clean up old evidence based on retention period.

        This is an alias for the cleanup method with a more intuitive name
        for CLI usage, and returns a result format suitable for display.

        Args:
            retention_days: Days of evidence to retain.
            archive: Whether to archive before deleting.

        Returns:
            Dictionary with cleanup results including:
            - files_removed: Number of files deleted
            - bytes_freed: Total bytes freed
            - database_rows_removed: Number of DB records removed
            - archive_path: Path to archive file (if created)
        """
        # Call the existing cleanup method
        stats = self.cleanup(retention_days=retention_days, archive=archive)

        # Format results for CLI display
        result: dict[str, Any] = {
            "files_removed": stats.get("files_deleted", 0),
            "bytes_freed": 0,  # We don't track this in the existing cleanup
            "database_rows_removed": (
                stats.get("evidence_deleted", 0) +
                stats.get("mappings_deleted", 0) +
                stats.get("runs_deleted", 0)
            ),
        }

        # Check if archive was created
        if archive and stats.get("evidence_archived", 0) > 0:
            archive_dir = self.data_dir / "archives"
            cutoff_date = datetime.now(UTC) - timedelta(days=retention_days)
            archive_name = f"evidence_before_{cutoff_date.strftime('%Y-%m-%d')}.json.gz"
            archive_file = archive_dir / archive_name
            if archive_file.exists():
                result["archive_path"] = str(archive_file)

        return result
