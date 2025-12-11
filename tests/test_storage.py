"""
Tests for the evidence storage engine.

Uses Python's unittest module.
Tests evidence persistence, integrity verification, and retention cleanup.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from nisify.collectors.base import CollectionResult, Evidence
from nisify.storage.evidence_store import (
    EvidenceNotFoundError,
    EvidenceStore,
    IntegrityError,
    StorageError,
)
from nisify.storage.models import (
    CollectionRun,
    EvidenceQuery,
    StoredEvidence,
)


class TestStoredEvidence(unittest.TestCase):
    """Tests for StoredEvidence model."""

    def test_stored_evidence_creation(self) -> None:
        """Test creating a StoredEvidence instance."""
        now = datetime.now(UTC)
        stored = StoredEvidence(
            id="test-id",
            collection_run_id="run-id",
            platform="aws",
            evidence_type="mfa_status",
            collected_at=now,
            file_path="/path/to/file.json",
            file_hash="abc123",
            metadata={"key": "value"},
            item_count=10,
        )

        self.assertEqual(stored.id, "test-id")
        self.assertEqual(stored.platform, "aws")
        self.assertEqual(stored.evidence_type, "mfa_status")
        self.assertEqual(stored.item_count, 10)

    def test_stored_evidence_to_dict(self) -> None:
        """Test converting StoredEvidence to dictionary."""
        now = datetime.now(UTC)
        stored = StoredEvidence(
            id="test-id",
            collection_run_id="run-id",
            platform="aws",
            evidence_type="mfa_status",
            collected_at=now,
            file_path="/path/to/file.json",
            file_hash="abc123",
        )

        result = stored.to_dict()

        self.assertEqual(result["id"], "test-id")
        self.assertEqual(result["platform"], "aws")
        self.assertIn("collected_at", result)


class TestCollectionRun(unittest.TestCase):
    """Tests for CollectionRun model."""

    def test_collection_run_creation(self) -> None:
        """Test creating a CollectionRun instance."""
        now = datetime.now(UTC)
        run = CollectionRun(
            id="run-id",
            platform="aws",
            timestamp=now,
            success=True,
            partial=False,
            duration_seconds=10.5,
            evidence_count=5,
            error_count=0,
            errors=[],
        )

        self.assertEqual(run.id, "run-id")
        self.assertEqual(run.platform, "aws")
        self.assertTrue(run.success)
        self.assertEqual(run.evidence_count, 5)


class TestEvidenceQuery(unittest.TestCase):
    """Tests for EvidenceQuery model."""

    def test_query_defaults(self) -> None:
        """Test EvidenceQuery default values."""
        query = EvidenceQuery()

        self.assertIsNone(query.platform)
        self.assertIsNone(query.evidence_type)
        self.assertIsNone(query.start_date)
        self.assertIsNone(query.end_date)
        self.assertIsNone(query.limit)

    def test_query_with_filters(self) -> None:
        """Test EvidenceQuery with filters."""
        now = datetime.now(UTC)
        query = EvidenceQuery(
            platform="aws",
            evidence_type="mfa_status",
            start_date=now - timedelta(days=7),
            end_date=now,
            limit=100,
        )

        self.assertEqual(query.platform, "aws")
        self.assertEqual(query.evidence_type, "mfa_status")
        self.assertEqual(query.limit, 100)


class TestEvidenceStore(unittest.TestCase):
    """Tests for EvidenceStore class."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_store_initialization(self) -> None:
        """Test that store initializes correctly."""
        self.assertTrue(self.store.db_path.exists())

    def test_store_evidence_basic(self) -> None:
        """Test storing basic evidence."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="mfa_status",
            raw_data={"users": [{"id": 1, "mfa_enabled": True}]},
        )

        stored = self.store.store_evidence(evidence)

        self.assertIsNotNone(stored.id)
        self.assertEqual(stored.platform, "aws")
        self.assertEqual(stored.evidence_type, "mfa_status")

    def test_store_evidence_file_created(self) -> None:
        """Test that evidence file is created."""
        evidence = Evidence.create(
            platform="okta",
            evidence_type="user_inventory",
            raw_data={"users": [{"id": "user1"}]},
        )

        stored = self.store.store_evidence(evidence)

        # file_path is relative to the store's base directory
        full_path = Path(self.temp_dir) / stored.file_path
        self.assertTrue(full_path.exists())

    def test_store_evidence_hash_computed(self) -> None:
        """Test that evidence hash is computed."""
        evidence = Evidence.create(
            platform="jamf",
            evidence_type="device_inventory",
            raw_data={"devices": []},
        )

        stored = self.store.store_evidence(evidence)

        self.assertIsNotNone(stored.file_hash)
        self.assertTrue(len(stored.file_hash) > 0)

    def test_get_evidence_by_id(self) -> None:
        """Test retrieving evidence by ID."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="password_policy",
            raw_data={"policy": {}},
        )

        stored = self.store.store_evidence(evidence)
        retrieved, data = self.store.get_evidence(stored.id)

        self.assertEqual(retrieved.id, stored.id)
        self.assertEqual(retrieved.platform, "aws")
        self.assertIsNotNone(data)

    def test_get_evidence_not_found(self) -> None:
        """Test retrieving non-existent evidence."""
        with self.assertRaises(EvidenceNotFoundError):
            self.store.get_evidence("nonexistent-id")

    def test_query_evidence_by_platform(self) -> None:
        """Test querying evidence by platform."""
        # Store evidence from different platforms
        for platform in ["aws", "aws", "okta"]:
            evidence = Evidence.create(
                platform=platform,
                evidence_type="test_type",
                raw_data={},
            )
            self.store.store_evidence(evidence)

        query = EvidenceQuery(platform="aws")
        results = self.store.query_evidence(query)

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.platform, "aws")

    def test_query_evidence_by_type(self) -> None:
        """Test querying evidence by type."""
        # Store different evidence types
        for evidence_type in ["mfa_status", "mfa_status", "password_policy"]:
            evidence = Evidence.create(
                platform="aws",
                evidence_type=evidence_type,
                raw_data={},
            )
            self.store.store_evidence(evidence)

        query = EvidenceQuery(evidence_type="mfa_status")
        results = self.store.query_evidence(query)

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.evidence_type, "mfa_status")

    def test_query_evidence_by_date_range(self) -> None:
        """Test querying evidence by date range."""
        now = datetime.now(UTC)

        # Store evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data={},
        )
        self.store.store_evidence(evidence)

        query = EvidenceQuery(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
        )
        results = self.store.query_evidence(query)

        self.assertGreaterEqual(len(results), 1)

    def test_query_evidence_with_limit(self) -> None:
        """Test querying evidence with limit."""
        # Store multiple evidence items
        for i in range(10):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="test_type",
                raw_data={"index": i},
            )
            self.store.store_evidence(evidence)

        query = EvidenceQuery(limit=5)
        results = self.store.query_evidence(query)

        self.assertEqual(len(results), 5)

    def test_get_evidence_data(self) -> None:
        """Test retrieving evidence raw data."""
        original_data = {"users": [{"id": 1}, {"id": 2}]}
        evidence = Evidence.create(
            platform="aws",
            evidence_type="user_inventory",
            raw_data=original_data,
        )

        stored = self.store.store_evidence(evidence)
        retrieved_data = self.store.get_evidence_data(stored.id)

        self.assertEqual(retrieved_data, original_data)

    def test_verify_integrity_success(self) -> None:
        """Test integrity verification success."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data={"data": "value"},
        )

        stored = self.store.store_evidence(evidence)
        is_valid = self.store.verify_integrity(stored.id)

        self.assertTrue(is_valid)

    def test_verify_integrity_failure(self) -> None:
        """Test integrity verification failure after tampering."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data={"data": "value"},
        )

        stored = self.store.store_evidence(evidence)

        # Tamper with the file (use full path)
        full_path = Path(self.temp_dir) / stored.file_path
        with open(full_path, "w") as f:
            json.dump({"data": "tampered"}, f)

        is_valid = self.store.verify_integrity(stored.id)

        self.assertFalse(is_valid)

    def test_delete_evidence(self) -> None:
        """Test deleting evidence."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data={},
        )

        stored = self.store.store_evidence(evidence)
        file_path = stored.file_path

        self.store.delete_evidence(stored.id)

        # Should raise not found
        with self.assertRaises(EvidenceNotFoundError):
            self.store.get_evidence(stored.id)

        # File should be deleted
        self.assertFalse(Path(file_path).exists())

    def test_get_latest_evidence(self) -> None:
        """Test getting latest evidence by platform and type."""
        import time

        # Store multiple evidence items
        for i in range(3):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="mfa_status",
                raw_data={"index": i},
            )
            self.store.store_evidence(evidence)
            time.sleep(0.01)  # Ensure different timestamps

        latest = self.store.get_latest_evidence("aws", "mfa_status")

        self.assertIsNotNone(latest)
        self.assertEqual(latest.platform, "aws")
        self.assertEqual(latest.evidence_type, "mfa_status")

    def test_get_latest_evidence_not_found(self) -> None:
        """Test getting latest evidence when none exists."""
        latest = self.store.get_latest_evidence("nonexistent", "type")

        self.assertIsNone(latest)


class TestCollectionRunStorage(unittest.TestCase):
    """Tests for collection run storage."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_record_collection_run(self) -> None:
        """Test recording a collection run."""
        run = CollectionRun(
            id="run-1",
            platform="aws",
            timestamp=datetime.now(UTC),
            success=True,
            partial=False,
            duration_seconds=15.5,
            evidence_count=10,
            error_count=0,
            errors=[],
        )

        self.store.record_collection_run(run)

        # Retrieve and verify
        retrieved = self.store.get_collection_run("run-1")
        self.assertEqual(retrieved.platform, "aws")
        self.assertTrue(retrieved.success)

    def test_get_collection_runs_by_platform(self) -> None:
        """Test getting collection runs by platform."""
        # Record multiple runs
        for i in range(3):
            run = CollectionRun(
                id=f"run-aws-{i}",
                platform="aws",
                timestamp=datetime.now(UTC),
                success=True,
                partial=False,
                duration_seconds=10.0,
                evidence_count=5,
                error_count=0,
            )
            self.store.record_collection_run(run)

        run_okta = CollectionRun(
            id="run-okta-1",
            platform="okta",
            timestamp=datetime.now(UTC),
            success=True,
            partial=False,
            duration_seconds=8.0,
            evidence_count=3,
            error_count=0,
        )
        self.store.record_collection_run(run_okta)

        runs = self.store.get_collection_runs(platform="aws")

        self.assertEqual(len(runs), 3)
        for run in runs:
            self.assertEqual(run.platform, "aws")

    def test_get_last_collection_run(self) -> None:
        """Test getting the most recent collection run."""
        import time

        for i in range(3):
            run = CollectionRun(
                id=f"run-{i}",
                platform="aws",
                timestamp=datetime.now(UTC),
                success=True,
                partial=False,
                duration_seconds=10.0,
                evidence_count=i + 1,
                error_count=0,
            )
            self.store.record_collection_run(run)
            time.sleep(0.01)

        last_run = self.store.get_last_collection_run("aws")

        self.assertIsNotNone(last_run)
        self.assertEqual(last_run.evidence_count, 3)


class TestRetentionCleanup(unittest.TestCase):
    """Tests for retention and cleanup functionality."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cleanup_old_evidence(self) -> None:
        """Test cleaning up evidence older than retention period."""
        # Store evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data={},
        )
        stored = self.store.store_evidence(evidence)

        # Cleanup with very long retention should keep evidence
        cleanup_result = self.store.cleanup_old_evidence(retention_days=365)
        # cleanup_old_evidence returns a dict with stats
        self.assertIsInstance(cleanup_result, dict)
        self.assertEqual(cleanup_result.get("files_removed", 0), 0)

        # Evidence should still exist
        retrieved = self.store.get_evidence(stored.id)
        self.assertIsNotNone(retrieved)

    def test_get_storage_statistics(self) -> None:
        """Test getting storage statistics."""
        # Store some evidence
        for i in range(5):
            evidence = Evidence.create(
                platform="aws" if i < 3 else "okta",
                evidence_type="test_type",
                raw_data={"data": f"value-{i}"},
            )
            self.store.store_evidence(evidence)

        stats = self.store.get_storage_statistics()

        self.assertIn("total_evidence_count", stats)
        self.assertIn("total_size_bytes", stats)
        self.assertIn("by_platform", stats)
        self.assertEqual(stats["total_evidence_count"], 5)


class TestMaturitySnapshots(unittest.TestCase):
    """Tests for maturity snapshot storage."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_store_maturity_snapshot(self) -> None:
        """Test storing a maturity snapshot."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="snapshot-1",
            timestamp=datetime.now(UTC),
            function_id="PR",
            category_id=None,
            subcategory_id=None,
            maturity_level=3,
            evidence_count=50,
            confidence=0.85,
            details={"notes": "test"},
        )

        self.store.store_maturity_snapshot(snapshot)

        # Verify it was stored
        snapshots = self.store.get_maturity_snapshots(function_id="PR")
        self.assertGreaterEqual(len(snapshots), 1)

    def test_maturity_snapshots_never_deleted(self) -> None:
        """Test that maturity snapshots are never deleted."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="snapshot-perm",
            timestamp=datetime.now(UTC),
            function_id="GV",
            category_id=None,
            subcategory_id=None,
            maturity_level=2,
            evidence_count=20,
            confidence=0.75,
        )

        self.store.store_maturity_snapshot(snapshot)

        # Run cleanup - should not affect snapshots
        cleanup_result = self.store.cleanup_old_evidence(retention_days=0)
        # cleanup_old_evidence returns a dict with stats
        self.assertIsInstance(cleanup_result, dict)

        # Snapshot should still exist
        snapshots = self.store.get_maturity_snapshots(function_id="GV")
        self.assertGreaterEqual(len(snapshots), 1)


class TestDatabaseSchema(unittest.TestCase):
    """Tests for database schema initialization."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tables_created(self) -> None:
        """Test that all required tables are created."""
        import sqlite3

        conn = sqlite3.connect(self.store.db_path)
        cursor = conn.cursor()

        # Get list of tables
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}

        conn.close()

        # Verify expected tables exist
        expected_tables = {
            "schema_version",
            "collection_runs",
            "evidence_items",
            "control_mappings",
            "maturity_snapshots",
        }

        for table in expected_tables:
            self.assertIn(table, tables)

    def test_indexes_created(self) -> None:
        """Test that indexes are created."""
        import sqlite3

        conn = sqlite3.connect(self.store.db_path)
        cursor = conn.cursor()

        # Get list of indexes
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )
        indexes = {row[0] for row in cursor.fetchall()}

        conn.close()

        # Should have some indexes
        self.assertGreater(len(indexes), 0)


class TestAtomicWrites(unittest.TestCase):
    """Tests for atomic file operations."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_evidence_file_atomic_write(self) -> None:
        """Test that evidence files are written atomically."""
        large_data = {"items": [{"id": i} for i in range(1000)]}
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test_type",
            raw_data=large_data,
        )

        stored = self.store.store_evidence(evidence)

        # File should exist and be valid (use full path)
        full_path = Path(self.temp_dir) / stored.file_path
        with open(full_path) as f:
            data = json.load(f)

        self.assertEqual(len(data["items"]), 1000)


class TestSaveCollectionRun(unittest.TestCase):
    """Tests for save_collection_run method."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_collection_run_success(self) -> None:
        """Test saving a collection run with evidence items."""
        from nisify.collectors.base import CollectionResult, Evidence

        evidence1 = Evidence.create(
            platform="aws",
            evidence_type="mfa_status",
            raw_data={"users": [{"id": 1, "mfa_enabled": True}]},
        )
        evidence2 = Evidence.create(
            platform="aws",
            evidence_type="password_policy",
            raw_data={"policy": {"min_length": 14}},
        )

        result = CollectionResult(
            platform="aws",
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=[evidence1, evidence2],
            errors=[],
            duration_seconds=5.5,
            partial=False,
        )

        run_id = self.store.save_collection_run(result)

        self.assertIsNotNone(run_id)

        # Verify run was saved
        run = self.store.get_collection_run(run_id)
        self.assertIsNotNone(run)
        self.assertEqual(run.platform, "aws")
        self.assertTrue(run.success)
        self.assertEqual(run.evidence_count, 2)

    def test_save_collection_run_with_errors(self) -> None:
        """Test saving a collection run with errors."""
        from nisify.collectors.base import CollectionResult, Evidence

        evidence = Evidence.create(
            platform="okta",
            evidence_type="user_inventory",
            raw_data={"total_users": 100, "users": []},
        )

        result = CollectionResult(
            platform="okta",
            timestamp=datetime.now(UTC),
            success=False,
            evidence_items=[evidence],
            errors=["Failed to get MFA status", "Rate limit exceeded"],
            duration_seconds=10.2,
            partial=True,
        )

        run_id = self.store.save_collection_run(result)

        run = self.store.get_collection_run(run_id)
        self.assertFalse(run.success)
        self.assertTrue(run.partial)
        self.assertEqual(run.error_count, 2)
        self.assertEqual(len(run.errors), 2)

    def test_save_collection_run_item_count_detection(self) -> None:
        """Test that item counts are detected from different data structures."""
        from nisify.collectors.base import CollectionResult, Evidence

        # Test total_count field
        ev1 = Evidence.create(
            platform="aws",
            evidence_type="test1",
            raw_data={"total_count": 50},
        )
        # Test users list
        ev2 = Evidence.create(
            platform="aws",
            evidence_type="test2",
            raw_data={"users": [{"id": i} for i in range(10)]},
        )
        # Test devices list
        ev3 = Evidence.create(
            platform="aws",
            evidence_type="test3",
            raw_data={"devices": [{"id": i} for i in range(5)]},
        )

        result = CollectionResult(
            platform="aws",
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=[ev1, ev2, ev3],
            errors=[],
            duration_seconds=1.0,
        )

        self.store.save_collection_run(result)

        # Query and verify item counts were stored
        query = EvidenceQuery(platform="aws")
        evidence_list = self.store.query_evidence(query)
        self.assertEqual(len(evidence_list), 3)


class TestControlMappingStorage(unittest.TestCase):
    """Tests for control mapping operations."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_control_mapping(self) -> None:
        """Test saving a single control mapping."""
        from nisify.storage.models import ControlMapping

        # First store some evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="mfa_status",
            raw_data={"users": []},
        )
        stored = self.store.store_evidence(evidence)

        # Create and save mapping
        mapping = ControlMapping.create(
            evidence_id=stored.id,
            control_id="PR.AC-01",
            mapping_confidence=0.9,
            mapping_reason="MFA status provides identity management evidence",
        )
        self.store.save_control_mapping(mapping)

        # Verify mapping was saved
        mappings = self.store.get_mappings_for_control("PR.AC-01")
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].evidence_id, stored.id)
        self.assertEqual(mappings[0].mapping_confidence, 0.9)

    def test_save_control_mappings_batch(self) -> None:
        """Test saving multiple control mappings in batch."""
        from nisify.storage.models import ControlMapping

        # Store evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="audit_logging",
            raw_data={"trails": []},
        )
        stored = self.store.store_evidence(evidence)

        # Create multiple mappings
        mappings = [
            ControlMapping.create(
                evidence_id=stored.id,
                control_id=f"DE.CM-0{i}",
                mapping_confidence=0.8,
                mapping_reason=f"Audit logging evidence for DE.CM-0{i}",
            )
            for i in range(1, 4)
        ]

        self.store.save_control_mappings(mappings)

        # Verify all mappings were saved
        for i in range(1, 4):
            result = self.store.get_mappings_for_control(f"DE.CM-0{i}")
            self.assertEqual(len(result), 1)

    def test_get_evidence_for_control(self) -> None:
        """Test getting evidence mapped to a control."""
        from nisify.storage.models import ControlMapping

        # Store multiple evidence items
        ev1 = Evidence.create(
            platform="aws",
            evidence_type="mfa_status",
            raw_data={},
        )
        ev2 = Evidence.create(
            platform="okta",
            evidence_type="mfa_status",
            raw_data={},
        )
        stored1 = self.store.store_evidence(ev1)
        stored2 = self.store.store_evidence(ev2)

        # Map both to same control
        for stored in [stored1, stored2]:
            mapping = ControlMapping.create(
                evidence_id=stored.id,
                control_id="PR.AC-01",
                mapping_confidence=0.85,
                mapping_reason="MFA evidence",
            )
            self.store.save_control_mapping(mapping)

        # Get evidence for control
        evidence_list = self.store.get_evidence_for_control("PR.AC-01")
        self.assertEqual(len(evidence_list), 2)


class TestQueryEvidenceAdvanced(unittest.TestCase):
    """Advanced tests for query_evidence method."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_query_with_control_id(self) -> None:
        """Test querying evidence by control ID."""
        from nisify.storage.models import ControlMapping

        # Store evidence and create mapping
        evidence = Evidence.create(
            platform="aws",
            evidence_type="encryption_status",
            raw_data={},
        )
        stored = self.store.store_evidence(evidence)

        mapping = ControlMapping.create(
            evidence_id=stored.id,
            control_id="PR.DS-01",
            mapping_confidence=0.95,
            mapping_reason="Encryption evidence",
        )
        self.store.save_control_mapping(mapping)

        # Query by control ID
        query = EvidenceQuery(control_id="PR.DS-01")
        results = self.store.query_evidence(query)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, stored.id)

    def test_query_with_offset(self) -> None:
        """Test querying evidence with offset."""
        # Store multiple evidence items
        for i in range(10):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="test_type",
                raw_data={"index": i},
            )
            self.store.store_evidence(evidence)

        # Query with offset
        query = EvidenceQuery(limit=5, offset=3)
        results = self.store.query_evidence(query)
        self.assertEqual(len(results), 5)


class TestGetAllEvidence(unittest.TestCase):
    """Tests for get_all_evidence method."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_all_evidence_with_limit(self) -> None:
        """Test getting all evidence with limit."""
        for i in range(10):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="test",
                raw_data={"i": i},
            )
            self.store.store_evidence(evidence)

        results = self.store.get_all_evidence(limit=5)
        self.assertEqual(len(results), 5)

    def test_get_all_evidence_with_offset(self) -> None:
        """Test getting all evidence with offset."""
        for i in range(10):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="test",
                raw_data={"i": i},
            )
            self.store.store_evidence(evidence)

        results = self.store.get_all_evidence(limit=5, offset=3)
        self.assertEqual(len(results), 5)


class TestGetEvidenceByType(unittest.TestCase):
    """Tests for get_evidence_by_type method."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_evidence_by_type_with_platform(self) -> None:
        """Test getting evidence by type filtered by platform."""
        # Store evidence from multiple platforms
        for platform in ["aws", "okta"]:
            evidence = Evidence.create(
                platform=platform,
                evidence_type="mfa_status",
                raw_data={},
            )
            self.store.store_evidence(evidence)

        results = self.store.get_evidence_by_type("mfa_status", platform="aws")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].platform, "aws")

    def test_get_evidence_by_type_with_date_range(self) -> None:
        """Test getting evidence by type with date filters."""
        now = datetime.now(UTC)

        evidence = Evidence.create(
            platform="aws",
            evidence_type="audit_logs",
            raw_data={},
        )
        self.store.store_evidence(evidence)

        # Query with date range
        results = self.store.get_evidence_by_type(
            "audit_logs",
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
        )
        self.assertGreaterEqual(len(results), 1)

    def test_get_evidence_by_type_with_limit(self) -> None:
        """Test getting evidence by type with limit."""
        for i in range(5):
            evidence = Evidence.create(
                platform="aws",
                evidence_type="config_snapshot",
                raw_data={"i": i},
            )
            self.store.store_evidence(evidence)

        results = self.store.get_evidence_by_type("config_snapshot", limit=3)
        self.assertEqual(len(results), 3)


class TestGetLatestEvidenceAll(unittest.TestCase):
    """Tests for get_latest_evidence without type filter."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_latest_evidence_all_types(self) -> None:
        """Test getting latest evidence for all types on a platform."""
        import time

        # Store multiple types of evidence
        for evidence_type in ["mfa_status", "password_policy", "audit_logs"]:
            for i in range(2):
                evidence = Evidence.create(
                    platform="aws",
                    evidence_type=evidence_type,
                    raw_data={"version": i},
                )
                self.store.store_evidence(evidence)
                time.sleep(0.01)

        # Get latest of each type
        latest = self.store.get_latest_evidence("aws")

        # Should be a dict mapping type to latest evidence
        self.assertIsInstance(latest, dict)
        self.assertEqual(len(latest), 3)
        self.assertIn("mfa_status", latest)
        self.assertIn("password_policy", latest)
        self.assertIn("audit_logs", latest)


class TestMaturitySnapshotsAdvanced(unittest.TestCase):
    """Advanced tests for maturity snapshot operations."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_maturity_snapshots_batch(self) -> None:
        """Test saving multiple maturity snapshots in batch."""
        from nisify.storage.models import MaturitySnapshot

        snapshots = [
            MaturitySnapshot.create(
                function_id="PR",
                maturity_level=i,
                evidence_count=10 * i,
                confidence=0.8,
                category_id="PR.AC" if i == 1 else None,
            )
            for i in range(1, 4)
        ]

        self.store.save_maturity_snapshots(snapshots)

        # Verify all were saved
        results = self.store.get_maturity_snapshots(function_id="PR")
        self.assertEqual(len(results), 3)

    def test_get_maturity_snapshots_with_category(self) -> None:
        """Test getting snapshots filtered by category."""
        from nisify.storage.models import MaturitySnapshot

        # Store snapshots at different levels
        s1 = MaturitySnapshot.create(
            function_id="PR",
            category_id="PR.AC",
            maturity_level=3,
            evidence_count=50,
            confidence=0.85,
        )
        s2 = MaturitySnapshot.create(
            function_id="PR",
            category_id="PR.DS",
            maturity_level=2,
            evidence_count=30,
            confidence=0.75,
        )

        self.store.save_maturity_snapshot(s1)
        self.store.save_maturity_snapshot(s2)

        # Query by category
        results = self.store.get_maturity_snapshots(
            function_id="PR", category_id="PR.AC"
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].category_id, "PR.AC")

    def test_get_maturity_snapshots_with_subcategory(self) -> None:
        """Test getting snapshots filtered by subcategory."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot.create(
            function_id="PR",
            category_id="PR.AC",
            subcategory_id="PR.AC-01",
            maturity_level=4,
            evidence_count=100,
            confidence=0.95,
        )
        self.store.save_maturity_snapshot(snapshot)

        results = self.store.get_maturity_snapshots(
            function_id="PR", category_id="PR.AC", subcategory_id="PR.AC-01"
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].subcategory_id, "PR.AC-01")

    def test_get_maturity_history(self) -> None:
        """Test getting maturity history for trend analysis."""
        from nisify.storage.models import MaturitySnapshot

        # Store snapshots over time
        for i in range(5):
            snapshot = MaturitySnapshot(
                id=f"snapshot-{i}",
                timestamp=datetime.now(UTC) - timedelta(days=i),
                function_id="DE",
                category_id=None,
                subcategory_id=None,
                maturity_level=i + 1,
                evidence_count=10 * i,
                confidence=0.8,
            )
            self.store.save_maturity_snapshot(snapshot)

        # Get history for last 30 days
        history = self.store.get_maturity_history(function_id="DE", days=30)
        self.assertEqual(len(history), 5)
        # Should be sorted oldest first
        self.assertLess(history[0].timestamp, history[-1].timestamp)

    def test_get_maturity_history_by_category(self) -> None:
        """Test getting maturity history filtered by category."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="cat-snapshot",
            timestamp=datetime.now(UTC),
            function_id="ID",
            category_id="ID.AM",
            subcategory_id=None,
            maturity_level=2,
            evidence_count=25,
            confidence=0.7,
        )
        self.store.save_maturity_snapshot(snapshot)

        history = self.store.get_maturity_history(category_id="ID.AM", days=30)
        self.assertEqual(len(history), 1)

    def test_get_maturity_history_by_control(self) -> None:
        """Test getting maturity history filtered by control (subcategory)."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="ctrl-snapshot",
            timestamp=datetime.now(UTC),
            function_id="RS",
            category_id="RS.CO",
            subcategory_id="RS.CO-01",
            maturity_level=3,
            evidence_count=40,
            confidence=0.85,
        )
        self.store.save_maturity_snapshot(snapshot)

        history = self.store.get_maturity_history(control_id="RS.CO-01", days=30)
        self.assertEqual(len(history), 1)

    def test_get_latest_maturity_function_only(self) -> None:
        """Test getting latest maturity for function level."""
        from nisify.storage.models import MaturitySnapshot

        # Store function-level snapshot (no category/subcategory)
        snapshot = MaturitySnapshot(
            id="func-snapshot",
            timestamp=datetime.now(UTC),
            function_id="GV",
            category_id=None,
            subcategory_id=None,
            maturity_level=2,
            evidence_count=60,
            confidence=0.75,
        )
        self.store.save_maturity_snapshot(snapshot)

        latest = self.store.get_latest_maturity(function_id="GV")
        self.assertIsNotNone(latest)
        self.assertEqual(latest.function_id, "GV")
        self.assertIsNone(latest.category_id)

    def test_get_latest_maturity_with_category(self) -> None:
        """Test getting latest maturity for category level."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="cat-latest",
            timestamp=datetime.now(UTC),
            function_id="ID",
            category_id="ID.RA",
            subcategory_id=None,
            maturity_level=3,
            evidence_count=45,
            confidence=0.8,
        )
        self.store.save_maturity_snapshot(snapshot)

        latest = self.store.get_latest_maturity(function_id="ID", category_id="ID.RA")
        self.assertIsNotNone(latest)
        self.assertEqual(latest.category_id, "ID.RA")
        self.assertIsNone(latest.subcategory_id)

    def test_get_latest_maturity_with_subcategory(self) -> None:
        """Test getting latest maturity for subcategory level."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="sub-latest",
            timestamp=datetime.now(UTC),
            function_id="PR",
            category_id="PR.AC",
            subcategory_id="PR.AC-05",
            maturity_level=4,
            evidence_count=80,
            confidence=0.9,
        )
        self.store.save_maturity_snapshot(snapshot)

        latest = self.store.get_latest_maturity(
            function_id="PR", category_id="PR.AC", subcategory_id="PR.AC-05"
        )
        self.assertIsNotNone(latest)
        self.assertEqual(latest.subcategory_id, "PR.AC-05")

    def test_get_latest_maturity_not_found(self) -> None:
        """Test getting latest maturity when none exists."""
        latest = self.store.get_latest_maturity(function_id="NONEXISTENT")
        self.assertIsNone(latest)


class TestCleanupAdvanced(unittest.TestCase):
    """Advanced tests for cleanup and archival."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cleanup_with_old_evidence(self) -> None:
        """Test cleanup removes old evidence but preserves snapshots."""
        import sqlite3

        from nisify.storage.models import ControlMapping, MaturitySnapshot

        # Store evidence with old timestamp
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test",
            raw_data={"data": "old"},
        )
        stored = self.store.store_evidence(evidence)

        # Create mapping for this evidence
        mapping = ControlMapping.create(
            evidence_id=stored.id,
            control_id="PR.AC-01",
            mapping_confidence=0.9,
            mapping_reason="Test mapping",
        )
        self.store.save_control_mapping(mapping)

        # Create maturity snapshot
        snapshot = MaturitySnapshot.create(
            function_id="PR",
            maturity_level=2,
            evidence_count=10,
            confidence=0.8,
        )
        self.store.save_maturity_snapshot(snapshot)

        # Manually backdate the evidence in the database
        with sqlite3.connect(self.store.db_path) as conn:
            old_date = (datetime.now(UTC) - timedelta(days=400)).isoformat()
            conn.execute(
                "UPDATE evidence_items SET collected_at = ? WHERE id = ?",
                (old_date, stored.id),
            )
            conn.execute(
                "UPDATE collection_runs SET timestamp = ? WHERE id = ?",
                (old_date, f"direct-{stored.id}"),
            )

        # Run cleanup with 365 day retention
        stats = self.store.cleanup(retention_days=365, archive=False)

        self.assertEqual(stats["evidence_deleted"], 1)
        self.assertEqual(stats["mappings_deleted"], 1)

        # Snapshot should still exist
        snapshots = self.store.get_maturity_snapshots(function_id="PR")
        self.assertEqual(len(snapshots), 1)

    def test_cleanup_with_archive(self) -> None:
        """Test cleanup creates archive before deleting."""
        import sqlite3

        # Store evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="archive_test",
            raw_data={"important": "data"},
        )
        stored = self.store.store_evidence(evidence)

        # Backdate the evidence
        with sqlite3.connect(self.store.db_path) as conn:
            old_date = (datetime.now(UTC) - timedelta(days=400)).isoformat()
            conn.execute(
                "UPDATE evidence_items SET collected_at = ? WHERE id = ?",
                (old_date, stored.id),
            )
            conn.execute(
                "UPDATE collection_runs SET timestamp = ? WHERE id = ?",
                (old_date, f"direct-{stored.id}"),
            )

        # Run cleanup with archive
        stats = self.store.cleanup(retention_days=365, archive=True)

        self.assertEqual(stats["evidence_archived"], 1)
        self.assertEqual(stats["evidence_deleted"], 1)

        # Check archive exists
        archive_dir = Path(self.temp_dir) / "archives"
        self.assertTrue(archive_dir.exists())
        archives = list(archive_dir.glob("*.json.gz"))
        self.assertEqual(len(archives), 1)

    def test_get_cleanup_candidates(self) -> None:
        """Test getting cleanup candidates for dry run."""
        import sqlite3

        # Store evidence
        evidence = Evidence.create(
            platform="aws",
            evidence_type="candidate_test",
            raw_data={"data": "value"},
        )
        stored = self.store.store_evidence(evidence)

        # Backdate the evidence
        with sqlite3.connect(self.store.db_path) as conn:
            old_date = (datetime.now(UTC) - timedelta(days=100)).isoformat()
            conn.execute(
                "UPDATE evidence_items SET collected_at = ? WHERE id = ?",
                (old_date, stored.id),
            )

        # Get candidates for 30 day retention
        candidates = self.store.get_cleanup_candidates(retention_days=30)

        self.assertEqual(candidates["file_count"], 1)
        self.assertGreater(candidates["total_size_bytes"], 0)
        self.assertEqual(len(candidates["files"]), 1)
        self.assertGreater(candidates["files"][0]["age_days"], 30)

    def test_cleanup_old_evidence_wrapper(self) -> None:
        """Test cleanup_old_evidence returns expected format."""
        # With no old evidence, should return zeros
        result = self.store.cleanup_old_evidence(retention_days=365, archive=False)

        self.assertEqual(result["files_removed"], 0)
        self.assertEqual(result["database_rows_removed"], 0)
        self.assertNotIn("archive_path", result)


class TestSchemaVersioning(unittest.TestCase):
    """Tests for schema version handling."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_version_initialized(self) -> None:
        """Test that schema version is initialized."""
        import sqlite3

        store = EvidenceStore(Path(self.temp_dir))

        conn = sqlite3.connect(store.db_path)
        cursor = conn.execute(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
        )
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertGreater(row[0], 0)


class TestGetRecentRuns(unittest.TestCase):
    """Tests for get_recent_runs method."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_recent_runs_all_platforms(self) -> None:
        """Test getting recent runs without platform filter."""
        # Record runs for multiple platforms
        for platform in ["aws", "okta", "jamf"]:
            run = CollectionRun(
                id=f"run-{platform}",
                platform=platform,
                timestamp=datetime.now(UTC),
                success=True,
                partial=False,
                duration_seconds=10.0,
                evidence_count=5,
                error_count=0,
            )
            self.store.record_collection_run(run)

        runs = self.store.get_recent_runs(limit=10)
        self.assertEqual(len(runs), 3)

    def test_get_recent_runs_with_errors(self) -> None:
        """Test that runs with errors are properly returned."""
        run = CollectionRun(
            id="run-with-errors",
            platform="aws",
            timestamp=datetime.now(UTC),
            success=False,
            partial=True,
            duration_seconds=15.0,
            evidence_count=2,
            error_count=3,
            errors=["Error 1", "Error 2", "Error 3"],
        )
        self.store.record_collection_run(run)

        runs = self.store.get_recent_runs(platform="aws")
        self.assertEqual(len(runs), 1)
        self.assertEqual(len(runs[0].errors), 3)


class TestIntegrityAndErrors(unittest.TestCase):
    """Tests for integrity checks and error handling."""

    def setUp(self) -> None:
        """Set up test fixtures with temp directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = EvidenceStore(Path(self.temp_dir))

    def tearDown(self) -> None:
        """Clean up temp directory."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verify_integrity_missing_file(self) -> None:
        """Test integrity check when file is missing."""
        evidence = Evidence.create(
            platform="aws",
            evidence_type="test",
            raw_data={"data": "value"},
        )
        stored = self.store.store_evidence(evidence)

        # Delete the file
        full_path = Path(self.temp_dir) / stored.file_path
        full_path.unlink()

        # Verify should return False
        is_valid = self.store.verify_integrity(stored.id)
        self.assertFalse(is_valid)

    def test_delete_nonexistent_evidence(self) -> None:
        """Test deleting non-existent evidence raises error."""
        with self.assertRaises(EvidenceNotFoundError):
            self.store.delete_evidence("nonexistent-id")


class TestModelSerialization(unittest.TestCase):
    """Tests for model to_dict and from_dict methods."""

    def test_collection_run_to_dict(self) -> None:
        """Test CollectionRun to_dict method."""
        run = CollectionRun(
            id="run-123",
            platform="aws",
            timestamp=datetime.now(UTC),
            success=True,
            partial=False,
            duration_seconds=15.5,
            evidence_count=10,
            error_count=0,
            errors=[],
        )

        data = run.to_dict()

        self.assertEqual(data["id"], "run-123")
        self.assertEqual(data["platform"], "aws")
        self.assertTrue(data["success"])
        self.assertFalse(data["partial"])
        self.assertEqual(data["duration_seconds"], 15.5)
        self.assertEqual(data["evidence_count"], 10)

    def test_collection_run_from_dict(self) -> None:
        """Test CollectionRun from_dict method."""
        timestamp = datetime.now(UTC)
        data = {
            "id": "run-456",
            "platform": "okta",
            "timestamp": timestamp.isoformat(),
            "success": False,
            "partial": True,
            "duration_seconds": 20.0,
            "evidence_count": 5,
            "error_count": 2,
            "errors": ["Error 1", "Error 2"],
        }

        run = CollectionRun.from_dict(data)

        self.assertEqual(run.id, "run-456")
        self.assertEqual(run.platform, "okta")
        self.assertFalse(run.success)
        self.assertTrue(run.partial)
        self.assertEqual(len(run.errors), 2)

    def test_stored_evidence_from_dict(self) -> None:
        """Test StoredEvidence from_dict method."""
        collected_at = datetime.now(UTC)
        data = {
            "id": "ev-123",
            "collection_run_id": "run-123",
            "platform": "aws",
            "evidence_type": "mfa_status",
            "collected_at": collected_at.isoformat(),
            "file_path": "evidence/aws/2024-01-01/mfa_status.json",
            "file_hash": "abc123",
            "metadata": {"key": "value"},
            "item_count": 50,
        }

        evidence = StoredEvidence.from_dict(data)

        self.assertEqual(evidence.id, "ev-123")
        self.assertEqual(evidence.platform, "aws")
        self.assertEqual(evidence.evidence_type, "mfa_status")
        self.assertEqual(evidence.metadata, {"key": "value"})
        self.assertEqual(evidence.item_count, 50)

    def test_control_mapping_to_dict(self) -> None:
        """Test ControlMapping to_dict method."""
        from nisify.storage.models import ControlMapping

        mapping = ControlMapping(
            id="map-123",
            evidence_id="ev-123",
            control_id="PR.AC-01",
            mapping_confidence=0.9,
            mapping_reason="Test reason",
            created_at=datetime.now(UTC),
        )

        data = mapping.to_dict()

        self.assertEqual(data["id"], "map-123")
        self.assertEqual(data["evidence_id"], "ev-123")
        self.assertEqual(data["control_id"], "PR.AC-01")
        self.assertEqual(data["mapping_confidence"], 0.9)
        self.assertEqual(data["mapping_reason"], "Test reason")
        self.assertIn("created_at", data)

    def test_control_mapping_from_dict(self) -> None:
        """Test ControlMapping from_dict method."""
        from nisify.storage.models import ControlMapping

        created_at = datetime.now(UTC)
        data = {
            "id": "map-456",
            "evidence_id": "ev-456",
            "control_id": "DE.CM-01",
            "mapping_confidence": 0.85,
            "mapping_reason": "Audit logging evidence",
            "created_at": created_at.isoformat(),
        }

        mapping = ControlMapping.from_dict(data)

        self.assertEqual(mapping.id, "map-456")
        self.assertEqual(mapping.evidence_id, "ev-456")
        self.assertEqual(mapping.control_id, "DE.CM-01")
        self.assertEqual(mapping.mapping_confidence, 0.85)

    def test_maturity_snapshot_to_dict(self) -> None:
        """Test MaturitySnapshot to_dict method."""
        from nisify.storage.models import MaturitySnapshot

        snapshot = MaturitySnapshot(
            id="snap-123",
            timestamp=datetime.now(UTC),
            function_id="PR",
            category_id="PR.AC",
            subcategory_id="PR.AC-01",
            maturity_level=3,
            evidence_count=50,
            confidence=0.85,
            details={"notes": "Test details"},
        )

        data = snapshot.to_dict()

        self.assertEqual(data["id"], "snap-123")
        self.assertEqual(data["function_id"], "PR")
        self.assertEqual(data["category_id"], "PR.AC")
        self.assertEqual(data["subcategory_id"], "PR.AC-01")
        self.assertEqual(data["maturity_level"], 3)
        self.assertEqual(data["evidence_count"], 50)
        self.assertEqual(data["confidence"], 0.85)
        self.assertEqual(data["details"], {"notes": "Test details"})

    def test_maturity_snapshot_from_dict(self) -> None:
        """Test MaturitySnapshot from_dict method."""
        from nisify.storage.models import MaturitySnapshot

        timestamp = datetime.now(UTC)
        data = {
            "id": "snap-456",
            "timestamp": timestamp.isoformat(),
            "function_id": "ID",
            "category_id": "ID.AM",
            "subcategory_id": None,
            "maturity_level": 2,
            "evidence_count": 30,
            "confidence": 0.75,
            "details": {"assessment": "partial"},
        }

        snapshot = MaturitySnapshot.from_dict(data)

        self.assertEqual(snapshot.id, "snap-456")
        self.assertEqual(snapshot.function_id, "ID")
        self.assertEqual(snapshot.category_id, "ID.AM")
        self.assertIsNone(snapshot.subcategory_id)
        self.assertEqual(snapshot.maturity_level, 2)
        self.assertEqual(snapshot.details, {"assessment": "partial"})


class TestEvidenceStoreEdgeCases(unittest.TestCase):
    """Test edge cases and error paths in EvidenceStore."""

    def test_init_with_none_data_dir(self) -> None:
        """Test initialization with None data_dir uses default path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Patch Path.home() to use our temp directory
            with patch("nisify.storage.evidence_store.Path.home") as mock_home:
                mock_home.return_value = Path(tmp_dir)
                store = EvidenceStore(data_dir=None)

                # Should use ~/.nisify/data as default
                expected_path = Path(tmp_dir) / ".nisify" / "data"
                self.assertEqual(store.data_dir, expected_path)
                self.assertTrue(store.data_dir.exists())

    def test_init_with_string_data_dir(self) -> None:
        """Test initialization with string data_dir converts to Path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            string_path = os.path.join(tmp_dir, "test_data")
            store = EvidenceStore(data_dir=string_path)

            # Should convert string to Path
            self.assertIsInstance(store.data_dir, Path)
            self.assertEqual(store.data_dir, Path(string_path))
            self.assertTrue(store.data_dir.exists())

    def test_schema_version_migration_warning(self) -> None:
        """Test warning when database schema is older than expected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir) / "data"
            data_dir.mkdir(parents=True)
            db_path = data_dir / "nisify.db"

            # Create database with old schema version
            conn = sqlite3.connect(str(db_path))
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                INSERT INTO schema_version (version, applied_at) VALUES (0, '2024-01-01');
            """)
            conn.close()

            # Now initialize store - should log warning about old version
            with patch("nisify.storage.evidence_store.logger") as mock_logger:
                store = EvidenceStore(data_dir=data_dir)
                # Check that warning was logged about old schema version
                mock_logger.warning.assert_called()
                call_args = str(mock_logger.warning.call_args)
                self.assertIn("schema version", call_args.lower())

    def test_atomic_write_cleanup_on_error(self) -> None:
        """Test that temp file is cleaned up on write error."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            # Create a mock that raises an exception during os.rename
            # But only for file renames, not directory operations
            with patch("nisify.storage.evidence_store.os.rename") as mock_rename:
                mock_rename.side_effect = PermissionError("Cannot rename file")

                # Save evidence to get a result
                result = CollectionResult(
                    platform="test",
                    timestamp=datetime.now(UTC),
                    success=True,
                    evidence_items=[evidence],
                    errors=[],
                    duration_seconds=1.0,
                )

                # The error should propagate up
                with self.assertRaises((PermissionError, StorageError)):
                    store.save_collection_run(result)

    def test_read_evidence_file_not_found(self) -> None:
        """Test EvidenceNotFoundError when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # Try to read non-existent file
            with self.assertRaises(EvidenceNotFoundError) as ctx:
                store._read_evidence_file("nonexistent/file.json", None)

            self.assertIn("Evidence file not found", str(ctx.exception))

    def test_read_evidence_file_integrity_error(self) -> None:
        """Test IntegrityError when hash doesn't match."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # Create a test evidence file
            test_file = store.data_dir / "test_evidence.json"
            test_file.write_text('{"test": "data"}')

            # Try to read with wrong hash
            with self.assertRaises(IntegrityError) as ctx:
                store._read_evidence_file("test_evidence.json", "wrong_hash")

            self.assertIn("integrity check failed", str(ctx.exception))

    def test_save_collection_run_rollback_on_error(self) -> None:
        """Test that collection run save rolls back on error."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            result = CollectionResult(
                platform="test",
                timestamp=datetime.now(UTC),
                success=True,
                evidence_items=[evidence],
                errors=[],
                duration_seconds=1.0,
            )

            # Mock _save_evidence_item to raise an exception
            with patch.object(store, "_save_evidence_item") as mock_save:
                mock_save.side_effect = Exception("Database error")

                with self.assertRaises(StorageError) as ctx:
                    store.save_collection_run(result)

                self.assertIn("Failed to save collection run", str(ctx.exception))

    def test_get_collection_run_not_found(self) -> None:
        """Test get_collection_run returns None for non-existent run."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            result = store.get_collection_run("nonexistent-run-id")
            self.assertIsNone(result)

    def test_store_evidence_rollback_on_error(self) -> None:
        """Test that store_evidence rolls back on error."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            # Mock _write_evidence_file to raise an exception
            with patch.object(store, "_write_evidence_file") as mock_write:
                mock_write.side_effect = Exception("Write error")

                with self.assertRaises(StorageError) as ctx:
                    store.store_evidence(evidence)

                self.assertIn("Failed to store evidence", str(ctx.exception))

    def test_verify_integrity_evidence_not_found(self) -> None:
        """Test verify_integrity raises error for non-existent evidence."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            with self.assertRaises(EvidenceNotFoundError) as ctx:
                store.verify_integrity("nonexistent-evidence-id")

            self.assertIn("Evidence not found", str(ctx.exception))

    def test_save_control_mappings_rollback_on_error(self) -> None:
        """Test save_control_mappings rolls back on error (lines 1142-1144)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            from nisify.storage.models import ControlMapping

            mappings = [
                ControlMapping(
                    id="map-1",
                    evidence_id="ev-1",
                    control_id="PR.AC-01",
                    mapping_confidence=0.9,
                    mapping_reason="Test",
                    created_at=datetime.now(UTC),
                )
            ]

            # Create a wrapper class that intercepts execute calls
            class ConnectionWrapper:
                def __init__(self, conn: sqlite3.Connection):
                    self._conn = conn
                    self.rollback_called = False

                def execute(self, sql: str, params=None):
                    if "ROLLBACK" in sql.upper():
                        self.rollback_called = True
                        return self._conn.execute(sql)
                    if "INSERT INTO control_mappings" in sql:
                        raise Exception("Database error")
                    if params:
                        return self._conn.execute(sql, params)
                    return self._conn.execute(sql)

                def close(self):
                    self._conn.close()

                def __getattr__(self, name):
                    return getattr(self._conn, name)

            wrapper = [None]
            original_get_connection = store._get_connection

            @contextmanager
            def mock_connection():
                with original_get_connection() as conn:
                    wrapper[0] = ConnectionWrapper(conn)
                    try:
                        yield wrapper[0]
                    finally:
                        pass  # Connection closed by original context manager

            with patch.object(store, "_get_connection", mock_connection):
                with self.assertRaises(Exception):
                    store.save_control_mappings(mappings)

            # Verify ROLLBACK was called (lines 1142-1144 executed)
            self.assertTrue(wrapper[0].rollback_called, "ROLLBACK should have been called")

    def test_save_maturity_snapshots_rollback_on_error(self) -> None:
        """Test save_maturity_snapshots rolls back on error (lines 1302-1304)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            from nisify.storage.models import MaturitySnapshot

            snapshots = [
                MaturitySnapshot(
                    id="snap-1",
                    timestamp=datetime.now(UTC),
                    function_id="PR",
                    category_id="PR.AC",
                    subcategory_id="PR.AC-01",
                    maturity_level=3,
                    evidence_count=10,
                    confidence=0.9,
                    details={},
                )
            ]

            # Create a wrapper class that intercepts execute calls
            class ConnectionWrapper:
                def __init__(self, conn: sqlite3.Connection):
                    self._conn = conn
                    self.rollback_called = False

                def execute(self, sql: str, params=None):
                    if "ROLLBACK" in sql.upper():
                        self.rollback_called = True
                        return self._conn.execute(sql)
                    if "INSERT INTO maturity_snapshots" in sql:
                        raise Exception("Database error")
                    if params:
                        return self._conn.execute(sql, params)
                    return self._conn.execute(sql)

                def close(self):
                    self._conn.close()

                def __getattr__(self, name):
                    return getattr(self._conn, name)

            wrapper = [None]
            original_get_connection = store._get_connection

            @contextmanager
            def mock_connection():
                with original_get_connection() as conn:
                    wrapper[0] = ConnectionWrapper(conn)
                    try:
                        yield wrapper[0]
                    finally:
                        pass  # Connection closed by original context manager

            with patch.object(store, "_get_connection", mock_connection):
                with self.assertRaises(Exception):
                    store.save_maturity_snapshots(snapshots)

            # Verify ROLLBACK was called (lines 1302-1304 executed)
            self.assertTrue(wrapper[0].rollback_called, "ROLLBACK should have been called")

    def test_cleanup_failure_handling(self) -> None:
        """Test cleanup rolls back and raises StorageError on failure (lines 1528-1531)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # First save some evidence
            old_time = datetime.now(UTC) - timedelta(days=100)
            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            result = CollectionResult(
                platform="test",
                timestamp=old_time,
                success=True,
                evidence_items=[evidence],
                errors=[],
                duration_seconds=1.0,
            )

            store.save_collection_run(result)

            # Manually update the collected_at in the database to be old
            with store._get_connection() as conn:
                conn.execute(
                    "UPDATE evidence_items SET collected_at = ?",
                    (old_time.isoformat(),)
                )
                conn.commit()

            # Create a wrapper class that intercepts execute calls
            class ConnectionWrapper:
                def __init__(self, conn: sqlite3.Connection):
                    self._conn = conn
                    self.rollback_called = False

                def execute(self, sql: str, params=None):
                    if "ROLLBACK" in sql.upper():
                        self.rollback_called = True
                        return self._conn.execute(sql)
                    # Fail on DELETE to trigger the except block
                    if "DELETE FROM control_mappings" in sql:
                        raise Exception("Database error during cleanup")
                    if params:
                        return self._conn.execute(sql, params)
                    return self._conn.execute(sql)

                def close(self):
                    self._conn.close()

                def __getattr__(self, name):
                    return getattr(self._conn, name)

            wrapper = [None]
            original_get_connection = store._get_connection

            @contextmanager
            def mock_connection():
                with original_get_connection() as conn:
                    wrapper[0] = ConnectionWrapper(conn)
                    try:
                        yield wrapper[0]
                    finally:
                        pass  # Connection closed by original context manager

            with patch.object(store, "_get_connection", mock_connection):
                with self.assertRaises(StorageError) as ctx:
                    store.cleanup(retention_days=30, archive=False)

                self.assertIn("Cleanup failed", str(ctx.exception))

            # Verify ROLLBACK was called (lines 1528-1531 executed)
            self.assertTrue(wrapper[0].rollback_called, "ROLLBACK should have been called")

    def test_cleanup_no_old_evidence(self) -> None:
        """Test that cleanup handles case when no old evidence exists."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")
            result = store.cleanup(retention_days=30, archive=False)
            # Should return empty stats when no old evidence
            self.assertEqual(result.get("evidence_deleted", 0), 0)

    def test_archive_read_failure_warning(self) -> None:
        """Test that failed evidence reads during archive log warning (lines 1572-1573)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # Save old evidence
            old_time = datetime.now(UTC) - timedelta(days=100)
            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            result = CollectionResult(
                platform="test",
                timestamp=old_time,
                success=True,
                evidence_items=[evidence],
                errors=[],
                duration_seconds=1.0,
            )

            store.save_collection_run(result)

            # Manually update the timestamp in the database to be old
            with store._get_connection() as conn:
                conn.execute(
                    "UPDATE evidence_items SET collected_at = ?",
                    (old_time.isoformat(),)
                )
                conn.execute(
                    "UPDATE collection_runs SET timestamp = ?",
                    (old_time.isoformat(),)
                )
                conn.commit()

            # Corrupt the evidence file with invalid JSON to trigger read failure
            # The file must EXIST but fail to be read/parsed
            for f in store.evidence_dir.rglob("*.json"):
                f.write_text("{ invalid json }")

            with patch("nisify.storage.evidence_store.logger") as mock_logger:
                store.cleanup(retention_days=30, archive=True)
                # Check that warning was logged about failed archive read
                warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
                # At least one warning should mention "Failed to read evidence for archive"
                has_archive_warning = any("failed to read" in w.lower() for w in warning_calls)
                self.assertTrue(has_archive_warning, f"Expected archive read warning but got: {warning_calls}")

    def test_cleanup_empty_dirs_oserror(self) -> None:
        """Test cleanup_empty_dirs handles OSError gracefully."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # Create empty subdirectory
            empty_dir = store.evidence_dir / "empty_subdir"
            empty_dir.mkdir(parents=True)

            # Mock os.rmdir to raise OSError
            with patch("os.rmdir") as mock_rmdir:
                mock_rmdir.side_effect = OSError("Cannot remove directory")

                # Should not raise, just silently skip
                store._cleanup_empty_dirs()

    def test_cleanup_old_evidence_returns_archive_path(self) -> None:
        """Test cleanup_old_evidence returns archive_path when archive is created."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = EvidenceStore(data_dir=Path(tmp_dir) / "data")

            # Save old evidence
            old_time = datetime.now(UTC) - timedelta(days=100)
            evidence = Evidence.create(
                platform="test",
                evidence_type="test_type",
                raw_data={"key": "value"},
            )

            result = CollectionResult(
                platform="test",
                timestamp=old_time,
                success=True,
                evidence_items=[evidence],
                errors=[],
                duration_seconds=1.0,
            )

            store.save_collection_run(result)

            # Manually update the timestamp in the database to be old
            with store._get_connection() as conn:
                conn.execute(
                    "UPDATE evidence_items SET collected_at = ?",
                    (old_time.isoformat(),)
                )
                conn.execute(
                    "UPDATE collection_runs SET timestamp = ?",
                    (old_time.isoformat(),)
                )
                conn.commit()

            # Verify evidence exists before cleanup
            with store._get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM evidence_items")
                count = cursor.fetchone()[0]
                self.assertGreater(count, 0, "Should have evidence before cleanup")

            # Run cleanup_old_evidence with archive (this method adds archive_path)
            cleanup_result = store.cleanup_old_evidence(retention_days=30, archive=True)

            # Should have the CLI-formatted result keys
            self.assertIn("files_removed", cleanup_result)
            self.assertIn("database_rows_removed", cleanup_result)

            # If archive file was created, should have archive_path
            archive_dir = store.data_dir / "archives"
            if archive_dir.exists() and list(archive_dir.glob("*.json.gz")):
                self.assertIn("archive_path", cleanup_result)


if __name__ == "__main__":
    unittest.main()
