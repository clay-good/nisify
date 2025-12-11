"""
Tests for the backup and restore functionality.

Tests cover:
- BackupManager backup creation
- BackupManager restore operations
- Manifest generation and verification
- Checksum validation
- Error handling
"""

import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nisify.backup import (
    BackupError,
    BackupManager,
    BackupManifest,
    BackupResult,
    RestoreError,
    RestoreResult,
)


class TestBackupManifest(unittest.TestCase):
    """Tests for BackupManifest dataclass."""

    def test_to_dict(self):
        """Test manifest serialization to dictionary."""
        manifest = BackupManifest(
            version="0.1.0",
            created_at="2024-01-15T10:30:00",
            organization="Test Org",
            includes_credentials=True,
            files=[{"path": "data/nisify.db", "hash": "abc123", "size": 1000}],
            database_info={"tables": {"evidence_items": 50}},
            evidence_stats={"total": 50, "by_platform": {"aws": 30, "okta": 20}},
        )

        data = manifest.to_dict()

        self.assertEqual(data["version"], "0.1.0")
        self.assertEqual(data["created_at"], "2024-01-15T10:30:00")
        self.assertEqual(data["organization"], "Test Org")
        self.assertTrue(data["includes_credentials"])
        self.assertEqual(len(data["files"]), 1)
        self.assertEqual(data["evidence_stats"]["total"], 50)

    def test_from_dict(self):
        """Test manifest creation from dictionary."""
        data = {
            "version": "0.1.0",
            "created_at": "2024-01-15T10:30:00",
            "organization": "Test Org",
            "includes_credentials": False,
            "files": [{"path": "config/config.yaml", "hash": "def456", "size": 500}],
            "database_info": {},
            "evidence_stats": {"total": 0},
        }

        manifest = BackupManifest.from_dict(data)

        self.assertEqual(manifest.version, "0.1.0")
        self.assertEqual(manifest.organization, "Test Org")
        self.assertFalse(manifest.includes_credentials)
        self.assertEqual(len(manifest.files), 1)

    def test_from_dict_missing_fields(self):
        """Test manifest creation handles missing fields gracefully."""
        data = {"version": "0.1.0"}

        manifest = BackupManifest.from_dict(data)

        self.assertEqual(manifest.version, "0.1.0")
        self.assertEqual(manifest.created_at, "")
        self.assertIsNone(manifest.organization)
        self.assertFalse(manifest.includes_credentials)
        self.assertEqual(manifest.files, [])


class TestBackupResult(unittest.TestCase):
    """Tests for BackupResult dataclass."""

    def test_success_result(self):
        """Test successful backup result."""
        result = BackupResult(
            success=True,
            path=Path("/tmp/backup.tar.gz"),
            size_bytes=10000,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.path, Path("/tmp/backup.tar.gz"))
        self.assertEqual(result.size_bytes, 10000)
        self.assertIsNone(result.error)

    def test_failure_result(self):
        """Test failed backup result."""
        result = BackupResult(
            success=False,
            error="No files to backup",
        )

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertEqual(result.error, "No files to backup")


class TestRestoreResult(unittest.TestCase):
    """Tests for RestoreResult dataclass."""

    def test_success_result(self):
        """Test successful restore result."""
        result = RestoreResult(
            success=True,
            files_restored=25,
            evidence_count=20,
            backup_created=Path("/tmp/pre-backup.tar.gz"),
        )

        self.assertTrue(result.success)
        self.assertEqual(result.files_restored, 25)
        self.assertEqual(result.evidence_count, 20)
        self.assertIsNotNone(result.backup_created)

    def test_failure_result(self):
        """Test failed restore result."""
        result = RestoreResult(
            success=False,
            error="Checksum mismatch",
        )

        self.assertFalse(result.success)
        self.assertEqual(result.error, "Checksum mismatch")


class TestBackupManager(unittest.TestCase):
    """Tests for BackupManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.data_dir = Path(self.temp_dir) / "data"
        self.output_dir = Path(self.temp_dir) / "output"

        self.config_dir.mkdir(parents=True)
        self.data_dir.mkdir(parents=True)
        self.output_dir.mkdir(parents=True)

        # Create manager
        self.manager = BackupManager(self.config_dir, self.data_dir)

    def tearDown(self):
        """Clean up temporary directories."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_test_database(self):
        """Create a test SQLite database."""
        db_path = self.data_dir / "nisify.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version TEXT,
                applied_at TEXT
            )
        """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_items (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                evidence_type TEXT
            )
        """
        )
        cursor.execute("INSERT INTO schema_version VALUES ('1.0', '2024-01-15')")
        cursor.execute("INSERT INTO evidence_items VALUES (1, 'aws', 'mfa_status')")
        cursor.execute("INSERT INTO evidence_items VALUES (2, 'okta', 'user_inventory')")

        conn.commit()
        conn.close()

        return db_path

    def _create_test_evidence(self):
        """Create test evidence files."""
        evidence_dir = self.data_dir / "evidence" / "aws" / "2024-01-15"
        evidence_dir.mkdir(parents=True)

        # Create evidence files
        evidence1 = evidence_dir / "mfa_status_001.json"
        evidence1.write_text(json.dumps({"type": "mfa_status", "data": []}))

        evidence2 = evidence_dir / "audit_logging_002.json"
        evidence2.write_text(json.dumps({"type": "audit_logging", "data": []}))

        return [evidence1, evidence2]

    def _create_test_config(self):
        """Create a test config file."""
        config_path = self.config_dir / "config.yaml"
        config_path.write_text("organization: Test Org\nlog_level: INFO\n")
        return config_path

    def _create_test_credentials(self):
        """Create test credential files."""
        creds_path = self.config_dir / "credentials.enc"
        creds_path.write_bytes(b"encrypted-credentials-data")

        salt_path = self.config_dir / "salt"
        salt_path.write_bytes(os.urandom(32))

        return creds_path, salt_path

    def test_create_backup_empty(self):
        """Test backup with no files returns error."""
        result = self.manager.create_backup(self.output_dir)

        self.assertFalse(result.success)
        self.assertIn("No files to backup", result.error)

    def test_create_backup_basic(self):
        """Test basic backup creation."""
        self._create_test_database()
        self._create_test_evidence()
        self._create_test_config()

        result = self.manager.create_backup(self.output_dir)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.path)
        self.assertTrue(result.path.exists())
        self.assertTrue(result.path.name.startswith("nisify-backup-"))
        self.assertTrue(result.path.name.endswith(".tar.gz"))
        self.assertGreater(result.size_bytes, 0)

    def test_create_backup_with_credentials(self):
        """Test backup including credentials."""
        self._create_test_database()
        self._create_test_config()
        self._create_test_credentials()

        result = self.manager.create_backup(
            self.output_dir,
            include_credentials=True,
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.manifest)
        self.assertTrue(result.manifest.includes_credentials)

        # Verify credentials are in the archive
        with tarfile.open(result.path, "r:gz") as tar:
            names = tar.getnames()
            self.assertIn("credentials/credentials.enc", names)
            self.assertIn("credentials/salt", names)

    def test_create_backup_without_credentials(self):
        """Test backup excluding credentials."""
        self._create_test_database()
        self._create_test_config()
        self._create_test_credentials()

        result = self.manager.create_backup(
            self.output_dir,
            include_credentials=False,
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.manifest)
        self.assertFalse(result.manifest.includes_credentials)

        # Verify credentials are NOT in the archive
        with tarfile.open(result.path, "r:gz") as tar:
            names = tar.getnames()
            self.assertNotIn("credentials/credentials.enc", names)
            self.assertNotIn("credentials/salt", names)

    def test_backup_manifest_checksums(self):
        """Test that manifest contains valid checksums."""
        self._create_test_database()
        self._create_test_config()

        result = self.manager.create_backup(self.output_dir)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.manifest)

        # Each file should have a hash
        for file_info in result.manifest.files:
            self.assertIn("hash", file_info)
            self.assertEqual(len(file_info["hash"]), 64)  # SHA-256 hex

    def test_backup_manifest_database_info(self):
        """Test that manifest contains database info."""
        self._create_test_database()

        result = self.manager.create_backup(self.output_dir)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.manifest)

        db_info = result.manifest.database_info
        self.assertIn("tables", db_info)
        self.assertIn("evidence_items", db_info["tables"])
        self.assertEqual(db_info["tables"]["evidence_items"], 2)

    def test_backup_manifest_evidence_stats(self):
        """Test that manifest contains evidence statistics."""
        self._create_test_database()
        self._create_test_evidence()

        result = self.manager.create_backup(self.output_dir)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.manifest)

        stats = result.manifest.evidence_stats
        self.assertEqual(stats["total"], 2)
        self.assertIn("aws", stats["by_platform"])
        self.assertEqual(stats["by_platform"]["aws"], 2)

    def test_verify_backup_valid(self):
        """Test verification of a valid backup."""
        self._create_test_database()
        self._create_test_config()

        result = self.manager.create_backup(self.output_dir)
        self.assertTrue(result.success)

        valid, errors = self.manager.verify_backup(result.path)

        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

    def test_verify_backup_nonexistent(self):
        """Test verification of nonexistent file."""
        valid, errors = self.manager.verify_backup(Path("/nonexistent/backup.tar.gz"))

        self.assertFalse(valid)
        self.assertIn("not found", errors[0].lower())

    def test_verify_backup_corrupted(self):
        """Test verification detects corruption."""
        self._create_test_database()
        self._create_test_config()

        result = self.manager.create_backup(self.output_dir)
        self.assertTrue(result.success)

        # Corrupt the archive by modifying a file
        # Read the archive, modify it, write back
        with open(result.path, "r+b") as f:
            content = f.read()
            # Corrupt some bytes in the middle
            mid = len(content) // 2
            corrupted = content[:mid] + b"CORRUPTED" + content[mid + 9 :]
            f.seek(0)
            f.write(corrupted)
            f.truncate()

        valid, errors = self.manager.verify_backup(result.path)

        # Should fail verification (either not a valid tar or checksum mismatch)
        self.assertFalse(valid)

    def test_restore_basic(self):
        """Test basic restore operation."""
        # Create backup
        self._create_test_database()
        self._create_test_config()
        evidence_files = self._create_test_evidence()

        backup_result = self.manager.create_backup(self.output_dir)
        self.assertTrue(backup_result.success)

        # Create a new empty target
        new_config_dir = Path(self.temp_dir) / "new_config"
        new_data_dir = Path(self.temp_dir) / "new_data"
        new_config_dir.mkdir()
        new_data_dir.mkdir()

        new_manager = BackupManager(new_config_dir, new_data_dir)

        # Restore
        restore_result = new_manager.restore_backup(
            backup_result.path,
            backup_existing=False,
        )

        self.assertTrue(restore_result.success)
        self.assertGreater(restore_result.files_restored, 0)
        self.assertEqual(restore_result.evidence_count, 2)

        # Verify files were restored
        self.assertTrue((new_data_dir / "nisify.db").exists())
        self.assertTrue((new_config_dir / "config.yaml").exists())

    def test_restore_creates_pre_backup(self):
        """Test that restore creates pre-backup of existing data."""
        # Create initial data
        self._create_test_database()
        self._create_test_config()

        # Create backup
        backup_result = self.manager.create_backup(self.output_dir)
        self.assertTrue(backup_result.success)

        # Restore to same location (should create pre-backup)
        restore_result = self.manager.restore_backup(
            backup_result.path,
            backup_existing=True,
        )

        self.assertTrue(restore_result.success)
        self.assertIsNotNone(restore_result.backup_created)
        self.assertTrue(restore_result.backup_created.exists())

    def test_restore_verify_only(self):
        """Test restore with verify-only flag."""
        self._create_test_database()
        self._create_test_config()

        backup_result = self.manager.create_backup(self.output_dir)
        self.assertTrue(backup_result.success)

        # Create new target
        new_config_dir = Path(self.temp_dir) / "verify_only_config"
        new_data_dir = Path(self.temp_dir) / "verify_only_data"
        new_config_dir.mkdir()
        new_data_dir.mkdir()

        new_manager = BackupManager(new_config_dir, new_data_dir)

        # Verify only
        restore_result = new_manager.restore_backup(
            backup_result.path,
            verify_only=True,
        )

        self.assertTrue(restore_result.success)
        self.assertEqual(restore_result.files_restored, 0)

        # Files should NOT be restored
        self.assertFalse((new_data_dir / "nisify.db").exists())

    def test_restore_nonexistent_backup(self):
        """Test restore with nonexistent backup file."""
        restore_result = self.manager.restore_backup(
            Path("/nonexistent/backup.tar.gz")
        )

        self.assertFalse(restore_result.success)
        self.assertIn("not found", restore_result.error.lower())

    def test_get_backup_info(self):
        """Test getting backup info without extracting."""
        self._create_test_database()
        self._create_test_config()

        backup_result = self.manager.create_backup(self.output_dir)
        self.assertTrue(backup_result.success)

        manifest = self.manager.get_backup_info(backup_result.path)

        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.version, backup_result.manifest.version)
        self.assertGreater(len(manifest.files), 0)

    def test_get_backup_info_invalid(self):
        """Test getting info from invalid file."""
        invalid_path = self.output_dir / "not_a_backup.txt"
        invalid_path.write_text("not a backup")

        manifest = self.manager.get_backup_info(invalid_path)

        self.assertIsNone(manifest)

    def test_backup_output_is_file(self):
        """Test backup fails when output path is a file."""
        self._create_test_database()

        file_path = self.output_dir / "file.txt"
        file_path.write_text("content")

        result = self.manager.create_backup(file_path)

        self.assertFalse(result.success)
        self.assertIn("file", result.error.lower())

    def test_backup_creates_output_dir(self):
        """Test backup creates output directory if it doesn't exist."""
        self._create_test_database()

        new_output = self.output_dir / "nested" / "path"

        result = self.manager.create_backup(new_output)

        self.assertTrue(result.success)
        self.assertTrue(new_output.exists())


class TestBackupIntegration(unittest.TestCase):
    """Integration tests for backup/restore cycle."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directories."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_backup_restore_cycle(self):
        """Test complete backup and restore cycle."""
        # Setup original data
        config_dir = Path(self.temp_dir) / "original" / "config"
        data_dir = Path(self.temp_dir) / "original" / "data"
        config_dir.mkdir(parents=True)
        data_dir.mkdir(parents=True)

        # Create config
        config_path = config_dir / "config.yaml"
        config_path.write_text("organization: Original\n")

        # Create database
        db_path = data_dir / "nisify.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER, value TEXT)")
        cursor.execute("INSERT INTO test VALUES (1, 'original_value')")
        conn.commit()
        conn.close()

        # Create backup
        manager = BackupManager(config_dir, data_dir)
        backup_result = manager.create_backup(Path(self.temp_dir) / "backups")

        self.assertTrue(backup_result.success)

        # Setup new location
        new_config_dir = Path(self.temp_dir) / "restored" / "config"
        new_data_dir = Path(self.temp_dir) / "restored" / "data"
        new_config_dir.mkdir(parents=True)
        new_data_dir.mkdir(parents=True)

        # Restore
        new_manager = BackupManager(new_config_dir, new_data_dir)
        restore_result = new_manager.restore_backup(
            backup_result.path,
            backup_existing=False,
        )

        self.assertTrue(restore_result.success)

        # Verify restored config
        restored_config = new_config_dir / "config.yaml"
        self.assertTrue(restored_config.exists())
        self.assertEqual(restored_config.read_text(), "organization: Original\n")

        # Verify restored database
        restored_db = new_data_dir / "nisify.db"
        self.assertTrue(restored_db.exists())

        conn = sqlite3.connect(restored_db)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM test WHERE id = 1")
        value = cursor.fetchone()[0]
        conn.close()

        self.assertEqual(value, "original_value")


if __name__ == "__main__":
    unittest.main()
