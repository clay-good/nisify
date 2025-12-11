"""
Backup and restore manager for Nisify.

Provides functionality to create portable backup archives and restore from them.
Backups are stored as tar.gz archives with SHA-256 checksums for integrity
verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BackupError(Exception):
    """Error during backup operation."""

    pass


class RestoreError(Exception):
    """Error during restore operation."""

    pass


@dataclass
class BackupManifest:
    """Manifest containing backup metadata and checksums."""

    version: str
    created_at: str
    organization: str | None
    includes_credentials: bool
    files: list[dict[str, Any]]
    database_info: dict[str, Any]
    evidence_stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupManifest:
        """Create manifest from dictionary."""
        return cls(
            version=data.get("version", "unknown"),
            created_at=data.get("created_at", ""),
            organization=data.get("organization"),
            includes_credentials=data.get("includes_credentials", False),
            files=data.get("files", []),
            database_info=data.get("database_info", {}),
            evidence_stats=data.get("evidence_stats", {}),
        )


@dataclass
class BackupResult:
    """Result of a backup operation."""

    success: bool
    path: Path | None = None
    manifest: BackupManifest | None = None
    size_bytes: int = 0
    error: str | None = None


@dataclass
class RestoreResult:
    """Result of a restore operation."""

    success: bool
    files_restored: int = 0
    evidence_count: int = 0
    backup_created: Path | None = None
    error: str | None = None


class BackupManager:
    """
    Manages backup and restore operations for Nisify data.

    Creates portable tar.gz archives containing:
    - SQLite database
    - Evidence JSON files
    - Configuration file
    - Optionally: encrypted credentials

    All files include SHA-256 checksums in a manifest for integrity verification.
    """

    # Files and directories to backup
    DATABASE_FILE = "nisify.db"
    EVIDENCE_DIR = "evidence"
    CONFIG_FILE = "config.yaml"
    CREDENTIALS_FILE = "credentials.enc"
    SALT_FILE = "salt"
    MANIFEST_FILE = "manifest.json"

    def __init__(self, config_dir: Path, data_dir: Path) -> None:
        """
        Initialize backup manager.

        Args:
            config_dir: Path to Nisify configuration directory (~/.nisify)
            data_dir: Path to Nisify data directory (~/.nisify/data)
        """
        self.config_dir = Path(config_dir)
        self.data_dir = Path(data_dir)

    def create_backup(
        self,
        output_path: Path | None = None,
        include_credentials: bool = False,
    ) -> BackupResult:
        """
        Create a backup archive of Nisify data.

        Args:
            output_path: Directory to save backup (default: current directory)
            include_credentials: Whether to include encrypted credentials

        Returns:
            BackupResult with success status and backup details
        """
        try:
            # Determine output location
            if output_path is None:
                output_path = Path.cwd()
            output_path = Path(output_path)

            if output_path.is_file():
                return BackupResult(
                    success=False,
                    error=f"Output path is a file: {output_path}",
                )

            output_path.mkdir(parents=True, exist_ok=True)

            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_name = f"nisify-backup-{timestamp}.tar.gz"
            backup_path = output_path / backup_name

            # Collect files to backup
            files_to_backup: list[dict[str, Any]] = []

            # Database file
            db_path = self.data_dir / self.DATABASE_FILE
            if db_path.exists():
                files_to_backup.append(
                    {
                        "source": db_path,
                        "archive_path": f"data/{self.DATABASE_FILE}",
                        "type": "database",
                    }
                )

            # Evidence directory
            evidence_dir = self.data_dir / self.EVIDENCE_DIR
            if evidence_dir.exists():
                for evidence_file in evidence_dir.rglob("*.json"):
                    rel_path = evidence_file.relative_to(self.data_dir)
                    files_to_backup.append(
                        {
                            "source": evidence_file,
                            "archive_path": f"data/{rel_path}",
                            "type": "evidence",
                        }
                    )

            # Config file
            config_path = self.config_dir / self.CONFIG_FILE
            if config_path.exists():
                files_to_backup.append(
                    {
                        "source": config_path,
                        "archive_path": f"config/{self.CONFIG_FILE}",
                        "type": "config",
                    }
                )

            # Credentials (optional)
            if include_credentials:
                creds_path = self.config_dir / self.CREDENTIALS_FILE
                salt_path = self.config_dir / self.SALT_FILE
                if creds_path.exists():
                    files_to_backup.append(
                        {
                            "source": creds_path,
                            "archive_path": f"credentials/{self.CREDENTIALS_FILE}",
                            "type": "credentials",
                        }
                    )
                if salt_path.exists():
                    files_to_backup.append(
                        {
                            "source": salt_path,
                            "archive_path": f"credentials/{self.SALT_FILE}",
                            "type": "credentials",
                        }
                    )

            if not files_to_backup:
                return BackupResult(
                    success=False,
                    error="No files to backup. Is Nisify initialized?",
                )

            # Compute checksums and build manifest
            manifest_files = []
            for file_info in files_to_backup:
                source = file_info["source"]
                checksum = self._compute_file_checksum(source)
                manifest_files.append(
                    {
                        "path": file_info["archive_path"],
                        "hash": checksum,
                        "size": source.stat().st_size,
                        "type": file_info["type"],
                    }
                )

            # Get database info
            database_info = self._get_database_info()

            # Get evidence stats
            evidence_stats = self._get_evidence_stats(files_to_backup)

            # Create manifest
            manifest = BackupManifest(
                version=self._get_version(),
                created_at=datetime.now().isoformat(),
                organization=self._get_organization(),
                includes_credentials=include_credentials,
                files=manifest_files,
                database_info=database_info,
                evidence_stats=evidence_stats,
            )

            # Create archive
            with tarfile.open(backup_path, "w:gz") as tar:
                # Add all files
                for file_info in files_to_backup:
                    tar.add(
                        file_info["source"],
                        arcname=file_info["archive_path"],
                    )

                # Add manifest
                manifest_data = json.dumps(manifest.to_dict(), indent=2)
                manifest_bytes = manifest_data.encode("utf-8")

                import io

                manifest_file = io.BytesIO(manifest_bytes)
                tarinfo = tarfile.TarInfo(name=self.MANIFEST_FILE)
                tarinfo.size = len(manifest_bytes)
                tarinfo.mtime = int(datetime.now().timestamp())
                tar.addfile(tarinfo, manifest_file)

            # Get final size
            size_bytes = backup_path.stat().st_size

            logger.info(f"Backup created: {backup_path} ({size_bytes:,} bytes)")

            return BackupResult(
                success=True,
                path=backup_path,
                manifest=manifest,
                size_bytes=size_bytes,
            )

        except Exception as e:
            logger.exception("Backup failed")
            return BackupResult(success=False, error=str(e))

    def restore_backup(
        self,
        backup_path: Path,
        backup_existing: bool = True,
        verify_only: bool = False,
    ) -> RestoreResult:
        """
        Restore from a backup archive.

        Args:
            backup_path: Path to backup archive
            backup_existing: Create backup of existing data before restore
            verify_only: Only verify integrity, don't restore

        Returns:
            RestoreResult with success status and restore details
        """
        try:
            backup_path = Path(backup_path)

            if not backup_path.exists():
                return RestoreResult(
                    success=False,
                    error=f"Backup file not found: {backup_path}",
                )

            # Verify backup first
            valid, errors = self.verify_backup(backup_path)
            if not valid:
                return RestoreResult(
                    success=False,
                    error=f"Backup verification failed: {'; '.join(errors)}",
                )

            if verify_only:
                return RestoreResult(success=True, files_restored=0)

            # Create pre-restore backup if requested
            pre_backup_path = None
            if backup_existing and self._has_existing_data():
                pre_result = self.create_backup(
                    output_path=self.config_dir / "backups",
                    include_credentials=True,
                )
                if pre_result.success:
                    pre_backup_path = pre_result.path
                    logger.info(f"Pre-restore backup created: {pre_backup_path}")

            # Extract to temp directory first
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Extract archive
                with tarfile.open(backup_path, "r:gz") as tar:
                    tar.extractall(temp_path, filter="data")

                # Read manifest
                manifest_path = temp_path / self.MANIFEST_FILE
                with open(manifest_path) as f:
                    manifest_data = json.load(f)
                manifest = BackupManifest.from_dict(manifest_data)

                # Restore files
                files_restored = 0
                evidence_count = 0

                for file_info in manifest.files:
                    source = temp_path / file_info["path"]
                    if not source.exists():
                        continue

                    # Determine destination
                    if file_info["path"].startswith("data/"):
                        rel_path = file_info["path"][5:]  # Remove "data/" prefix
                        dest = self.data_dir / rel_path
                    elif file_info["path"].startswith("config/"):
                        rel_path = file_info["path"][7:]  # Remove "config/" prefix
                        dest = self.config_dir / rel_path
                    elif file_info["path"].startswith("credentials/"):
                        rel_path = file_info["path"][12:]  # Remove "credentials/" prefix
                        dest = self.config_dir / rel_path
                    else:
                        continue

                    # Create parent directory
                    dest.parent.mkdir(parents=True, exist_ok=True)

                    # Copy file
                    shutil.copy2(source, dest)
                    files_restored += 1

                    if file_info.get("type") == "evidence":
                        evidence_count += 1

                logger.info(
                    f"Restore completed: {files_restored} files, "
                    f"{evidence_count} evidence items"
                )

                return RestoreResult(
                    success=True,
                    files_restored=files_restored,
                    evidence_count=evidence_count,
                    backup_created=pre_backup_path,
                )

        except Exception as e:
            logger.exception("Restore failed")
            return RestoreResult(success=False, error=str(e))

    def verify_backup(self, backup_path: Path) -> tuple[bool, list[str]]:
        """
        Verify backup archive integrity.

        Args:
            backup_path: Path to backup archive

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors: list[str] = []
        backup_path = Path(backup_path)

        try:
            if not backup_path.exists():
                return False, [f"Backup file not found: {backup_path}"]

            if not tarfile.is_tarfile(backup_path):
                return False, [f"Not a valid tar archive: {backup_path}"]

            with tarfile.open(backup_path, "r:gz") as tar:
                # Check for manifest
                try:
                    manifest_member = tar.getmember(self.MANIFEST_FILE)
                except KeyError:
                    return False, ["Manifest file not found in archive"]

                # Extract and read manifest
                manifest_file = tar.extractfile(manifest_member)
                if manifest_file is None:
                    return False, ["Could not read manifest file"]

                manifest_data = json.load(manifest_file)
                manifest = BackupManifest.from_dict(manifest_data)

                # Verify each file's checksum
                for file_info in manifest.files:
                    file_path = file_info["path"]
                    expected_hash = file_info["hash"]

                    try:
                        member = tar.getmember(file_path)
                        file_obj = tar.extractfile(member)
                        if file_obj is None:
                            errors.append(f"Could not read file: {file_path}")
                            continue

                        # Compute hash
                        hasher = hashlib.sha256()
                        while chunk := file_obj.read(8192):
                            hasher.update(chunk)
                        actual_hash = hasher.hexdigest()

                        if actual_hash != expected_hash:
                            errors.append(
                                f"Checksum mismatch for {file_path}: "
                                f"expected {expected_hash[:16]}..., "
                                f"got {actual_hash[:16]}..."
                            )

                    except KeyError:
                        errors.append(f"File not found in archive: {file_path}")

            if errors:
                return False, errors

            return True, []

        except Exception as e:
            return False, [f"Verification error: {str(e)}"]

    def get_backup_info(self, backup_path: Path) -> BackupManifest | None:
        """
        Get information about a backup without extracting it.

        Args:
            backup_path: Path to backup archive

        Returns:
            BackupManifest or None if unable to read
        """
        try:
            with tarfile.open(backup_path, "r:gz") as tar:
                manifest_file = tar.extractfile(self.MANIFEST_FILE)
                if manifest_file is None:
                    return None
                manifest_data = json.load(manifest_file)
                return BackupManifest.from_dict(manifest_data)
        except Exception:
            return None

    def _compute_file_checksum(self, path: Path) -> str:
        """Compute SHA-256 checksum of a file."""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _get_database_info(self) -> dict[str, Any]:
        """Get information about the database."""
        db_path = self.data_dir / self.DATABASE_FILE
        if not db_path.exists():
            return {}

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get table counts
            tables = {}
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            for (table_name,) in cursor.fetchall():
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")  # noqa: S608
                (count,) = cursor.fetchone()
                tables[table_name] = count

            # Get schema version
            schema_version = None
            try:
                cursor.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    schema_version = row[0]
            except sqlite3.OperationalError:
                pass

            conn.close()

            return {
                "tables": tables,
                "schema_version": schema_version,
            }

        except Exception as e:
            logger.warning(f"Could not get database info: {e}")
            return {}

    def _get_evidence_stats(self, files: list[dict[str, Any]]) -> dict[str, Any]:
        """Get statistics about evidence files."""
        total = 0
        by_platform: dict[str, int] = {}

        for file_info in files:
            if file_info.get("type") != "evidence":
                continue
            total += 1

            # Extract platform from path
            # Format: data/evidence/{platform}/{date}/{filename}.json
            path = file_info.get("archive_path", "")
            parts = path.split("/")
            if len(parts) >= 3:
                platform = parts[2]
                by_platform[platform] = by_platform.get(platform, 0) + 1

        return {
            "total": total,
            "by_platform": by_platform,
        }

    def _get_version(self) -> str:
        """Get Nisify version."""
        try:
            from nisify import __version__

            return __version__
        except ImportError:
            return "unknown"

    def _get_organization(self) -> str | None:
        """Get organization name from config."""
        config_path = self.config_dir / self.CONFIG_FILE
        if not config_path.exists():
            return None

        try:
            import yaml

            with open(config_path) as f:
                config = yaml.safe_load(f)
            return config.get("organization")
        except Exception:
            return None

    def _has_existing_data(self) -> bool:
        """Check if there is existing data to backup."""
        db_path = self.data_dir / self.DATABASE_FILE
        evidence_dir = self.data_dir / self.EVIDENCE_DIR
        return db_path.exists() or (evidence_dir.exists() and any(evidence_dir.iterdir()))
