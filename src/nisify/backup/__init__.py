"""
Backup and restore functionality for Nisify.

This module provides tools to create portable backup archives of Nisify data
and restore from those backups. Backups include the SQLite database, evidence
files, and optionally encrypted credentials.

Usage:
    from nisify.backup import BackupManager

    # Create a backup
    manager = BackupManager(config_dir, data_dir)
    result = manager.create_backup(output_path)

    # Restore from backup
    result = manager.restore_backup(backup_path)

    # Verify backup integrity
    valid, errors = manager.verify_backup(backup_path)
"""

from nisify.backup.manager import (
    BackupError,
    BackupManager,
    BackupManifest,
    BackupResult,
    RestoreError,
    RestoreResult,
)

__all__ = [
    "BackupManager",
    "BackupManifest",
    "BackupResult",
    "RestoreResult",
    "BackupError",
    "RestoreError",
]
