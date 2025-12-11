"""
Scheduler for automated evidence collection.

Provides both system cron integration (Unix-like systems) and a built-in
scheduler using threading for cross-platform support.

The scheduler manages automated execution of evidence collection at
configurable intervals: hourly, daily, or weekly.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from nisify.config.settings import DEFAULT_CONFIG_DIR

logger = logging.getLogger(__name__)


# Scheduler data directory
SCHEDULER_DIR = DEFAULT_CONFIG_DIR / "scheduler"
STATE_FILE = SCHEDULER_DIR / "state.json"
PID_FILE = SCHEDULER_DIR / "scheduler.pid"
LOG_FILE = DEFAULT_CONFIG_DIR / "logs" / "scheduler.log"

# Maximum log file size before rotation (5 MB)
MAX_LOG_SIZE = 5 * 1024 * 1024
# Number of backup log files to keep
LOG_BACKUP_COUNT = 3


class ScheduleInterval(Enum):
    """Supported schedule intervals."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"

    @property
    def seconds(self) -> int:
        """Get interval duration in seconds."""
        if self == ScheduleInterval.HOURLY:
            return 3600
        elif self == ScheduleInterval.DAILY:
            return 86400
        elif self == ScheduleInterval.WEEKLY:
            return 604800
        return 86400

    @property
    def cron_schedule(self) -> str:
        """
        Get cron schedule expression for this interval.

        Returns standard cron format: minute hour day month weekday
        """
        if self == ScheduleInterval.HOURLY:
            return "0 * * * *"  # Every hour at minute 0
        elif self == ScheduleInterval.DAILY:
            return "0 2 * * *"  # Daily at 2:00 AM
        elif self == ScheduleInterval.WEEKLY:
            return "0 2 * * 0"  # Weekly on Sunday at 2:00 AM
        return "0 2 * * *"

    @classmethod
    def from_string(cls, value: str) -> ScheduleInterval:
        """Parse interval from string."""
        value = value.lower().strip()
        for interval in cls:
            if interval.value == value:
                return interval
        raise ValueError(f"Invalid interval: {value}. Must be hourly, daily, or weekly.")


class SchedulerMode(Enum):
    """Scheduler implementation modes."""

    SYSTEM_CRON = "system_cron"
    BUILT_IN = "built_in"


@dataclass
class ScheduleStatus:
    """
    Current status of the scheduler.

    Attributes:
        enabled: Whether scheduling is currently active.
        interval: The configured collection interval.
        mode: The scheduler implementation being used.
        next_run: Datetime of the next scheduled collection.
        last_run: Datetime of the last completed collection.
        last_run_success: Whether the last collection succeeded.
        last_run_error: Error message from last failed run, if any.
        pid: Process ID of the built-in scheduler daemon, if running.
    """

    enabled: bool = False
    interval: str = "daily"
    mode: str = "built_in"
    next_run: datetime | None = None
    last_run: datetime | None = None
    last_run_success: bool | None = None
    last_run_error: str | None = None
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert status to dictionary."""
        return {
            "enabled": self.enabled,
            "interval": self.interval,
            "mode": self.mode,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_run_success": self.last_run_success,
            "last_run_error": self.last_run_error,
            "pid": self.pid,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScheduleStatus:
        """Create status from dictionary."""
        return cls(
            enabled=data.get("enabled", False),
            interval=data.get("interval", "daily"),
            mode=data.get("mode", "built_in"),
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            last_run_success=data.get("last_run_success"),
            last_run_error=data.get("last_run_error"),
            pid=data.get("pid"),
        )


@dataclass
class CollectionRun:
    """Record of a single collection run."""

    started_at: datetime
    completed_at: datetime | None = None
    success: bool = False
    error: str | None = None
    evidence_count: int = 0
    platforms_collected: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert run to dictionary."""
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error": self.error,
            "evidence_count": self.evidence_count,
            "platforms_collected": self.platforms_collected,
        }


class SchedulerError(Exception):
    """Base exception for scheduler errors."""

    pass


class CronNotAvailableError(SchedulerError):
    """Raised when system cron is not available."""

    pass


class SchedulerAlreadyRunningError(SchedulerError):
    """Raised when the scheduler is already running."""

    pass


class SchedulerNotRunningError(SchedulerError):
    """Raised when the scheduler is not running but expected to be."""

    pass


class Scheduler:
    """
    Manages automated evidence collection scheduling.

    Supports two modes:
    - System cron integration (Unix-like systems)
    - Built-in scheduler using threading (cross-platform)

    The scheduler persists state to disk so it survives restarts.

    Usage:
        scheduler = Scheduler()

        # Install a schedule
        scheduler.install_schedule(ScheduleInterval.DAILY, mode=SchedulerMode.BUILT_IN)

        # Check status
        status = scheduler.get_schedule_status()

        # Uninstall
        scheduler.uninstall_schedule()
    """

    def __init__(self, config_dir: Path | None = None) -> None:
        """
        Initialize the scheduler.

        Args:
            config_dir: Base configuration directory. Defaults to ~/.nisify
        """
        self._config_dir = config_dir or DEFAULT_CONFIG_DIR
        self._scheduler_dir = self._config_dir / "scheduler"
        self._state_file = self._scheduler_dir / "state.json"
        self._pid_file = self._scheduler_dir / "scheduler.pid"
        self._log_file = self._config_dir / "logs" / "scheduler.log"

        # Built-in scheduler state
        self._scheduler_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._collection_callback: Callable[[], CollectionRun] | None = None

        # Ensure directories exist
        self._scheduler_dir.mkdir(parents=True, exist_ok=True)
        (self._config_dir / "logs").mkdir(parents=True, exist_ok=True)

    def install_schedule(
        self,
        interval: ScheduleInterval | str,
        mode: SchedulerMode | str | None = None,
    ) -> ScheduleStatus:
        """
        Install a collection schedule.

        Args:
            interval: Collection interval (hourly, daily, weekly).
            mode: Scheduler mode. If None, auto-detects best option.

        Returns:
            Current schedule status after installation.

        Raises:
            SchedulerError: If schedule cannot be installed.
        """
        # Parse interval
        if isinstance(interval, str):
            interval = ScheduleInterval.from_string(interval)

        # Determine mode
        if mode is None:
            mode = self._detect_best_mode()
        elif isinstance(mode, str):
            mode = SchedulerMode(mode)

        # Log installation
        self._log(f"Installing schedule: {interval.value}, mode: {mode.value}")

        # Install based on mode
        if mode == SchedulerMode.SYSTEM_CRON:
            self._install_cron_schedule(interval)
        else:
            self._install_builtin_schedule(interval)

        # Calculate next run
        next_run = self._calculate_next_run(interval)

        # Save state
        status = ScheduleStatus(
            enabled=True,
            interval=interval.value,
            mode=mode.value,
            next_run=next_run,
        )
        self._save_state(status)

        self._log(f"Schedule installed successfully. Next run: {next_run.isoformat()}")

        return status

    def uninstall_schedule(self) -> ScheduleStatus:
        """
        Uninstall the current schedule.

        Removes cron entries and stops the built-in scheduler if running.

        Returns:
            Updated schedule status.
        """
        status = self._load_state()

        self._log("Uninstalling schedule")

        # Stop built-in scheduler if running
        if self._is_daemon_running():
            self._stop_daemon()

        # Remove cron entry if present
        try:
            self._uninstall_cron_schedule()
        except Exception as e:
            self._log(f"Warning: Could not remove cron entry: {e}")

        # Update state
        status.enabled = False
        status.pid = None
        self._save_state(status)

        self._log("Schedule uninstalled successfully")

        return status

    def get_schedule_status(self) -> ScheduleStatus:
        """
        Get current schedule status.

        Returns:
            Current schedule status including last run information.
        """
        status = self._load_state()

        # Check if daemon is still running
        if status.mode == SchedulerMode.BUILT_IN.value:
            if self._is_daemon_running():
                status.pid = self._get_daemon_pid()
            else:
                status.pid = None
                if status.enabled:
                    # Daemon died unexpectedly
                    status.enabled = False
                    self._save_state(status)

        return status

    def get_next_run_time(self) -> datetime | None:
        """
        Get the datetime of the next scheduled run.

        Returns:
            Next run datetime, or None if scheduling is disabled.
        """
        status = self._load_state()
        if not status.enabled:
            return None
        return status.next_run

    def run_scheduled_collection(self, passphrase: str | None = None) -> CollectionRun:
        """
        Execute a scheduled collection run.

        This method is called by the scheduler (cron or built-in) to perform
        evidence collection. It handles errors gracefully and logs results.

        Args:
            passphrase: Passphrase for credential decryption. If None,
                       attempts to use environment variable NISIFY_PASSPHRASE.

        Returns:
            CollectionRun with results of the collection.
        """
        run = CollectionRun(started_at=datetime.now(UTC))

        self._log("Starting scheduled collection")

        try:
            # Get passphrase from environment if not provided
            if passphrase is None:
                passphrase = os.environ.get("NISIFY_PASSPHRASE")

            if not passphrase:
                raise SchedulerError(
                    "No passphrase provided. Set NISIFY_PASSPHRASE environment variable "
                    "or use the built-in scheduler with passphrase callback."
                )

            # Import here to avoid circular imports
            from nisify.collectors import (
                AwsCollector,
                DatadogCollector,
                GoogleCollector,
                JamfCollector,
                OktaCollector,
                SnowflakeCollector,
            )
            from nisify.config.credentials import CredentialStore
            from nisify.config.settings import load_config
            from nisify.storage import EvidenceStore

            # Load configuration
            settings = load_config()

            # Initialize credential store
            credential_store = CredentialStore()
            credential_store.unlock(passphrase)

            # Initialize evidence store
            store = EvidenceStore(Path(settings.data_dir))

            # Collect from enabled platforms
            collector_classes = {
                "aws": (AwsCollector, settings.aws),
                "okta": (OktaCollector, settings.okta),
                "jamf": (JamfCollector, settings.jamf),
                "google": (GoogleCollector, settings.google),
                "snowflake": (SnowflakeCollector, settings.snowflake),
                "datadog": (DatadogCollector, settings.datadog),
            }

            total_evidence = 0
            platforms_collected: list[str] = []
            collection_errors: list[tuple[str, str]] = []

            for platform_name, (collector_class, platform_config) in collector_classes.items():
                if not platform_config.enabled:
                    continue

                self._log(f"Collecting from {platform_name}")

                try:
                    # Get credentials
                    credentials = self._get_platform_credentials(
                        platform_name, credential_store
                    )

                    if not credentials:
                        self._log(f"  No credentials for {platform_name}, skipping")
                        continue

                    # Create collector and collect
                    collector = collector_class(settings, credential_store)
                    result = collector.collect()

                    if result.success:
                        # Store evidence
                        for evidence in result.evidence_items:
                            store.store_evidence(evidence)
                        total_evidence += len(result.evidence_items)
                        platforms_collected.append(platform_name)
                        self._log(f"  Collected {len(result.evidence_items)} items from {platform_name}")
                    else:
                        error_msg = ", ".join(result.errors) if result.errors else "Unknown error"
                        self._log(f"  Error collecting from {platform_name}: {error_msg}")
                        collection_errors.append((platform_name, error_msg))

                except Exception as e:
                    self._log(f"  Exception collecting from {platform_name}: {e}")
                    collection_errors.append((platform_name, str(e)))

            credential_store.lock()

            run.success = True
            run.evidence_count = total_evidence
            run.platforms_collected = platforms_collected
            run.completed_at = datetime.now(UTC)

            self._log(
                f"Collection complete: {total_evidence} items from "
                f"{len(platforms_collected)} platforms"
            )

        except Exception as e:
            run.success = False
            run.error = str(e)
            run.completed_at = datetime.now(UTC)
            self._log(f"Collection failed: {e}")

        # Update state with last run info
        status = self._load_state()
        status.last_run = run.completed_at
        status.last_run_success = run.success
        status.last_run_error = run.error

        # Calculate next run
        if status.enabled:
            interval = ScheduleInterval.from_string(status.interval)
            status.next_run = self._calculate_next_run(interval)

        self._save_state(status)

        return run

    def start_daemon(
        self,
        passphrase: str | None = None,
        foreground: bool = False,
    ) -> None:
        """
        Start the built-in scheduler daemon.

        Args:
            passphrase: Passphrase for credential decryption.
            foreground: If True, run in foreground (blocking).

        Raises:
            SchedulerAlreadyRunningError: If daemon is already running.
            SchedulerError: If daemon cannot be started.
        """
        if self._is_daemon_running():
            raise SchedulerAlreadyRunningError(
                f"Scheduler daemon already running with PID {self._get_daemon_pid()}"
            )

        status = self._load_state()
        if not status.enabled:
            raise SchedulerError("No schedule is installed. Run install_schedule first.")

        self._log("Starting scheduler daemon")

        # Store passphrase in environment for subprocess
        if passphrase:
            os.environ["NISIFY_PASSPHRASE"] = passphrase

        if foreground:
            # Run in current process
            self._run_scheduler_loop()
        else:
            # Start background thread
            self._stop_event.clear()
            self._scheduler_thread = threading.Thread(
                target=self._run_scheduler_loop,
                name="nisify-scheduler",
                daemon=True,
            )
            self._scheduler_thread.start()

            # Write PID file
            self._write_pid_file()

            status.pid = os.getpid()
            self._save_state(status)

            self._log(f"Scheduler daemon started with PID {os.getpid()}")

    def stop_daemon(self) -> None:
        """
        Stop the built-in scheduler daemon.

        Raises:
            SchedulerNotRunningError: If daemon is not running.
        """
        if not self._is_daemon_running():
            raise SchedulerNotRunningError("Scheduler daemon is not running")

        self._stop_daemon()

    def _run_scheduler_loop(self) -> None:
        """Main scheduler loop for built-in mode."""
        self._log("Scheduler loop started")

        while not self._stop_event.is_set():
            try:
                status = self._load_state()

                if not status.enabled:
                    self._log("Schedule disabled, stopping loop")
                    break

                now = datetime.now(UTC)
                next_run = status.next_run

                if next_run and now >= next_run:
                    # Time to run collection
                    self._log("Running scheduled collection")
                    self.run_scheduled_collection()

                # Sleep for 60 seconds before checking again
                self._stop_event.wait(60)

            except Exception as e:
                self._log(f"Error in scheduler loop: {e}")
                # Wait before retrying
                self._stop_event.wait(300)

        self._log("Scheduler loop stopped")
        self._remove_pid_file()

    def _detect_best_mode(self) -> SchedulerMode:
        """Detect the best scheduler mode for the current platform."""
        system = platform.system().lower()

        if system in ("linux", "darwin", "freebsd"):
            # Check if crontab is available
            try:
                result = subprocess.run(
                    ["which", "crontab"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return SchedulerMode.SYSTEM_CRON
            except (subprocess.SubprocessError, OSError):
                pass

        return SchedulerMode.BUILT_IN

    def _install_cron_schedule(self, interval: ScheduleInterval) -> None:
        """Install a crontab entry for scheduled collection."""
        # Get path to nisify command
        nisify_cmd = self._get_nisify_command()

        # Build cron line
        cron_schedule = interval.cron_schedule
        cron_comment = "# Nisify scheduled evidence collection"
        cron_line = f"{cron_schedule} {nisify_cmd} collect --all --quiet"

        # Get current crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                current_crontab = result.stdout
            else:
                current_crontab = ""
        except subprocess.SubprocessError as e:
            raise CronNotAvailableError(f"Cannot read crontab: {e}") from e

        # Remove existing nisify entries
        lines = current_crontab.strip().split("\n") if current_crontab.strip() else []
        lines = [line for line in lines if "nisify" not in line.lower()]

        # Add new entry
        lines.append(cron_comment)
        lines.append(cron_line)

        # Install new crontab
        new_crontab = "\n".join(lines) + "\n"

        try:
            process = subprocess.Popen(
                ["crontab", "-"],
                stdin=subprocess.PIPE,
                text=True,
            )
            process.communicate(input=new_crontab, timeout=10)

            if process.returncode != 0:
                raise CronNotAvailableError("Failed to install crontab entry")

        except subprocess.SubprocessError as e:
            raise CronNotAvailableError(f"Cannot write crontab: {e}") from e

        self._log(f"Installed cron entry: {cron_line}")

    def _uninstall_cron_schedule(self) -> None:
        """Remove nisify crontab entries."""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return  # No crontab

            current_crontab = result.stdout

        except subprocess.SubprocessError:
            return  # Cron not available

        # Remove nisify entries
        lines = current_crontab.strip().split("\n") if current_crontab.strip() else []
        lines = [line for line in lines if "nisify" not in line.lower()]

        if not lines:
            # Remove crontab entirely
            try:
                subprocess.run(["crontab", "-r"], capture_output=True, timeout=10)
            except subprocess.SubprocessError:
                pass
        else:
            # Install filtered crontab
            new_crontab = "\n".join(lines) + "\n"
            try:
                process = subprocess.Popen(
                    ["crontab", "-"],
                    stdin=subprocess.PIPE,
                    text=True,
                )
                process.communicate(input=new_crontab, timeout=10)
            except subprocess.SubprocessError:
                pass

        self._log("Removed cron entries")

    def _install_builtin_schedule(self, interval: ScheduleInterval) -> None:
        """Configure built-in scheduler for the given interval."""
        # The built-in scheduler uses state file for configuration
        # Actual scheduling happens in start_daemon()
        self._log(f"Configured built-in scheduler for {interval.value} collection")

    def _calculate_next_run(self, interval: ScheduleInterval) -> datetime:
        """Calculate the next run time based on interval."""
        now = datetime.now(UTC)

        if interval == ScheduleInterval.HOURLY:
            # Next hour at minute 0
            next_run = now.replace(minute=0, second=0, microsecond=0)
            next_run += timedelta(hours=1)

        elif interval == ScheduleInterval.DAILY:
            # Tomorrow at 2:00 AM UTC
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if now.hour >= 2:
                next_run += timedelta(days=1)

        elif interval == ScheduleInterval.WEEKLY:
            # Next Sunday at 2:00 AM UTC
            days_until_sunday = (6 - now.weekday()) % 7
            if days_until_sunday == 0 and now.hour >= 2:
                days_until_sunday = 7
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            next_run += timedelta(days=days_until_sunday)

        else:
            # Default to daily
            next_run = now + timedelta(days=1)

        return next_run

    def _get_nisify_command(self) -> str:
        """Get the full path to the nisify command."""
        # Try to find nisify in PATH
        try:
            result = subprocess.run(
                ["which", "nisify"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except subprocess.SubprocessError:
            pass

        # Fall back to python -m nisify
        python_path = sys.executable
        return f"{python_path} -m nisify"

    def _get_platform_credentials(
        self,
        platform: str,
        credential_store: Any,
    ) -> dict[str, str]:
        """Get credentials for a platform from the credential store."""
        from nisify.config.credentials import PLATFORM_CREDENTIAL_KEYS

        credentials = {}
        credential_keys = PLATFORM_CREDENTIAL_KEYS.get(platform, {})

        for key in credential_keys:
            try:
                value = credential_store.get_credential(platform, key)
                if value:
                    credentials[key] = value
            except Exception:
                pass

        return credentials

    def _load_state(self) -> ScheduleStatus:
        """Load scheduler state from disk."""
        if not self._state_file.exists():
            return ScheduleStatus()

        try:
            with open(self._state_file) as f:
                data = json.load(f)
            return ScheduleStatus.from_dict(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not load scheduler state: %s", e)
            return ScheduleStatus()

    def _save_state(self, status: ScheduleStatus) -> None:
        """Save scheduler state to disk."""
        self._scheduler_dir.mkdir(parents=True, exist_ok=True)

        try:
            with open(self._state_file, "w") as f:
                json.dump(status.to_dict(), f, indent=2)
        except OSError as e:
            logger.error("Could not save scheduler state: %s", e)

    def _is_daemon_running(self) -> bool:
        """Check if the scheduler daemon is running."""
        pid = self._get_daemon_pid()
        if pid is None:
            return False

        # Check if process exists
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            # Process doesn't exist, clean up PID file
            self._remove_pid_file()
            return False

    def _get_daemon_pid(self) -> int | None:
        """Get the PID of the running daemon."""
        if not self._pid_file.exists():
            return None

        try:
            with open(self._pid_file) as f:
                return int(f.read().strip())
        except (ValueError, OSError):
            return None

    def _write_pid_file(self) -> None:
        """Write current process PID to file."""
        try:
            with open(self._pid_file, "w") as f:
                f.write(str(os.getpid()))
        except OSError as e:
            logger.error("Could not write PID file: %s", e)

    def _remove_pid_file(self) -> None:
        """Remove PID file."""
        try:
            self._pid_file.unlink(missing_ok=True)
        except OSError:
            pass

    def _stop_daemon(self) -> None:
        """Stop the scheduler daemon."""
        # Signal the stop event for thread-based daemon
        self._stop_event.set()

        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=10)

        # Kill by PID if external process
        pid = self._get_daemon_pid()
        if pid and pid != os.getpid():
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait for process to terminate
                time.sleep(1)
                try:
                    os.kill(pid, 0)
                    # Still running, force kill
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            except OSError:
                pass

        self._remove_pid_file()

        # Update state
        status = self._load_state()
        status.pid = None
        self._save_state(status)

        self._log("Scheduler daemon stopped")

    def _log(self, message: str) -> None:
        """Write a message to the scheduler log with rotation."""
        timestamp = datetime.now(UTC).isoformat()
        log_line = f"[{timestamp}] {message}\n"

        # Rotate log if needed
        self._rotate_log_if_needed()

        # Append to log
        try:
            with open(self._log_file, "a") as f:
                f.write(log_line)
        except OSError as e:
            logger.error("Could not write to scheduler log: %s", e)

        # Also log to Python logger
        logger.info(message)

    def _rotate_log_if_needed(self) -> None:
        """Rotate the log file if it exceeds maximum size."""
        if not self._log_file.exists():
            return

        try:
            size = self._log_file.stat().st_size
            if size < MAX_LOG_SIZE:
                return

            # Rotate existing backups
            for i in range(LOG_BACKUP_COUNT - 1, 0, -1):
                old_backup = self._log_file.with_suffix(f".log.{i}")
                new_backup = self._log_file.with_suffix(f".log.{i + 1}")
                if old_backup.exists():
                    old_backup.rename(new_backup)

            # Rotate current log
            backup = self._log_file.with_suffix(".log.1")
            self._log_file.rename(backup)

        except OSError as e:
            logger.warning("Could not rotate log file: %s", e)

    def get_logs(self, lines: int = 100) -> list[str]:
        """
        Get recent scheduler log entries.

        Args:
            lines: Number of lines to return.

        Returns:
            List of log lines (newest last).
        """
        if not self._log_file.exists():
            return []

        try:
            with open(self._log_file) as f:
                all_lines = f.readlines()

            return all_lines[-lines:]
        except OSError:
            return []


def get_cron_help() -> str:
    """
    Get help text explaining cron schedule syntax.

    Returns:
        Multi-line string with cron syntax explanation.
    """
    return """
Cron Schedule Syntax
====================

Cron uses a 5-field schedule format:

    minute  hour  day-of-month  month  day-of-week
      |      |         |          |         |
      |      |         |          |         +-- 0-7 (0 and 7 are Sunday)
      |      |         |          +------------ 1-12
      |      |         +----------------------- 1-31
      |      +--------------------------------- 0-23
      +---------------------------------------- 0-59

Special characters:
    *   Any value
    ,   Value list separator
    -   Range of values
    /   Step values

Nisify Schedule Mappings:
    hourly  -> "0 * * * *"     (Every hour at minute 0)
    daily   -> "0 2 * * *"     (Daily at 2:00 AM)
    weekly  -> "0 2 * * 0"     (Sundays at 2:00 AM)

To view current crontab:
    crontab -l

To edit crontab manually:
    crontab -e
"""
