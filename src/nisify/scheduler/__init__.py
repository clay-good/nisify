"""
Scheduler for automated evidence collection.

Enables scheduled, automated evidence collection via system cron
or a built-in scheduler for cross-platform support.

Supports intervals: hourly, daily, weekly.

Two modes are available:
    - System cron: Uses the system crontab on Unix-like systems.
      Advantages: Survives reboots, system-managed, no daemon needed.
      Limitations: Unix-only, requires crontab access.

    - Built-in scheduler: Uses Python threading for cross-platform support.
      Advantages: Works on all platforms, no system configuration needed.
      Limitations: Requires a running daemon process.

Usage:
    from nisify.scheduler import Scheduler, ScheduleInterval

    scheduler = Scheduler()

    # Install daily collection schedule
    scheduler.install_schedule(ScheduleInterval.DAILY)

    # Check status
    status = scheduler.get_schedule_status()
    print(f"Next run: {status.next_run}")

    # Start built-in scheduler daemon (if using built-in mode)
    scheduler.start_daemon(passphrase="your-passphrase")

    # Disable scheduling
    scheduler.uninstall_schedule()
"""

from nisify.scheduler.cron import (
    CollectionRun,
    CronNotAvailableError,
    ScheduleInterval,
    Scheduler,
    SchedulerAlreadyRunningError,
    SchedulerError,
    SchedulerMode,
    SchedulerNotRunningError,
    ScheduleStatus,
    get_cron_help,
)

__all__ = [
    # Main class
    "Scheduler",
    # Enums
    "ScheduleInterval",
    "SchedulerMode",
    # Dataclasses
    "ScheduleStatus",
    "CollectionRun",
    # Errors
    "SchedulerError",
    "CronNotAvailableError",
    "SchedulerAlreadyRunningError",
    "SchedulerNotRunningError",
    # Utilities
    "get_cron_help",
]
