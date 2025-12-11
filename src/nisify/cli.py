"""
Command-line interface for Nisify.

Provides commands for all Nisify operations including initialization,
configuration, evidence collection, analysis, and reporting.

Uses Python's argparse module (no external CLI libraries).
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from nisify import __version__
from nisify.config.credentials import (
    PLATFORM_CREDENTIAL_KEYS,
    CredentialStore,
    CredentialStoreLockedError,
    CredentialStoreNotInitializedError,
    InvalidPassphraseError,
)
from nisify.config.settings import (
    DEFAULT_CONFIG_DIR,
    ConfigurationError,
    Settings,
    load_config,
    save_config,
)

# Set up logging
logger = logging.getLogger(__name__)

# Global verbosity settings (set during main() based on args)
_quiet_mode = False
_verbose_level = 0


def set_output_mode(quiet: bool = False, verbose: int = 0) -> None:
    """
    Set the output mode for the CLI.

    Args:
        quiet: If True, suppress non-essential output.
        verbose: Verbosity level (0=normal, 1+=verbose).
    """
    global _quiet_mode, _verbose_level
    _quiet_mode = quiet
    _verbose_level = verbose


def output(message: str = "", force: bool = False) -> None:
    """
    Print a message to stdout, respecting quiet mode.

    Args:
        message: The message to print.
        force: If True, print even in quiet mode (for essential output like JSON/CSV).
    """
    if force or not _quiet_mode:
        print(message)


def output_verbose(message: str, level: int = 1) -> None:
    """
    Print a verbose message only if verbosity is high enough.

    Args:
        message: The message to print.
        level: Required verbosity level to show this message.
    """
    if _verbose_level >= level and not _quiet_mode:
        print(message)


def output_error(message: str) -> None:
    """
    Print an error message (always shown, even in quiet mode).

    Args:
        message: The error message to print.
    """
    print(message, file=sys.stderr)


def format_as_csv(headers: list[str], rows: list[list[Any]]) -> str:
    """
    Format data as CSV string.

    Args:
        headers: Column headers.
        rows: List of row data (each row is a list of values).

    Returns:
        CSV formatted string.
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for Nisify CLI."""
    parser = argparse.ArgumentParser(
        prog="nisify",
        description="NIST CSF 2.0 compliance evidence aggregator",
        epilog="For more information, visit: https://github.com/clay-good/nisify",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"nisify {__version__}",
    )

    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Override config file location (default: ~/.nisify/config.yaml)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (can be repeated)",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential output",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>",
    )

    # info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show system information and diagnostics",
        description="Display version, configuration paths, storage statistics, and system info.",
    )
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    info_parser.set_defaults(func=cmd_info)

    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize Nisify configuration",
        description="Create config directory structure and set up initial settings.",
    )
    init_parser.set_defaults(func=cmd_init)

    # configure command
    configure_parser = subparsers.add_parser(
        "configure",
        help="Interactive configuration editor",
        description="Add or update platform credentials and settings.",
    )
    configure_parser.add_argument(
        "--platform",
        metavar="NAME",
        choices=["aws", "okta", "jamf", "google", "snowflake", "datadog", "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"],
        help="Configure specific platform",
    )
    configure_parser.set_defaults(func=cmd_configure)

    # status command
    status_parser = subparsers.add_parser(
        "status",
        help="Show current configuration status",
        description="Display configuration status, last collection times, and credential status.",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    status_parser.set_defaults(func=cmd_status)

    # collect command
    collect_parser = subparsers.add_parser(
        "collect",
        help="Run evidence collection",
        description="Collect evidence from configured platforms.",
    )
    collect_parser.add_argument(
        "--platform",
        metavar="NAME",
        choices=["aws", "okta", "jamf", "google", "snowflake", "datadog", "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"],
        help="Collect from specific platform only",
    )
    collect_parser.add_argument(
        "--all",
        action="store_true",
        dest="collect_all",
        help="Collect from all enabled platforms",
    )
    collect_parser.set_defaults(func=cmd_collect)

    # maturity command
    maturity_parser = subparsers.add_parser(
        "maturity",
        help="Calculate and display maturity scores",
        description="Show NIST CSF 2.0 maturity scores based on collected evidence.",
    )
    maturity_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    maturity_parser.add_argument(
        "--function",
        metavar="ID",
        help="Filter by NIST function (e.g., PR, DE)",
    )
    maturity_parser.set_defaults(func=cmd_maturity)

    # gaps command
    gaps_parser = subparsers.add_parser(
        "gaps",
        help="Show gap analysis",
        description="Display controls lacking sufficient evidence with recommendations.",
    )
    gaps_parser.add_argument(
        "--priority",
        choices=["critical", "high", "medium", "low"],
        help="Filter by priority level",
    )
    gaps_parser.add_argument(
        "--function",
        metavar="ID",
        help="Filter by NIST function",
    )
    gaps_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    gaps_parser.set_defaults(func=cmd_gaps)

    # report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate compliance report",
        description="Generate a compliance report in the specified format.",
    )
    report_parser.add_argument(
        "--format",
        choices=["pdf", "json", "html"],
        default="pdf",
        help="Report format (default: pdf)",
    )
    report_parser.add_argument(
        "--output",
        metavar="PATH",
        help="Output file or directory path",
    )
    report_parser.set_defaults(func=cmd_report)

    # export command
    export_parser = subparsers.add_parser(
        "export",
        help="Export data to JSON",
        description="Export evidence and analysis data for external use.",
    )
    export_parser.add_argument(
        "--type",
        choices=["full", "maturity", "evidence", "gaps"],
        default="full",
        help="Export type (default: full)",
    )
    export_parser.add_argument(
        "--output",
        metavar="PATH",
        help="Output directory path",
    )
    export_parser.add_argument(
        "--compress",
        action="store_true",
        help="Compress output with gzip",
    )
    export_parser.set_defaults(func=cmd_export)

    # dashboard command
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Start local dashboard server",
        description="Launch the web dashboard for visualizing compliance posture.",
    )
    dashboard_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Server port (default: 8080)",
    )
    dashboard_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)",
    )
    dashboard_parser.add_argument(
        "--background", "-b",
        action="store_true",
        help="Run dashboard server in background (returns immediately)",
    )
    dashboard_parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop a running background dashboard server",
    )
    dashboard_parser.add_argument(
        "--status",
        action="store_true",
        help="Check if dashboard server is running",
    )
    dashboard_parser.set_defaults(func=cmd_dashboard)

    # schedule command
    schedule_parser = subparsers.add_parser(
        "schedule",
        help="Configure scheduled collection",
        description="Set up automated evidence collection.",
    )
    schedule_parser.add_argument(
        "--interval",
        choices=["hourly", "daily", "weekly"],
        help="Collection interval",
    )
    schedule_group = schedule_parser.add_mutually_exclusive_group()
    schedule_group.add_argument(
        "--enable",
        action="store_true",
        help="Enable scheduled collection",
    )
    schedule_group.add_argument(
        "--disable",
        action="store_true",
        help="Disable scheduled collection",
    )
    schedule_group.add_argument(
        "--start-daemon",
        action="store_true",
        dest="start_daemon",
        help="Start the built-in scheduler daemon",
    )
    schedule_group.add_argument(
        "--stop-daemon",
        action="store_true",
        dest="stop_daemon",
        help="Stop the built-in scheduler daemon",
    )
    schedule_parser.add_argument(
        "--foreground",
        action="store_true",
        help="Run daemon in foreground (with --start-daemon)",
    )
    schedule_parser.add_argument(
        "--logs",
        action="store_true",
        help="Show recent scheduler logs",
    )
    schedule_parser.add_argument(
        "--cron-help",
        action="store_true",
        dest="cron_help",
        help="Show cron schedule syntax help",
    )
    schedule_parser.set_defaults(func=cmd_schedule)

    # test-connection command
    test_parser = subparsers.add_parser(
        "test-connection",
        help="Test platform connectivity",
        description="Verify credentials and connectivity for a specific platform.",
    )
    test_parser.add_argument(
        "platform",
        metavar="PLATFORM",
        choices=["aws", "okta", "jamf", "google", "snowflake", "datadog", "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"],
        help="Platform to test",
    )
    test_parser.set_defaults(func=cmd_test_connection)

    # cleanup command
    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Clean up old evidence and data",
        description="Remove old evidence files based on retention policy.",
    )
    cleanup_parser.add_argument(
        "--days",
        type=int,
        metavar="N",
        help="Override retention days (default: from config)",
    )
    cleanup_parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Show what would be deleted without deleting",
    )
    cleanup_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    cleanup_parser.set_defaults(func=cmd_cleanup)

    # backup command
    backup_parser = subparsers.add_parser(
        "backup",
        help="Create a backup of Nisify data",
        description="Create a portable backup archive of the database, evidence, and config.",
    )
    backup_parser.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help="Output directory for backup file (default: current directory)",
    )
    backup_parser.add_argument(
        "--include-credentials",
        action="store_true",
        dest="include_credentials",
        help="Include encrypted credentials in backup (requires passphrase at restore)",
    )
    backup_parser.set_defaults(func=cmd_backup)

    # restore command
    restore_parser = subparsers.add_parser(
        "restore",
        help="Restore from a backup archive",
        description="Restore Nisify data from a backup archive.",
    )
    restore_parser.add_argument(
        "backup_file",
        metavar="FILE",
        help="Path to backup archive (.tar.gz)",
    )
    restore_parser.add_argument(
        "--no-backup",
        action="store_true",
        dest="no_backup",
        help="Skip backing up existing data before restore",
    )
    restore_parser.add_argument(
        "--verify-only",
        action="store_true",
        dest="verify_only",
        help="Verify backup integrity without restoring",
    )
    restore_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompts",
    )
    restore_parser.set_defaults(func=cmd_restore)

    # demo command
    demo_parser = subparsers.add_parser(
        "demo",
        help="Generate demo data for quick evaluation",
        description=(
            "Generate realistic sample data without requiring platform credentials. "
            "Perfect for demos, evaluation, and testing."
        ),
    )
    demo_parser.add_argument(
        "--profile",
        choices=["startup", "growing", "mature"],
        default="growing",
        help="Organization profile: startup (many gaps), growing (moderate), mature (few gaps)",
    )
    demo_parser.add_argument(
        "--organization",
        metavar="NAME",
        help="Organization name (default based on profile)",
    )
    demo_parser.add_argument(
        "--days",
        type=int,
        default=30,
        metavar="N",
        help="Days of historical data to generate (default: 30)",
    )
    demo_parser.add_argument(
        "--platforms",
        nargs="+",
        choices=["aws", "okta", "jamf", "google"],
        help="Platforms to include (default: all)",
    )
    demo_parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start dashboard after generating demo data",
    )
    demo_parser.set_defaults(func=cmd_demo)

    # submit command - manual evidence submission
    submit_parser = subparsers.add_parser(
        "submit",
        help="Submit manual evidence for NIST CSF controls",
        description=(
            "Submit manual evidence files for controls that cannot be "
            "collected via API (e.g., policies, audit reports, training records)."
        ),
    )
    submit_parser.add_argument(
        "--control",
        "-c",
        metavar="ID",
        help="Control ID to submit evidence for (e.g., GV.PO-01, GV.RR-02)",
    )
    submit_parser.add_argument(
        "--type",
        "-t",
        metavar="TYPE",
        help="Evidence type (e.g., policy_document, risk_register, board_minutes)",
    )
    submit_parser.add_argument(
        "--file",
        "-f",
        type=Path,
        metavar="PATH",
        help="Path to evidence file (PDF, JSON, or text file)",
    )
    submit_parser.add_argument(
        "--description",
        "-d",
        metavar="TEXT",
        help="Description of the evidence being submitted",
    )
    submit_parser.add_argument(
        "--url",
        "-u",
        metavar="URL",
        help="URL reference for the evidence (e.g., link to document in SharePoint)",
    )
    submit_parser.add_argument(
        "--list-types",
        action="store_true",
        help="List all valid evidence types for manual submission",
    )
    submit_parser.set_defaults(func=cmd_submit)

    return parser


def setup_logging(verbose: int, quiet: bool) -> None:
    """Configure logging based on verbosity level."""
    if quiet:
        level = logging.WARNING
    elif verbose == 0:
        level = logging.INFO
    elif verbose == 1:
        level = logging.DEBUG
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_credentials_for_platform(
    platform: str,
    credential_store: CredentialStore,
) -> dict[str, str]:
    """Get all credentials for a platform."""
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


def cmd_info(args: argparse.Namespace) -> int:
    """Show system information and diagnostics."""
    import platform as platform_module

    from nisify.reports import WEASYPRINT_AVAILABLE

    info: dict[str, Any] = {
        "version": __version__,
        "python_version": platform_module.python_version(),
        "platform": platform_module.platform(),
        "config_dir": str(DEFAULT_CONFIG_DIR),
        "initialized": False,
        "credential_store": "not_initialized",
        "data_dir": None,
        "storage": None,
        "platforms_configured": [],
        "optional_dependencies": {
            "weasyprint": WEASYPRINT_AVAILABLE,
        },
    }

    # Check initialization status
    credential_store = CredentialStore()
    if credential_store.is_initialized():
        info["initialized"] = True
        info["credential_store"] = "locked"

    # Try to load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
        info["data_dir"] = str(settings.data_dir)

        # Check which platforms are enabled
        for platform_name in ["aws", "okta", "jamf", "google", "snowflake", "datadog", "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"]:
            platform_config = getattr(settings, platform_name, None)
            if platform_config and getattr(platform_config, "enabled", False):
                info["platforms_configured"].append(platform_name)

        # Get storage statistics
        try:
            from nisify.storage import EvidenceStore
            store = EvidenceStore(Path(settings.data_dir))
            stats = store.get_statistics()
            info["storage"] = {
                "total_evidence": stats.get("total_evidence", 0),
                "total_runs": stats.get("total_runs", 0),
                "total_snapshots": stats.get("total_snapshots", 0),
                "database_size_mb": round(stats.get("database_size_bytes", 0) / 1024 / 1024, 2),
                "evidence_size_mb": round(stats.get("evidence_size_bytes", 0) / 1024 / 1024, 2),
                "evidence_by_platform": stats.get("evidence_by_platform", {}),
                "last_collection": stats.get("last_collection", {}),
            }
        except Exception as e:
            info["storage"] = {"error": str(e)}

    except ConfigurationError:
        pass  # Not configured yet

    if args.json:
        output(json.dumps(info, indent=2, default=str), force=True)
    else:
        output("Nisify System Information")
        output("=" * 60)
        output()
        output(f"Version: {info['version']}")
        output(f"Python: {info['python_version']}")
        output(f"Platform: {info['platform']}")
        output()
        output("Paths:")
        output(f"  Config directory: {info['config_dir']}")
        if info["data_dir"]:
            output(f"  Data directory: {info['data_dir']}")
        output()
        output("Status:")
        output(f"  Initialized: {'Yes' if info['initialized'] else 'No'}")
        output(f"  Credential store: {info['credential_store']}")
        if info["platforms_configured"]:
            output(f"  Platforms enabled: {', '.join(info['platforms_configured'])}")
        else:
            output("  Platforms enabled: None")
        output()
        output("Optional Dependencies:")
        for dep, available in info["optional_dependencies"].items():
            status = "installed" if available else "not installed"
            output(f"  {dep}: {status}")
        output()
        if info["storage"] and "error" not in info["storage"]:
            storage = info["storage"]
            output("Storage Statistics:")
            output(f"  Total evidence items: {storage['total_evidence']:,}")
            output(f"  Collection runs: {storage['total_runs']:,}")
            output(f"  Maturity snapshots: {storage['total_snapshots']:,}")
            output(f"  Database size: {storage['database_size_mb']:.2f} MB")
            output(f"  Evidence files: {storage['evidence_size_mb']:.2f} MB")
            if storage["evidence_by_platform"]:
                output("  Evidence by platform:")
                for platform_name, count in storage["evidence_by_platform"].items():
                    output(f"    {platform_name}: {count:,}")
            if storage["last_collection"]:
                output("  Last collection:")
                for platform_name, timestamp in storage["last_collection"].items():
                    output(f"    {platform_name}: {timestamp}")

    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize Nisify configuration."""
    output("Nisify Initialization")
    output("=" * 50)
    output()

    credential_store = CredentialStore()

    # Check if already initialized
    if credential_store.is_initialized():
        output(f"Nisify is already initialized at: {DEFAULT_CONFIG_DIR}")
        output()
        output("Configuration files exist:")
        output(f"  - {DEFAULT_CONFIG_DIR / 'config.yaml'}")
        output(f"  - {DEFAULT_CONFIG_DIR / 'credentials.enc'}")
        output()
        output("To reset, delete the ~/.nisify directory and run init again.")
        return 0

    output("This will create the Nisify configuration directory and set up")
    output("encrypted credential storage.")
    output()
    output(f"Configuration directory: {DEFAULT_CONFIG_DIR}")
    output()

    # Get passphrase for credential encryption
    output("Credential Encryption Setup")
    output("-" * 30)
    output("Enter a passphrase to encrypt your API credentials.")
    output("This passphrase will be required to access credentials.")
    output("Minimum 8 characters recommended: 12+ with mixed case, numbers, symbols.")
    output()

    while True:
        passphrase = getpass.getpass("Enter passphrase: ")
        if len(passphrase) < 8:
            output_error("Error: Passphrase must be at least 8 characters.")
            continue

        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            output_error("Error: Passphrases do not match.")
            continue

        break

    # Initialize credential store
    try:
        credential_store.initialize(passphrase)
        output()
        output("Credential store initialized successfully.")
    except Exception as e:
        output_error(f"Error initializing credential store: {e}")
        return 1

    # Create default configuration
    settings = Settings()
    try:
        save_config(settings)
        output(f"Configuration file created: {DEFAULT_CONFIG_DIR / 'config.yaml'}")
    except ConfigurationError as e:
        output_error(f"Error creating configuration: {e}")
        return 1

    # Create data directories
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "evidence").mkdir(exist_ok=True)

    reports_dir = Path(settings.reporting.output_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = DEFAULT_CONFIG_DIR / "logs"
    logs_dir.mkdir(exist_ok=True)

    output()
    output("Initialization complete.")
    output()
    output("Next steps:")
    output("  1. Edit ~/.nisify/config.yaml to enable platforms")
    output("  2. Run 'nisify configure' to set up platform credentials")
    output("  3. Run 'nisify test-connection <platform>' to verify connectivity")
    output("  4. Run 'nisify collect --all' to gather evidence")
    output()

    return 0


def cmd_configure(args: argparse.Namespace) -> int:
    """Interactive configuration editor."""
    credential_store = CredentialStore()

    if not credential_store.is_initialized():
        output_error("Error: Nisify not initialized. Run 'nisify init' first.")
        return 1

    # Unlock credential store
    passphrase = getpass.getpass("Enter passphrase to unlock credentials: ")
    try:
        credential_store.unlock(passphrase)
    except InvalidPassphraseError:
        output_error("Error: Invalid passphrase.")
        return 1

    if args.platform:
        # Configure specific platform
        result = _configure_platform(args.platform, credential_store)
        credential_store.lock()
        return result
    else:
        # Interactive platform selection
        output()
        output("Platform Configuration")
        output("=" * 50)
        output()
        output("Available platforms:")
        output("   1. aws       - Amazon Web Services")
        output("   2. okta      - Okta Identity")
        output("   3. jamf      - Jamf Pro")
        output("   4. google    - Google Workspace")
        output("   5. snowflake - Snowflake Data Cloud")
        output("   6. datadog   - Datadog Monitoring")
        output("   7. gitlab    - GitLab")
        output("   8. jira      - Atlassian Jira")
        output("   9. zendesk   - Zendesk Support")
        output("  10. zoom      - Zoom Video")
        output("  11. notion    - Notion Workspace")
        output("  12. slab      - Slab Knowledge Base")
        output("  13. spotdraft - SpotDraft CLM")
        output("  14. Exit")
        output()

        while True:
            choice = input("Select platform to configure (1-14): ").strip()

            platform_map = {
                "1": "aws",
                "2": "okta",
                "3": "jamf",
                "4": "google",
                "5": "snowflake",
                "6": "datadog",
                "7": "gitlab",
                "8": "jira",
                "9": "zendesk",
                "10": "zoom",
                "11": "notion",
                "12": "slab",
                "13": "spotdraft",
                "14": None,
            }

            if choice not in platform_map:
                output_error("Invalid selection. Enter 1-14.")
                continue

            platform = platform_map[choice]
            if platform is None:
                break

            _configure_platform(platform, credential_store)
            output()

    credential_store.lock()
    return 0


def _configure_platform(platform: str, credential_store: CredentialStore) -> int:
    """Configure credentials for a specific platform."""
    output()
    output(f"Configuring {platform.upper()}")
    output("-" * 30)

    credential_keys = PLATFORM_CREDENTIAL_KEYS.get(platform, {})

    if not credential_keys:
        output(f"Platform '{platform}' uses file-based authentication.")
        output("Configure the file path in ~/.nisify/config.yaml")
        return 0

    # Show existing credentials (keys only, not values)
    try:
        existing = credential_store.list_credentials(platform)
        if existing:
            output(f"Existing credentials for {platform}: {', '.join(existing)}")
    except Exception:
        existing = []

    output()
    output("Credential keys for this platform:")
    for key, description in credential_keys.items():
        output(f"  {key}: {description}")
    output()

    for key, description in credential_keys.items():
        # Check if credential exists
        has_existing = key in existing

        if has_existing:
            update = input(f"Update {key}? (y/N): ").strip().lower()
            if update != "y":
                continue

        output(f"Enter {key}:")
        output(f"  ({description})")
        value = getpass.getpass(f"  {key}: ")

        if value:
            credential_store.set_credential(platform, key, value)
            output(f"  Saved {key}")
        else:
            output(f"  Skipped {key}")

    output()
    output(f"Configuration for {platform} complete.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show current configuration status."""
    # Check initialization
    credential_store = CredentialStore()
    if not credential_store.is_initialized():
        if args.format == "json":
            output(json.dumps({"status": "not_initialized", "version": __version__}), force=True)
        elif args.format == "csv":
            output("status,version", force=True)
            output(f"not_initialized,{__version__}", force=True)
        else:
            output("Nisify Status")
            output("=" * 50)
            output()
            output(f"Version: {__version__}")
            output(f"Config directory: {DEFAULT_CONFIG_DIR}")
            output()
            output("Status: NOT INITIALIZED")
            output()
            output("Run 'nisify init' to set up Nisify.")
        return 0

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Build platform status data
    platforms = [
        ("aws", settings.aws),
        ("okta", settings.okta),
        ("jamf", settings.jamf),
        ("google", settings.google),
        ("snowflake", settings.snowflake),
        ("datadog", settings.datadog),
        ("gitlab", settings.gitlab),
        ("jira", settings.jira),
        ("zendesk", settings.zendesk),
        ("zoom", settings.zoom),
        ("notion", settings.notion),
        ("slab", settings.slab),
        ("spotdraft", settings.spotdraft),
    ]

    # For JSON/CSV output, skip the passphrase prompt
    credentials_unlocked = False
    if args.format == "table":
        try:
            passphrase = getpass.getpass(
                "Enter passphrase to show credential status (or press Enter to skip): "
            )
            if passphrase:
                credential_store.unlock(passphrase)
                credentials_unlocked = True
        except InvalidPassphraseError:
            output("Invalid passphrase - showing limited status")
        except Exception:
            pass

    # Build platform data
    platform_data = []
    for name, config in platforms:
        cred_keys = []
        if credentials_unlocked:
            try:
                cred_keys = credential_store.list_credentials(name)
            except Exception:
                pass
        platform_data.append({
            "platform": name,
            "enabled": config.enabled,
            "credentials": cred_keys,
        })

    if credentials_unlocked:
        credential_store.lock()

    # Get evidence statistics
    evidence_stats = {}
    try:
        from nisify.storage import EvidenceStore
        store = EvidenceStore(Path(settings.data_dir))
        evidence_stats = store.get_statistics()
    except Exception:
        pass

    # Output based on format
    if args.format == "json":
        result = {
            "version": __version__,
            "status": "initialized",
            "config_directory": str(DEFAULT_CONFIG_DIR),
            "platforms": platform_data,
            "collection": {
                "schedule": settings.collection.schedule,
                "retention_days": settings.collection.retention_days,
            },
            "reporting": {
                "company_name": settings.reporting.company_name,
                "output_dir": str(settings.reporting.output_dir),
            },
            "evidence": evidence_stats,
        }
        output(json.dumps(result, indent=2, default=str), force=True)
    elif args.format == "csv":
        # CSV shows platform status
        headers = ["Platform", "Enabled", "Has Credentials"]
        rows = []
        for p in platform_data:
            rows.append([p["platform"], "yes" if p["enabled"] else "no", "yes" if p["credentials"] else "no"])
        output(format_as_csv(headers, rows), force=True)
    else:
        # Table output (original format)
        output("Nisify Status")
        output("=" * 50)
        output()
        output(f"Version: {__version__}")
        output(f"Config directory: {DEFAULT_CONFIG_DIR}")
        output()
        output("Status: Initialized")
        output()

        output("Platform Status")
        output("-" * 30)
        for p in platform_data:
            enabled = "ENABLED" if p["enabled"] else "disabled"
            cred_status = ""
            if p["credentials"]:
                cred_status = f" (credentials: {', '.join(p['credentials'])})"
            elif credentials_unlocked:
                cred_status = " (no credentials)"
            output(f"  {p['platform']:12} {enabled}{cred_status}")

        output()
        output("Collection Settings")
        output("-" * 30)
        output(f"  Schedule: {settings.collection.schedule}")
        output(f"  Retention: {settings.collection.retention_days} days")

        output()
        output("Reporting Settings")
        output("-" * 30)
        output(f"  Company: {settings.reporting.company_name or '(not set)'}")
        output(f"  Output: {settings.reporting.output_dir}")

        output()
        output("Evidence Status")
        output("-" * 30)
        output(f"  Total evidence items: {evidence_stats.get('total_evidence', 0)}")
        output(f"  Collection runs: {evidence_stats.get('total_runs', 0)}")
        if evidence_stats.get('last_collection'):
            output(f"  Last collection: {evidence_stats['last_collection']}")

    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    """Run evidence collection from configured platforms."""
    import time

    from nisify.collectors import (
        AwsCollector,
        DatadogCollector,
        GitLabCollector,
        GoogleCollector,
        JamfCollector,
        JiraCollector,
        NotionCollector,
        OktaCollector,
        SlabCollector,
        SnowflakeCollector,
        SpotDraftCollector,
        ZendeskCollector,
        ZoomCollector,
    )
    from nisify.storage import EvidenceStore

    credential_store = CredentialStore()

    if not credential_store.is_initialized():
        output_error("Error: Nisify not initialized. Run 'nisify init' first.")
        return 1

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Unlock credentials
    passphrase = getpass.getpass("Enter passphrase to unlock credentials: ")
    try:
        credential_store.unlock(passphrase)
    except InvalidPassphraseError:
        output_error("Error: Invalid passphrase.")
        return 1

    # Initialize evidence store
    store = EvidenceStore(Path(settings.data_dir))

    # All supported platforms
    all_platforms = [
        "aws", "okta", "jamf", "google", "snowflake", "datadog",
        "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"
    ]

    # Determine which platforms to collect from
    if args.platform:
        platforms_to_collect = [args.platform]
    elif args.collect_all:
        platforms_to_collect = []
        for platform_name in all_platforms:
            platform_config = getattr(settings, platform_name, None)
            if platform_config and getattr(platform_config, "enabled", False):
                platforms_to_collect.append(platform_name)
    else:
        output_error("Error: Specify --platform or --all")
        credential_store.lock()
        return 1

    if not platforms_to_collect:
        output("No platforms enabled. Enable platforms in ~/.nisify/config.yaml")
        credential_store.lock()
        return 0

    output("Evidence Collection")
    output("=" * 50)
    output(f"Platforms: {', '.join(platforms_to_collect)}")
    output()

    # Collector mapping
    collector_classes = {
        "aws": AwsCollector,
        "okta": OktaCollector,
        "jamf": JamfCollector,
        "google": GoogleCollector,
        "snowflake": SnowflakeCollector,
        "datadog": DatadogCollector,
        "gitlab": GitLabCollector,
        "jira": JiraCollector,
        "zendesk": ZendeskCollector,
        "zoom": ZoomCollector,
        "notion": NotionCollector,
        "slab": SlabCollector,
        "spotdraft": SpotDraftCollector,
    }

    total_evidence = 0
    errors: list[tuple[str, str]] = []
    start_time = time.time()

    for platform in platforms_to_collect:
        output(f"Collecting from {platform}...")

        try:
            # Get credentials for platform
            credentials = get_credentials_for_platform(platform, credential_store)

            if not credentials:
                output(f"  Warning: No credentials found for {platform}")
                continue

            # Get platform config
            platform_config = getattr(settings, platform)

            # Create collector
            collector_class = collector_classes.get(platform)
            if not collector_class:
                output_error(f"  Error: Unknown platform {platform}")
                continue

            collector = collector_class(settings, credential_store)  # type: ignore[abstract]

            # Collect evidence
            result = collector.collect()

            if result.success:
                evidence_count = len(result.evidence_items)
                output(f"  Collected {evidence_count} evidence items")
                total_evidence += evidence_count

                # Store evidence
                for evidence in result.evidence_items:
                    store.store_evidence(evidence)
            else:
                error_msg = ", ".join(result.errors) if result.errors else "Unknown error"
                output_error(f"  Error: {error_msg}")
                errors.append((platform, error_msg))

        except Exception as e:
            output_error(f"  Error: {e}")
            errors.append((platform, str(e)))

    credential_store.lock()

    # Calculate duration
    duration = time.time() - start_time

    output()
    output("-" * 50)
    output(f"Collection complete: {total_evidence} evidence items collected")

    if errors:
        output()
        output("Errors:")
        for platform, error in errors:
            output(f"  {platform}: {error}")

    return 0 if not errors else 1


def cmd_maturity(args: argparse.Namespace) -> int:
    """Calculate and display maturity scores."""
    from nisify.nist import MappingEngine, MaturityCalculator, get_all_functions
    from nisify.storage import EvidenceStore

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Initialize components
    store = EvidenceStore(Path(settings.data_dir))
    mapping_engine = MappingEngine()
    calculator = MaturityCalculator()

    # Get evidence from store
    evidence_items = store.get_all_evidence()

    if not evidence_items:
        output("No evidence collected yet. Run 'nisify collect --all' first.")
        return 0

    # Map evidence to controls
    output_verbose("Analyzing evidence...")
    mapping_results = mapping_engine.map_all_evidence(evidence_items)

    # Calculate maturity
    breakdown = calculator.calculate_all(mapping_results)

    if args.format == "json":
        # JSON output
        result = {
            "timestamp": datetime.now(UTC).isoformat(),
            "overall": breakdown.overall.to_dict(),
            "by_function": {k: v.to_dict() for k, v in breakdown.by_function.items()},
            "by_category": {k: v.to_dict() for k, v in breakdown.by_category.items()},
            "statistics": breakdown.statistics,
        }
        output(json.dumps(result, indent=2), force=True)
    elif args.format == "csv":
        # CSV output
        functions = get_all_functions()
        headers = ["Function ID", "Function Name", "Level", "Score", "Evidence Count", "Confidence"]
        rows = []
        for func in functions:
            if args.function and func.id != args.function.upper():
                continue
            if func.id in breakdown.by_function:
                score = breakdown.by_function[func.id]
                rows.append([func.id, func.name, score.level, f"{score.score:.2f}", score.evidence_count, f"{score.confidence:.2f}"])
        output(format_as_csv(headers, rows), force=True)
    else:
        # Table output
        output()
        output("NIST CSF 2.0 Maturity Assessment")
        output("=" * 60)
        output()

        # Overall score
        output(f"Overall Maturity: Level {breakdown.overall.level} ({breakdown.overall.score:.2f}/4.0)")
        output(f"Evidence items: {breakdown.overall.evidence_count}")
        output(f"Confidence: {breakdown.overall.confidence:.0%}")
        output()

        # Function scores
        output("By Function:")
        output("-" * 60)
        output(f"{'Function':<30} {'Level':>8} {'Score':>10} {'Evidence':>10}")
        output("-" * 60)

        functions = get_all_functions()
        for func in functions:
            if args.function and func.id != args.function.upper():
                continue

            if func.id in breakdown.by_function:
                score = breakdown.by_function[func.id]
                output(f"{func.name:<30} {score.level:>8} {score.score:>10.2f} {score.evidence_count:>10}")

        output("-" * 60)
        output()

        # Statistics
        stats = breakdown.statistics
        output(f"Subcategories with evidence: {stats.get('subcategories_with_evidence', 0)}/{stats.get('total_subcategories', 106)}")

    return 0


def cmd_gaps(args: argparse.Namespace) -> int:
    """Show gap analysis with recommendations."""
    from nisify.analysis import GapAnalyzer, Priority
    from nisify.nist import MappingEngine, MaturityCalculator
    from nisify.storage import EvidenceStore

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Initialize components
    store = EvidenceStore(Path(settings.data_dir))
    mapping_engine = MappingEngine()
    calculator = MaturityCalculator()
    analyzer = GapAnalyzer()

    # Get evidence
    evidence_items = store.get_all_evidence()

    if not evidence_items:
        output("No evidence collected yet. Run 'nisify collect --all' first.")
        return 0

    # Calculate maturity
    output_verbose("Analyzing gaps...")
    mapping_results = mapping_engine.map_all_evidence(evidence_items)
    breakdown = calculator.calculate_all(mapping_results)

    # Analyze gaps
    gap_analysis = analyzer.analyze_gaps(breakdown)

    # Filter gaps for all output formats
    gaps_to_show = gap_analysis.all_gaps

    if args.priority:
        priority_filter = Priority(args.priority)
        gaps_to_show = [g for g in gaps_to_show if g.priority == priority_filter]

    if args.function:
        func_filter = args.function.upper()
        gaps_to_show = [g for g in gaps_to_show if g.function_id == func_filter]

    if args.format == "json":
        # JSON output
        output(json.dumps(gap_analysis.to_dict(), indent=2), force=True)
    elif args.format == "csv":
        # CSV output
        headers = ["Control ID", "Control Name", "Function", "Priority", "Current Level", "Target Level", "Gap Type", "Recommendation"]
        rows = []
        for gap in gaps_to_show:
            recommendation = gap.recommendations[0].action if gap.recommendations else ""
            rows.append([
                gap.control_id,
                gap.control_name,
                gap.function_id,
                gap.priority.value,
                gap.current_maturity,
                gap.target_maturity,
                gap.gap_type.value,
                recommendation
            ])
        output(format_as_csv(headers, rows), force=True)
    else:
        # Table output
        output()
        output("NIST CSF 2.0 Gap Analysis")
        output("=" * 70)
        output()

        # Summary
        output(f"Total controls: {gap_analysis.total_controls}")
        output(f"Controls with gaps: {gap_analysis.controls_with_gaps} ({gap_analysis.gap_percentage:.1f}%)")
        output()

        output("By Priority:")
        for priority, count in gap_analysis.gaps_by_priority.items():
            output(f"  {priority.capitalize()}: {count}")
        output()

        # Show gaps
        if gaps_to_show:
            output("Gaps:")
            output("-" * 70)
            for gap in gaps_to_show[:20]:  # Limit to 20
                output(f"\n{gap.control_id}: {gap.control_name}")
                output(f"  Priority: {gap.priority.value.upper()}")
                output(f"  Current Level: {gap.current_maturity} (Target: {gap.target_maturity})")
                output(f"  Type: {gap.gap_type.value}")
                if gap.recommendations:
                    output(f"  Recommendation: {gap.recommendations[0].action}")

            if len(gaps_to_show) > 20:
                output(f"\n... and {len(gaps_to_show) - 20} more gaps")
        else:
            output("No gaps found matching filters.")

        # Quick wins
        if gap_analysis.quick_wins:
            output()
            output("Quick Wins (Low Effort, High Impact):")
            output("-" * 70)
            for gap in gap_analysis.quick_wins[:5]:
                output(f"  {gap.control_id}: {gap.control_name}")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate compliance report."""
    from nisify.analysis import GapAnalyzer
    from nisify.nist import MappingEngine, MaturityCalculator
    from nisify.reports import (
        WEASYPRINT_AVAILABLE,
        JsonExporter,
        PdfReportGenerator,
        ReportConfig,
    )
    from nisify.storage import EvidenceStore

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Initialize components
    store = EvidenceStore(Path(settings.data_dir))
    mapping_engine = MappingEngine()
    calculator = MaturityCalculator()
    analyzer = GapAnalyzer()

    # Get evidence
    evidence_items = store.get_all_evidence()

    if not evidence_items:
        output("No evidence collected yet. Run 'nisify collect --all' first.")
        return 0

    output("Generating report...")

    # Calculate maturity and gaps
    mapping_results = mapping_engine.map_all_evidence(evidence_items)
    breakdown = calculator.calculate_all(mapping_results)
    gap_analysis = analyzer.analyze_gaps(breakdown)

    # Determine output directory
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(settings.reporting.output_dir)

    output_path.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        # JSON export
        exporter = JsonExporter(
            version=__version__,
            organization=settings.reporting.company_name,
        )
        export_result = exporter.export_full(
            maturity=breakdown,
            gaps=gap_analysis,
            output_dir=output_path,
        )
        if export_result.success:
            output(f"JSON report generated: {export_result.path}")
        else:
            output_error(f"Error: {export_result.error}")
            return 1

    elif args.format == "html" or (args.format == "pdf" and not WEASYPRINT_AVAILABLE):
        # HTML report (or fallback from PDF)
        if args.format == "pdf" and not WEASYPRINT_AVAILABLE:
            output("Warning: weasyprint not installed. Generating HTML instead.")
            output("Install with: pip install weasyprint")

        config = ReportConfig(
            organization=settings.reporting.company_name or "Organization",
        )
        generator = PdfReportGenerator(config)
        report_result = generator.generate_report(
            maturity=breakdown,
            gaps=gap_analysis,
            output_dir=output_path,
        )
        if report_result.success:
            output(f"HTML report generated: {report_result.html_path}")
        else:
            output_error(f"Error: {report_result.error}")
            return 1

    else:
        # PDF report
        config = ReportConfig(
            organization=settings.reporting.company_name or "Organization",
        )
        generator = PdfReportGenerator(config)
        report_result = generator.generate_report(
            maturity=breakdown,
            gaps=gap_analysis,
            output_dir=output_path,
        )
        if report_result.success:
            output(f"PDF report generated: {report_result.pdf_path}")
            output(f"HTML report generated: {report_result.html_path}")
        else:
            output_error(f"Error: {report_result.error}")
            return 1

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Export data to JSON."""
    from nisify.analysis import GapAnalyzer
    from nisify.nist import MappingEngine, MaturityCalculator
    from nisify.reports import JsonExporter
    from nisify.storage import EvidenceStore

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Initialize components
    store = EvidenceStore(Path(settings.data_dir))

    # Determine output directory
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(settings.reporting.output_dir)

    output_path.mkdir(parents=True, exist_ok=True)

    exporter = JsonExporter(
        version=__version__,
        organization=settings.reporting.company_name,
    )

    output(f"Exporting {args.type} data...")

    if args.type == "evidence":
        # Export evidence only
        evidence_items = store.get_all_evidence()
        evidence_dicts = [
            {
                "platform": e.platform,
                "evidence_type": e.evidence_type,
                "collected_at": e.collected_at.isoformat() if e.collected_at else None,
                "data": store.get_evidence_data(e.id),
            }
            for e in evidence_items
        ]
        result = exporter.export_evidence(
            evidence_items=evidence_dicts,
            output_dir=output_path,
            compress=args.compress,
        )

    elif args.type == "maturity":
        # Export maturity only
        mapping_engine = MappingEngine()
        calculator = MaturityCalculator()

        evidence_items = store.get_all_evidence()
        mapping_results = mapping_engine.map_all_evidence(evidence_items)
        breakdown = calculator.calculate_all(mapping_results)

        result = exporter.export_maturity(
            breakdown=breakdown,
            output_dir=output_path,
            compress=args.compress,
        )

    elif args.type == "gaps":
        # Export gaps only
        mapping_engine = MappingEngine()
        calculator = MaturityCalculator()
        analyzer = GapAnalyzer()

        evidence_items = store.get_all_evidence()
        mapping_results = mapping_engine.map_all_evidence(evidence_items)
        breakdown = calculator.calculate_all(mapping_results)
        gap_analysis = analyzer.analyze_gaps(breakdown)

        result = exporter.export_gaps(
            gap_analysis=gap_analysis,
            output_dir=output_path,
            compress=args.compress,
        )

    else:
        # Export full
        mapping_engine = MappingEngine()
        calculator = MaturityCalculator()
        analyzer = GapAnalyzer()

        evidence_items = store.get_all_evidence()
        evidence_dicts = [
            {
                "platform": e.platform,
                "evidence_type": e.evidence_type,
                "collected_at": e.collected_at.isoformat() if e.collected_at else None,
                "data": store.get_evidence_data(e.id),
            }
            for e in evidence_items
        ]

        mapping_results = mapping_engine.map_all_evidence(evidence_items)
        breakdown = calculator.calculate_all(mapping_results)
        gap_analysis = analyzer.analyze_gaps(breakdown)

        result = exporter.export_full(
            maturity=breakdown,
            gaps=gap_analysis,
            evidence=evidence_dicts,
            output_dir=output_path,
            compress=args.compress,
        )

    if result.success:
        output(f"Export complete: {result.path}")
        output(f"Size: {result.size_bytes:,} bytes")
        output(f"Records: {result.record_count}")
    else:
        output_error(f"Error: {result.error}")
        return 1

    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Start local dashboard server."""
    import signal

    from nisify.analysis import GapAnalyzer
    from nisify.dashboard import DashboardServer, find_available_port
    from nisify.nist import MappingEngine, MaturityCalculator
    from nisify.storage import EvidenceStore

    # PID file location
    pid_file = DEFAULT_CONFIG_DIR / "dashboard.pid"

    # Handle --status command
    if args.status:
        if not pid_file.exists():
            output("Dashboard server is not running")
            return 1

        pid = int(pid_file.read_text().strip())
        try:
            # Check if process is actually running
            os.kill(pid, 0)
            output(f"Dashboard server is running (PID: {pid})")
            return 0
        except ProcessLookupError:
            output("Dashboard server is not running (stale PID file)")
            pid_file.unlink(missing_ok=True)
            return 1
        except PermissionError:
            # Process exists but we don't have permission to signal it
            output(f"Dashboard server is running (PID: {pid})")
            return 0

    # Handle --stop command
    if args.stop:
        if not pid_file.exists():
            output("No background dashboard server running")
            return 1

        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            pid_file.unlink(missing_ok=True)
            output(f"Dashboard server stopped (PID: {pid})")
            return 0
        except ProcessLookupError:
            pid_file.unlink(missing_ok=True)
            output("Dashboard server was not running (stale PID file removed)")
            return 1
        except PermissionError:
            output_error(f"Error: Permission denied to stop process {pid}")
            return 1

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Check if a background server is already running
    if pid_file.exists():
        pid = int(pid_file.read_text().strip())
        try:
            os.kill(pid, 0)
            output(f"Dashboard server is already running (PID: {pid})")
            output("Use 'nisify dashboard --stop' to stop it first")
            return 1
        except ProcessLookupError:
            # Stale PID file, remove it
            pid_file.unlink(missing_ok=True)

    output("Nisify Dashboard")
    output("=" * 50)
    output()

    # Initialize components
    store = EvidenceStore(Path(settings.data_dir))

    # Load and analyze data
    output_verbose("Loading data...")
    evidence_items = store.get_all_evidence()

    maturity_breakdown = None
    gap_analysis = None

    if evidence_items:
        mapping_engine = MappingEngine()
        calculator = MaturityCalculator()
        analyzer = GapAnalyzer()

        # Calculate maturity
        mapping_results = mapping_engine.map_all_evidence(evidence_items)
        maturity_breakdown = calculator.calculate_all(mapping_results)

        # Analyze gaps
        gap_analysis = analyzer.analyze_gaps(maturity_breakdown)

        # Note: Trend analysis requires full MaturityBreakdown history which
        # is not currently stored. The store only saves MaturitySnapshot records.
        # Future enhancement: aggregate snapshots into breakdowns for trends.

        output(f"  Evidence items: {len(evidence_items)}")
        output(f"  Overall maturity: Level {maturity_breakdown.overall.level} ({maturity_breakdown.overall.score:.2f}/4.0)")
        if gap_analysis:
            output(f"  Gaps identified: {gap_analysis.controls_with_gaps}")
    else:
        output("  No evidence collected yet.")
        output("  Run 'nisify collect --all' to gather evidence.")

    output()

    # Check if requested port is available
    host = args.host
    port = args.port

    try:
        port = find_available_port(port)
        if port != args.port:
            output(f"Port {args.port} is in use, using port {port}")
    except RuntimeError as e:
        output_error(f"Error: {e}")
        return 1

    # Create and configure server
    server = DashboardServer(host=host, port=port)

    server.update_data(
        maturity=maturity_breakdown,
        gaps=gap_analysis,
        trends=None,  # Trend analysis not yet implemented
        evidence_store=store,
        organization_name=settings.reporting.company_name or "Organization",
    )

    # Handle background mode
    if args.background:
        pid = os.fork()
        if pid > 0:
            # Parent process
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(pid))
            output(f"Dashboard started in background (PID: {pid})")
            output(f"URL: http://{host}:{port}/")
            output()
            output("To stop: nisify dashboard --stop")
            output("To check status: nisify dashboard --status")
            return 0
        else:
            # Child process - detach from terminal
            os.setsid()
            # Redirect standard file descriptors to /dev/null
            sys.stdin.close()
            sys.stdout = open(os.devnull, 'w')
            sys.stderr = open(os.devnull, 'w')
            # Start server (blocking in child)
            server.start(blocking=True)
            return 0

    # Foreground mode
    output(f"Starting dashboard server at http://{host}:{port}/")
    output()
    output("Dashboard features:")
    output("  - /           Overview and quick stats")
    output("  - /dashboard  Detailed maturity scores")
    output("  - /gaps       Gap analysis and recommendations")
    output("  - /evidence   Evidence browser")
    output("  - /trends     Historical trends")
    output()
    output("Press Ctrl+C to stop the server.")
    output()

    try:
        # Start in blocking mode
        server.start(blocking=True)
    except KeyboardInterrupt:
        output()
        output("Shutting down dashboard...")
        server.stop()

    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    """Configure scheduled collection."""
    from nisify.scheduler import (
        Scheduler,
        SchedulerAlreadyRunningError,
        SchedulerError,
        SchedulerNotRunningError,
        get_cron_help,
    )

    # Handle cron help first (doesn't require initialization)
    if args.cron_help:
        output(get_cron_help())
        return 0

    credential_store = CredentialStore()

    if not credential_store.is_initialized():
        output_error("Error: Nisify not initialized. Run 'nisify init' first.")
        return 1

    scheduler = Scheduler()

    # Handle logs display
    if args.logs:
        output("Scheduler Logs")
        output("=" * 50)
        output()
        logs = scheduler.get_logs(lines=50)
        if logs:
            for line in logs:
                output(line.rstrip())
        else:
            output("No scheduler logs found.")
        return 0

    # Handle daemon start
    if args.start_daemon:
        status = scheduler.get_schedule_status()
        if not status.enabled:
            output_error("Error: No schedule is installed.")
            output("First enable a schedule with: nisify schedule --interval daily --enable")
            return 1

        passphrase = os.environ.get("NISIFY_PASSPHRASE")
        if not passphrase:
            passphrase = getpass.getpass("Enter passphrase for scheduled collection: ")

        try:
            credential_store.unlock(passphrase)
            credential_store.lock()
        except InvalidPassphraseError:
            output_error("Error: Invalid passphrase.")
            return 1

        try:
            if args.foreground:
                output("Starting scheduler daemon in foreground mode...")
                output("Press Ctrl+C to stop.")
                output()
                scheduler.start_daemon(passphrase=passphrase, foreground=True)
            else:
                scheduler.start_daemon(passphrase=passphrase, foreground=False)
                status = scheduler.get_schedule_status()
                output("Scheduler daemon started.")
                if status.pid:
                    output(f"PID: {status.pid}")
        except SchedulerAlreadyRunningError as e:
            output_error(f"Error: {e}")
            return 1
        except SchedulerError as e:
            output_error(f"Error starting daemon: {e}")
            return 1

        return 0

    # Handle daemon stop
    if args.stop_daemon:
        try:
            scheduler.stop_daemon()
            output("Scheduler daemon stopped.")
            return 0
        except SchedulerNotRunningError:
            output("Scheduler daemon is not running.")
            return 0
        except SchedulerError as e:
            output_error(f"Error stopping daemon: {e}")
            return 1

    # If no action specified, show current status
    if not args.enable and not args.disable and not args.interval:
        status = scheduler.get_schedule_status()

        output("Scheduler Status")
        output("=" * 50)
        output()

        if status.enabled:
            output("Status: ENABLED")
            output(f"Interval: {status.interval}")
            output(f"Mode: {status.mode}")
            output()
            if status.next_run:
                output(f"Next run: {status.next_run.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if status.last_run:
                output(f"Last run: {status.last_run.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                if status.last_run_success is not None:
                    result = "SUCCESS" if status.last_run_success else "FAILED"
                    output(f"Last result: {result}")
                    if status.last_run_error:
                        output(f"Error: {status.last_run_error}")
            if status.mode == "built_in" and status.pid:
                output(f"Daemon PID: {status.pid}")
        else:
            output("Status: DISABLED")
            output()
            output("To enable scheduled collection:")
            output("  nisify schedule --interval daily --enable")
            output()
            output("Available intervals:")
            output("  - hourly: Collect every hour at minute 0")
            output("  - daily:  Collect daily at 2:00 AM UTC")
            output("  - weekly: Collect weekly on Sunday at 2:00 AM UTC")

        return 0

    # Handle disable
    if args.disable:
        try:
            status = scheduler.uninstall_schedule()
            output("Scheduler disabled.")
            output()
            output("Cron entries removed and daemon stopped (if running).")
            return 0
        except SchedulerError as e:
            output_error(f"Error disabling scheduler: {e}")
            return 1

    # Handle enable
    if args.enable:
        # Need an interval to enable
        interval = args.interval or "daily"

        output(f"Enabling scheduled collection ({interval})")
        output()

        # For built-in scheduler, we need the passphrase
        passphrase = getpass.getpass(
            "Enter passphrase (required for scheduled collection): "
        )

        try:
            credential_store.unlock(passphrase)
            credential_store.lock()  # Just verify it works
        except InvalidPassphraseError:
            output_error("Error: Invalid passphrase.")
            return 1

        try:
            status = scheduler.install_schedule(interval)
        except SchedulerError as e:
            output_error(f"Error installing schedule: {e}")
            return 1

        output("Schedule installed.")
        output()
        output(f"Mode: {status.mode}")
        output(f"Interval: {status.interval}")
        if status.next_run:
            output(f"Next run: {status.next_run.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        output()

        if status.mode == "built_in":
            output("Built-in scheduler selected.")
            output()
            output("To start the scheduler daemon:")
            output("  1. Set the NISIFY_PASSPHRASE environment variable")
            output("  2. Run: nisify schedule --start-daemon")
            output()
            output("Or run in foreground mode for testing:")
            output("  NISIFY_PASSPHRASE='...' nisify schedule --start-daemon --foreground")
        else:
            output("System cron selected.")
            output("The schedule has been added to your crontab.")
            output()
            output("Note: For scheduled collection to work, the NISIFY_PASSPHRASE")
            output("environment variable must be set in your cron environment.")
            output()
            output("To view crontab: crontab -l")

        return 0

    # Handle interval change without enable/disable
    if args.interval:
        status = scheduler.get_schedule_status()
        if not status.enabled:
            output_error("Error: Scheduler not enabled. Use --enable to enable it.")
            output("  Example: nisify schedule --interval daily --enable")
            return 1

        try:
            status = scheduler.install_schedule(args.interval)
            output(f"Schedule updated to {args.interval}.")
            if status.next_run:
                output(f"Next run: {status.next_run.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        except SchedulerError as e:
            output_error(f"Error updating schedule: {e}")
            return 1

    return 0


def cmd_test_connection(args: argparse.Namespace) -> int:
    """Test platform connectivity."""
    from nisify.collectors import (
        AwsCollector,
        DatadogCollector,
        GitLabCollector,
        GoogleCollector,
        JamfCollector,
        JiraCollector,
        NotionCollector,
        OktaCollector,
        SlabCollector,
        SnowflakeCollector,
        SpotDraftCollector,
        ZendeskCollector,
        ZoomCollector,
    )

    credential_store = CredentialStore()

    if not credential_store.is_initialized():
        output_error("Error: Nisify not initialized. Run 'nisify init' first.")
        return 1

    # Load configuration
    try:
        config_path = Path(args.config) if hasattr(args, 'config') and args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Unlock credentials
    passphrase = getpass.getpass("Enter passphrase to unlock credentials: ")
    try:
        credential_store.unlock(passphrase)
    except InvalidPassphraseError:
        output_error("Error: Invalid passphrase.")
        return 1

    platform = args.platform.lower()
    output(f"Testing connection to {platform.upper()}...")
    output()

    # Get credentials
    credentials = get_credentials_for_platform(platform, credential_store)

    if not credentials:
        credential_store.lock()
        output_error(f"Error: No credentials configured for {platform}")
        output(f"Run 'nisify configure --platform {platform}' to set up credentials.")
        return 1

    # Collector mapping
    collector_classes = {
        "aws": AwsCollector,
        "okta": OktaCollector,
        "jamf": JamfCollector,
        "google": GoogleCollector,
        "snowflake": SnowflakeCollector,
        "datadog": DatadogCollector,
        "gitlab": GitLabCollector,
        "jira": JiraCollector,
        "zendesk": ZendeskCollector,
        "zoom": ZoomCollector,
        "notion": NotionCollector,
        "slab": SlabCollector,
        "spotdraft": SpotDraftCollector,
    }

    collector_class = collector_classes.get(platform)
    if not collector_class:
        credential_store.lock()
        output_error(f"Error: Unknown platform {platform}")
        return 1

    try:
        collector = collector_class(settings, credential_store)  # type: ignore[abstract]
        success = collector.test_connection()
        credential_store.lock()

        if success:
            output(f"Connection to {platform.upper()} successful!")
            return 0
        else:
            output(f"Connection to {platform.upper()} failed.")
            return 1

    except Exception as e:
        credential_store.lock()
        output_error(f"Connection error: {e}")
        return 1


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Clean up old evidence and data based on retention policy."""
    from nisify.storage import EvidenceStore

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    # Determine retention days
    retention_days = args.days if args.days is not None else settings.collection.retention_days

    output("Evidence Cleanup")
    output("=" * 50)
    output()
    output(f"Retention period: {retention_days} days")
    output(f"Data directory: {settings.data_dir}")
    output()

    # Initialize store
    store = EvidenceStore(Path(settings.data_dir))

    # Get cleanup candidates
    output("Analyzing evidence for cleanup...")
    cleanup_info = store.get_cleanup_candidates(retention_days)

    if not cleanup_info["files"]:
        output()
        output("No evidence files older than retention period.")
        output("Nothing to clean up.")
        return 0

    # Show what would be deleted
    output()
    output(f"Files to remove: {cleanup_info['file_count']}")
    output(f"Total size: {cleanup_info['total_size_bytes']:,} bytes ({cleanup_info['total_size_bytes'] / 1024 / 1024:.2f} MB)")
    output()

    if args.dry_run:
        output("Dry run - no files will be deleted.")
        output()
        output("Files that would be removed:")
        for file_info in cleanup_info["files"][:20]:
            output(f"  {file_info['path']} ({file_info['age_days']} days old)")
        if len(cleanup_info["files"]) > 20:
            output(f"  ... and {len(cleanup_info['files']) - 20} more files")
        return 0

    # Confirmation
    if not args.force:
        output("This action cannot be undone.")
        response = input("Proceed with cleanup? [y/N]: ").strip().lower()
        if response not in ("y", "yes"):
            output("Cleanup cancelled.")
            return 0

    # Perform cleanup
    output()
    output("Cleaning up...")
    result = store.cleanup_old_evidence(retention_days, archive=True)

    output()
    output("Cleanup complete:")
    output(f"  Files removed: {result['files_removed']}")
    output(f"  Space freed: {result['bytes_freed']:,} bytes ({result['bytes_freed'] / 1024 / 1024:.2f} MB)")
    if result.get("archive_path"):
        output(f"  Archive created: {result['archive_path']}")
    if result.get("database_rows_removed"):
        output(f"  Database records cleaned: {result['database_rows_removed']}")

    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    """Create a backup of Nisify data."""
    from nisify.backup import BackupManager

    # Load configuration
    try:
        config_path = Path(args.config) if args.config else None
        settings = load_config(config_path)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        return 1

    output("Nisify Backup")
    output("=" * 50)
    output()

    # Determine output path
    output_path = Path(args.output) if args.output else Path.cwd()

    # Initialize backup manager
    manager = BackupManager(
        config_dir=DEFAULT_CONFIG_DIR,
        data_dir=Path(settings.data_dir),
    )

    # Show what will be backed up
    output(f"Configuration directory: {DEFAULT_CONFIG_DIR}")
    output(f"Data directory: {settings.data_dir}")
    output(f"Output directory: {output_path}")
    output(f"Include credentials: {args.include_credentials}")
    output()

    output("Creating backup...")
    result = manager.create_backup(
        output_path=output_path,
        include_credentials=args.include_credentials,
    )

    if result.success:
        output()
        output("Backup created successfully!")
        output()
        output(f"  File: {result.path}")
        output(f"  Size: {result.size_bytes:,} bytes ({result.size_bytes / 1024 / 1024:.2f} MB)")
        if result.manifest:
            output(f"  Files: {len(result.manifest.files)}")
            stats = result.manifest.evidence_stats
            output(f"  Evidence items: {stats.get('total', 0)}")
            if stats.get("by_platform"):
                for platform, count in sorted(stats["by_platform"].items()):
                    output(f"    - {platform}: {count}")
        output()
        output("To restore from this backup, run:")
        output(f"  nisify restore {result.path}")
        return 0
    else:
        output()
        output_error(f"Backup failed: {result.error}")
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore from a backup archive."""
    from nisify.backup import BackupManager

    backup_path = Path(args.backup_file)

    if not backup_path.exists():
        output_error(f"Error: Backup file not found: {backup_path}")
        return 1

    output("Nisify Restore")
    output("=" * 50)
    output()
    output(f"Backup file: {backup_path}")
    output()

    # Initialize backup manager with default paths
    manager = BackupManager(
        config_dir=DEFAULT_CONFIG_DIR,
        data_dir=DEFAULT_CONFIG_DIR / "data",
    )

    # Get backup info
    manifest = manager.get_backup_info(backup_path)
    if manifest:
        output("Backup information:")
        output(f"  Created: {manifest.created_at}")
        output(f"  Version: {manifest.version}")
        if manifest.organization:
            output(f"  Organization: {manifest.organization}")
        output(f"  Files: {len(manifest.files)}")
        output(f"  Evidence items: {manifest.evidence_stats.get('total', 0)}")
        output(f"  Includes credentials: {manifest.includes_credentials}")
        output()

    # Verify backup
    output("Verifying backup integrity...")
    valid, errors = manager.verify_backup(backup_path)

    if not valid:
        output()
        output_error("Backup verification failed:")
        for error in errors:
            output(f"  - {error}")
        return 1

    output("Backup verified successfully.")
    output()

    if args.verify_only:
        output("Verification complete (--verify-only specified)")
        return 0

    # Confirmation
    if not args.force:
        output("WARNING: This will overwrite existing Nisify data.")
        if not args.no_backup:
            output("(A backup of existing data will be created first)")
        output()
        response = input("Proceed with restore? [y/N]: ").strip().lower()
        if response not in ("y", "yes"):
            output("Restore cancelled.")
            return 0

    # Perform restore
    output()
    output("Restoring...")
    result = manager.restore_backup(
        backup_path=backup_path,
        backup_existing=not args.no_backup,
    )

    if result.success:
        output()
        output("Restore completed successfully!")
        output()
        output(f"  Files restored: {result.files_restored}")
        output(f"  Evidence items: {result.evidence_count}")
        if result.backup_created:
            output(f"  Previous data backed up to: {result.backup_created}")
        return 0
    else:
        output()
        output_error(f"Restore failed: {result.error}")
        return 1


def cmd_submit(args: argparse.Namespace) -> int:
    """Submit manual evidence for NIST CSF controls."""
    from nisify.collectors.base import Evidence
    from nisify.nist import get_subcategory
    from nisify.storage import EvidenceStore

    # Handle --list-types flag
    if args.list_types:
        output("Manual Evidence Types")
        output("=" * 50)
        output()
        output("Common evidence types for manual submission:")
        output()
        evidence_types = [
            ("policy_document", "Security policies, standards, procedures"),
            ("security_policy", "Information security policy document"),
            ("risk_register", "Risk register or risk assessment"),
            ("risk_assessment", "Risk assessment report"),
            ("board_minutes", "Board meeting minutes related to security"),
            ("governance_charter", "Security governance charter"),
            ("raci_matrix", "Roles and responsibilities matrix"),
            ("job_descriptions", "Security role job descriptions"),
            ("budget_allocation", "Security budget documentation"),
            ("hr_policy", "HR security policies"),
            ("compliance_register", "Regulatory compliance register"),
            ("vendor_inventory", "Third-party vendor inventory"),
            ("vendor_assessment", "Vendor security assessment"),
            ("contract_inventory", "Contract management records"),
            ("incident_response_plan", "Incident response procedures"),
            ("business_continuity_plan", "BC/DR plan documentation"),
            ("training_records", "Security awareness training records"),
            ("audit_report", "Internal or external audit reports"),
            ("penetration_test", "Penetration test results"),
            ("vulnerability_scan", "Vulnerability scan reports"),
        ]
        for etype, desc in evidence_types:
            output(f"  {etype:25} - {desc}")
        output()
        output("Use --type <evidence_type> to specify the type when submitting.")
        return 0

    # Validate required arguments when not listing types
    if not args.control:
        output_error("--control is required (use --list-types to see evidence types)")
        return 1
    if not args.type:
        output_error("--type is required (use --list-types to see evidence types)")
        return 1

    # Validate control ID
    control_id = args.control.upper()
    subcategory = get_subcategory(control_id)
    if not subcategory:
        output_error(f"Unknown control ID: {control_id}")
        output_error("Use 'nisify maturity --list-controls' to see valid control IDs")
        return 1

    evidence_type = args.type
    file_path = args.file
    description = args.description
    url = args.url

    # Need either file or URL
    if not file_path and not url:
        output_error("Must provide either --file or --url for evidence")
        return 1

    output("Manual Evidence Submission")
    output("=" * 50)
    output()
    output(f"Control: {control_id} - {subcategory.name}")
    output(f"Type: {evidence_type}")

    # Build evidence data
    raw_data: dict[str, Any] = {
        "control_id": control_id,
        "control_name": subcategory.name,
        "evidence_type": evidence_type,
        "submitted_at": datetime.now(UTC).isoformat(),
        "manual_submission": True,
    }

    if description:
        raw_data["description"] = description
        output(f"Description: {description}")

    if url:
        raw_data["reference_url"] = url
        output(f"URL: {url}")

    if file_path:
        if not file_path.exists():
            output_error(f"File not found: {file_path}")
            return 1

        output(f"File: {file_path}")

        # Read file content
        file_size = file_path.stat().st_size
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            output_error("File too large (max 10MB)")
            return 1

        raw_data["file_name"] = file_path.name
        raw_data["file_size"] = file_size

        # For JSON files, parse and include content
        if file_path.suffix.lower() == ".json":
            try:
                with open(file_path) as f:
                    raw_data["file_content"] = json.load(f)
            except json.JSONDecodeError as e:
                output_error(f"Invalid JSON file: {e}")
                return 1
        # For text files, include content
        elif file_path.suffix.lower() in (".txt", ".md", ".yaml", ".yml"):
            try:
                raw_data["file_content"] = file_path.read_text()
            except UnicodeDecodeError:
                output_error("Cannot read file as text")
                return 1
        # For PDFs and other binary files, store hash reference
        else:
            import hashlib

            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            raw_data["file_hash"] = file_hash
            raw_data["file_type"] = file_path.suffix.lower()

    output()

    # Create evidence object
    evidence = Evidence.create(
        platform="manual",
        evidence_type=evidence_type,
        raw_data=raw_data,
        metadata={
            "control_id": control_id,
            "submission_method": "cli",
        },
    )

    # Store evidence
    try:
        settings = load_config()
        store = EvidenceStore(Path(settings.data_dir))
        stored = store.store_evidence(evidence)

        output("Evidence submitted successfully!")
        output()
        output(f"  Evidence ID: {evidence.id}")
        output(f"  Stored at: {stored.file_path}")
        output(f"  Hash: {stored.file_hash[:16]}...")
        output()
        output("The evidence will be included in maturity calculations.")
        output("Run 'nisify maturity' to see updated scores.")

        return 0

    except Exception as e:
        output_error(f"Failed to store evidence: {e}")
        logger.exception("Evidence submission failed")
        return 1


def cmd_demo(args: argparse.Namespace) -> int:
    """Generate demo data for quick evaluation."""
    from nisify.demo import generate_demo_data

    output("Nisify Demo Data Generator")
    output("=" * 50)
    output()

    profile = args.profile
    organization = args.organization
    days = args.days
    platforms = args.platforms

    output(f"Profile: {profile}")
    if organization:
        output(f"Organization: {organization}")
    output(f"Days of history: {days}")
    if platforms:
        output(f"Platforms: {', '.join(platforms)}")
    else:
        output("Platforms: all (aws, okta, jamf, google)")
    output()

    output("Generating demo data...")
    output("(This may take a minute for longer time periods)")
    output()

    try:
        summary = generate_demo_data(
            profile=profile,
            organization=organization,
            days=days,
            platforms=platforms,
        )

        output("Demo data generated successfully!")
        output()
        output("Summary:")
        output(f"  Organization: {summary['organization']}")
        output(f"  Profile: {summary['profile']}")
        output(f"  Platforms: {', '.join(summary['platforms'])}")
        output(f"  Days of history: {summary['days_of_history']}")
        output(f"  Evidence items: {summary['evidence_items']}")
        output(f"  Control mappings: {summary['control_mappings']}")
        output(f"  Maturity snapshots: {summary['maturity_snapshots']}")
        output()

        if args.dashboard:
            output("Starting dashboard...")
            output()
            # Import and start dashboard
            from nisify.dashboard import DashboardServer

            server = DashboardServer()
            output(f"Dashboard running at: http://127.0.0.1:8080")
            output("Press Ctrl+C to stop")
            output()
            server.start(blocking=True)
        else:
            output("Next steps:")
            output("  1. Run 'nisify dashboard' to view the demo data")
            output("  2. Run 'nisify maturity' to see maturity scores")
            output("  3. Run 'nisify gaps' to see compliance gaps")
            output("  4. Run 'nisify report --format html' to generate a report")
            output()
            output("Or add --dashboard to this command to start immediately:")
            output(f"  nisify demo --profile {profile} --dashboard")

        return 0

    except Exception as e:
        output_error(f"Error generating demo data: {e}")
        logger.exception("Demo data generation failed")
        return 1


def main() -> NoReturn:
    """Main entry point for Nisify CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Set up logging and output mode
    setup_logging(args.verbose, args.quiet)
    set_output_mode(args.quiet, args.verbose)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    try:
        exit_code = args.func(args)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        output("\nOperation cancelled.")
        sys.exit(130)
    except (CredentialStoreNotInitializedError, CredentialStoreLockedError) as e:
        output_error(f"Credential error: {e}")
        sys.exit(2)
    except ConfigurationError as e:
        output_error(f"Configuration error: {e}")
        sys.exit(2)
    except Exception as e:
        if args.verbose > 0:
            raise
        output_error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
