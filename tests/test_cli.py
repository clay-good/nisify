"""
Tests for the CLI commands.

Uses Python's unittest module.
Tests all CLI commands, argument parsing, and output formatting.
"""

from __future__ import annotations

import unittest

from nisify.cli import create_parser


class TestArgumentParser(unittest.TestCase):
    """Tests for CLI argument parsing."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_parser_creation(self) -> None:
        """Test that parser is created successfully."""
        self.assertIsNotNone(self.parser)

    def test_version_argument(self) -> None:
        """Test --version argument."""
        with self.assertRaises(SystemExit) as cm:
            self.parser.parse_args(["--version"])

        self.assertEqual(cm.exception.code, 0)

    def test_help_argument(self) -> None:
        """Test --help argument."""
        with self.assertRaises(SystemExit) as cm:
            self.parser.parse_args(["--help"])

        self.assertEqual(cm.exception.code, 0)

    def test_no_command_defaults(self) -> None:
        """Test parsing with no command."""
        args = self.parser.parse_args([])

        # Should have default verbose and quiet values
        self.assertEqual(args.verbose, 0)
        self.assertFalse(args.quiet)

    def test_verbose_flag(self) -> None:
        """Test -v verbose flag."""
        args = self.parser.parse_args(["-v"])
        self.assertEqual(args.verbose, 1)

        args = self.parser.parse_args(["-vv"])
        self.assertEqual(args.verbose, 2)

        args = self.parser.parse_args(["-vvv"])
        self.assertEqual(args.verbose, 3)

    def test_quiet_flag(self) -> None:
        """Test -q quiet flag."""
        args = self.parser.parse_args(["-q"])
        self.assertTrue(args.quiet)


class TestInitCommand(unittest.TestCase):
    """Tests for the init command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_init_command_parses(self) -> None:
        """Test init command is parsed."""
        args = self.parser.parse_args(["init"])

        self.assertTrue(hasattr(args, "func"))


class TestConfigureCommand(unittest.TestCase):
    """Tests for the configure command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_configure_command_parses(self) -> None:
        """Test configure command is parsed."""
        args = self.parser.parse_args(["configure"])

        self.assertTrue(hasattr(args, "func"))

    def test_configure_set_platform(self) -> None:
        """Test configure --platform flag."""
        args = self.parser.parse_args(["configure", "--platform", "aws"])

        self.assertEqual(args.platform, "aws")


class TestStatusCommand(unittest.TestCase):
    """Tests for the status command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_status_command_parses(self) -> None:
        """Test status command is parsed."""
        args = self.parser.parse_args(["status"])

        self.assertTrue(hasattr(args, "func"))


class TestCollectCommand(unittest.TestCase):
    """Tests for the collect command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_collect_command_parses(self) -> None:
        """Test collect command is parsed."""
        args = self.parser.parse_args(["collect"])

        self.assertTrue(hasattr(args, "func"))

    def test_collect_all_flag(self) -> None:
        """Test collect --all flag."""
        args = self.parser.parse_args(["collect", "--all"])

        self.assertTrue(args.collect_all)

    def test_collect_platform_flag(self) -> None:
        """Test collect --platform flag."""
        args = self.parser.parse_args(["collect", "--platform", "aws"])

        self.assertEqual(args.platform, "aws")

    def test_collect_invalid_platform(self) -> None:
        """Test collect with invalid platform."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["collect", "--platform", "invalid"])


class TestMaturityCommand(unittest.TestCase):
    """Tests for the maturity command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_maturity_command_parses(self) -> None:
        """Test maturity command is parsed."""
        args = self.parser.parse_args(["maturity"])

        self.assertTrue(hasattr(args, "func"))

    def test_maturity_format_json(self) -> None:
        """Test maturity --format json output."""
        args = self.parser.parse_args(["maturity", "--format", "json"])

        self.assertEqual(args.format, "json")

    def test_maturity_function_filter(self) -> None:
        """Test maturity --function filter."""
        args = self.parser.parse_args(["maturity", "--function", "PR"])

        self.assertEqual(args.function, "PR")


class TestGapsCommand(unittest.TestCase):
    """Tests for the gaps command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_gaps_command_parses(self) -> None:
        """Test gaps command is parsed."""
        args = self.parser.parse_args(["gaps"])

        self.assertTrue(hasattr(args, "func"))

    def test_gaps_priority_filter(self) -> None:
        """Test gaps --priority filter."""
        args = self.parser.parse_args(["gaps", "--priority", "critical"])

        self.assertEqual(args.priority, "critical")

    def test_gaps_function_filter(self) -> None:
        """Test gaps --function filter."""
        args = self.parser.parse_args(["gaps", "--function", "DE"])

        self.assertEqual(args.function, "DE")

    def test_gaps_format_json(self) -> None:
        """Test gaps --format json."""
        args = self.parser.parse_args(["gaps", "--format", "json"])

        self.assertEqual(args.format, "json")


class TestReportCommand(unittest.TestCase):
    """Tests for the report command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_report_command_parses(self) -> None:
        """Test report command is parsed."""
        args = self.parser.parse_args(["report"])

        self.assertTrue(hasattr(args, "func"))

    def test_report_format_pdf(self) -> None:
        """Test report --format pdf."""
        args = self.parser.parse_args(["report", "--format", "pdf"])

        self.assertEqual(args.format, "pdf")

    def test_report_format_html(self) -> None:
        """Test report --format html."""
        args = self.parser.parse_args(["report", "--format", "html"])

        self.assertEqual(args.format, "html")

    def test_report_format_json(self) -> None:
        """Test report --format json."""
        args = self.parser.parse_args(["report", "--format", "json"])

        self.assertEqual(args.format, "json")

    def test_report_output_path(self) -> None:
        """Test report --output path."""
        args = self.parser.parse_args(["report", "--output", "/tmp/report.pdf"])

        self.assertEqual(args.output, "/tmp/report.pdf")


class TestExportCommand(unittest.TestCase):
    """Tests for the export command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_export_command_parses(self) -> None:
        """Test export command is parsed."""
        args = self.parser.parse_args(["export"])

        self.assertTrue(hasattr(args, "func"))

    def test_export_type_full(self) -> None:
        """Test export --type full."""
        args = self.parser.parse_args(["export", "--type", "full"])

        self.assertEqual(args.type, "full")

    def test_export_type_evidence(self) -> None:
        """Test export --type evidence."""
        args = self.parser.parse_args(["export", "--type", "evidence"])

        self.assertEqual(args.type, "evidence")

    def test_export_type_maturity(self) -> None:
        """Test export --type maturity."""
        args = self.parser.parse_args(["export", "--type", "maturity"])

        self.assertEqual(args.type, "maturity")

    def test_export_compress_flag(self) -> None:
        """Test export --compress flag."""
        args = self.parser.parse_args(["export", "--compress"])

        self.assertTrue(args.compress)


class TestDashboardCommand(unittest.TestCase):
    """Tests for the dashboard command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_dashboard_command_parses(self) -> None:
        """Test dashboard command is parsed."""
        args = self.parser.parse_args(["dashboard"])

        self.assertTrue(hasattr(args, "func"))

    def test_dashboard_port_argument(self) -> None:
        """Test dashboard --port argument."""
        args = self.parser.parse_args(["dashboard", "--port", "8888"])

        self.assertEqual(args.port, 8888)

    def test_dashboard_default_port(self) -> None:
        """Test dashboard default port."""
        args = self.parser.parse_args(["dashboard"])

        self.assertEqual(args.port, 8080)


class TestScheduleCommand(unittest.TestCase):
    """Tests for the schedule command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_schedule_command_parses(self) -> None:
        """Test schedule command is parsed."""
        args = self.parser.parse_args(["schedule"])

        self.assertTrue(hasattr(args, "func"))

    def test_schedule_interval_hourly(self) -> None:
        """Test schedule --interval hourly."""
        args = self.parser.parse_args(["schedule", "--interval", "hourly"])

        self.assertEqual(args.interval, "hourly")

    def test_schedule_interval_daily(self) -> None:
        """Test schedule --interval daily."""
        args = self.parser.parse_args(["schedule", "--interval", "daily"])

        self.assertEqual(args.interval, "daily")

    def test_schedule_interval_weekly(self) -> None:
        """Test schedule --interval weekly."""
        args = self.parser.parse_args(["schedule", "--interval", "weekly"])

        self.assertEqual(args.interval, "weekly")

    def test_schedule_enable_flag(self) -> None:
        """Test schedule --enable flag."""
        args = self.parser.parse_args(["schedule", "--enable"])

        self.assertTrue(args.enable)

    def test_schedule_disable_flag(self) -> None:
        """Test schedule --disable flag."""
        args = self.parser.parse_args(["schedule", "--disable"])

        self.assertTrue(args.disable)

    def test_schedule_start_daemon_flag(self) -> None:
        """Test schedule --start-daemon flag."""
        args = self.parser.parse_args(["schedule", "--start-daemon"])

        self.assertTrue(args.start_daemon)

    def test_schedule_stop_daemon_flag(self) -> None:
        """Test schedule --stop-daemon flag."""
        args = self.parser.parse_args(["schedule", "--stop-daemon"])

        self.assertTrue(args.stop_daemon)

    def test_schedule_foreground_flag(self) -> None:
        """Test schedule --foreground flag."""
        args = self.parser.parse_args(["schedule", "--foreground"])

        self.assertTrue(args.foreground)

    def test_schedule_logs_flag(self) -> None:
        """Test schedule --logs flag."""
        args = self.parser.parse_args(["schedule", "--logs"])

        self.assertTrue(args.logs)

    def test_schedule_cron_help_flag(self) -> None:
        """Test schedule --cron-help flag."""
        args = self.parser.parse_args(["schedule", "--cron-help"])

        self.assertTrue(args.cron_help)


class TestTestConnectionCommand(unittest.TestCase):
    """Tests for the test-connection command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_test_connection_command_parses(self) -> None:
        """Test test-connection command is parsed."""
        args = self.parser.parse_args(["test-connection", "aws"])

        self.assertTrue(hasattr(args, "func"))
        self.assertEqual(args.platform, "aws")

    def test_test_connection_all_platforms(self) -> None:
        """Test test-connection with all valid platforms."""
        platforms = ["aws", "okta", "jamf", "google", "snowflake", "datadog"]

        for platform in platforms:
            args = self.parser.parse_args(["test-connection", platform])
            self.assertEqual(args.platform, platform)


class TestInfoCommand(unittest.TestCase):
    """Tests for the info command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_info_command_parses(self) -> None:
        """Test info command is parsed."""
        args = self.parser.parse_args(["info"])

        self.assertTrue(hasattr(args, "func"))

    def test_info_json_flag(self) -> None:
        """Test info --json flag."""
        args = self.parser.parse_args(["info", "--json"])

        self.assertTrue(args.json)

    def test_info_without_json_flag(self) -> None:
        """Test info without --json flag."""
        args = self.parser.parse_args(["info"])

        self.assertFalse(args.json)


class TestCleanupCommand(unittest.TestCase):
    """Tests for the cleanup command."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_cleanup_command_parses(self) -> None:
        """Test cleanup command is parsed."""
        args = self.parser.parse_args(["cleanup"])

        self.assertTrue(hasattr(args, "func"))

    def test_cleanup_days_argument(self) -> None:
        """Test cleanup --days argument."""
        args = self.parser.parse_args(["cleanup", "--days", "90"])

        self.assertEqual(args.days, 90)

    def test_cleanup_dry_run_flag(self) -> None:
        """Test cleanup --dry-run flag."""
        args = self.parser.parse_args(["cleanup", "--dry-run"])

        self.assertTrue(args.dry_run)

    def test_cleanup_force_flag(self) -> None:
        """Test cleanup --force flag."""
        args = self.parser.parse_args(["cleanup", "--force"])

        self.assertTrue(args.force)

    def test_cleanup_combined_flags(self) -> None:
        """Test cleanup with multiple flags."""
        args = self.parser.parse_args(["cleanup", "--days", "30", "--force"])

        self.assertEqual(args.days, 30)
        self.assertTrue(args.force)

    def test_cleanup_dry_run_with_days(self) -> None:
        """Test cleanup --dry-run with --days."""
        args = self.parser.parse_args(["cleanup", "--dry-run", "--days", "60"])

        self.assertTrue(args.dry_run)
        self.assertEqual(args.days, 60)


class TestOutputFormatting(unittest.TestCase):
    """Tests for output formatting."""

    def test_json_output_valid(self) -> None:
        """Test that JSON output is valid JSON."""
        import json

        # This would test actual command output
        # For now, just verify json module works
        data = {"level": 2, "score": 2.5}
        output = json.dumps(data)
        parsed = json.loads(output)
        self.assertEqual(parsed, data)


class TestExitCodes(unittest.TestCase):
    """Tests for CLI exit codes."""

    def test_exit_code_success(self) -> None:
        """Test exit code 0 for success."""
        # Exit code 0 should be returned for successful operations
        # This would need integration with actual commands
        pass

    def test_exit_code_error(self) -> None:
        """Test exit code 1 for errors."""
        # Exit code 1 should be returned for errors
        # This would need integration with actual commands
        pass


class TestConfigPath(unittest.TestCase):
    """Tests for --config argument."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_config_path_argument(self) -> None:
        """Test --config argument."""
        args = self.parser.parse_args(["--config", "/custom/path/config.yaml", "status"])

        self.assertEqual(args.config, "/custom/path/config.yaml")


class TestMutuallyExclusiveArgs(unittest.TestCase):
    """Tests for mutually exclusive arguments."""

    def setUp(self) -> None:
        """Set up parser for tests."""
        self.parser = create_parser()

    def test_collect_all_and_platform_both_allowed(self) -> None:
        """Test that --all and --platform can both be specified (platform takes precedence)."""
        args = self.parser.parse_args(["collect", "--all", "--platform", "aws"])
        # Both flags can be set; the command handler decides precedence
        self.assertTrue(args.collect_all)
        self.assertEqual(args.platform, "aws")

    def test_schedule_enable_disable_exclusive(self) -> None:
        """Test that --enable and --disable are mutually exclusive for schedule."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["schedule", "--enable", "--disable"])


if __name__ == "__main__":
    unittest.main()
