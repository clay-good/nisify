#!/usr/bin/env python3
"""
Comprehensive Integration Test for Nisify.

This script performs a full end-to-end test of all Nisify components,
simulating a real deployment workflow without requiring actual API credentials.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Test results tracking
RESULTS = {"passed": 0, "failed": 0, "tests": []}


def log(msg: str, level: str = "INFO") -> None:
    """Print a log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {msg}")


def integration_test(name: str):
    """Decorator for test functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            log(f"Running: {name}")
            try:
                result = func(*args, **kwargs)
                if result:
                    RESULTS["passed"] += 1
                    RESULTS["tests"].append({"name": name, "status": "PASS"})
                    log(f"  PASS: {name}", "PASS")
                else:
                    RESULTS["failed"] += 1
                    RESULTS["tests"].append({"name": name, "status": "FAIL"})
                    log(f"  FAIL: {name}", "FAIL")
                # Return None to avoid pytest warning about return values
                return None
            except Exception as e:
                RESULTS["failed"] += 1
                RESULTS["tests"].append({"name": name, "status": "ERROR", "error": str(e)})
                log(f"  ERROR: {name} - {e}", "ERROR")
                import traceback
                traceback.print_exc()
                return None
        return wrapper
    return decorator


def section(title: str) -> None:
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


# =============================================================================
# SECTION 1: Module Import Tests
# =============================================================================

@integration_test("Import nisify.nist module")
def test_import_nist():
    from nisify import nist
    return hasattr(nist, 'get_all_functions')


@integration_test("Import nisify.storage module")
def test_import_storage():
    from nisify import storage
    return hasattr(storage, 'EvidenceStore')


@integration_test("Import nisify.collectors module")
def test_import_collectors():
    from nisify import collectors
    return hasattr(collectors, 'CollectorRegistry')


@integration_test("Import nisify.analysis module")
def test_import_analysis():
    from nisify import analysis
    return hasattr(analysis, 'GapAnalyzer')


@integration_test("Import nisify.reports module")
def test_import_reports():
    from nisify import reports
    return hasattr(reports, 'PdfReportGenerator')


@integration_test("Import nisify.dashboard module")
def test_import_dashboard():
    from nisify import dashboard
    return hasattr(dashboard, 'DashboardServer')


@integration_test("Import nisify.scheduler module")
def test_import_scheduler():
    from nisify import scheduler
    return hasattr(scheduler, 'Scheduler')


@integration_test("Import nisify.config module")
def test_import_config():
    from nisify import config
    return hasattr(config, 'CredentialStore')


# =============================================================================
# SECTION 2: NIST Framework Tests
# =============================================================================

@integration_test("Load all NIST functions (expect 6)")
def test_nist_functions():
    from nisify.nist import get_all_functions
    functions = get_all_functions()
    return len(functions) == 6


@integration_test("Load all NIST categories (expect 22)")
def test_nist_categories():
    from nisify.nist import get_all_categories
    categories = get_all_categories()
    return len(categories) == 22


@integration_test("Load all NIST subcategories (expect 106)")
def test_nist_subcategories():
    from nisify.nist import get_all_subcategories
    subcategories = get_all_subcategories()
    return len(subcategories) == 106


@integration_test("Get specific function (Protect)")
def test_get_function():
    from nisify.nist import get_function
    protect = get_function("PR")
    return protect is not None and protect.name == "Protect"


@integration_test("Get specific category (PR.AA)")
def test_get_category():
    from nisify.nist import get_category
    cat = get_category("PR.AA")
    return cat is not None and "Access" in cat.name


@integration_test("Get specific subcategory (PR.AA-01)")
def test_get_subcategory():
    from nisify.nist import get_subcategory
    sub = get_subcategory("PR.AA-01")
    return sub is not None


@integration_test("Initialize MappingEngine with evidence mappings")
def test_mapping_engine():
    from nisify.nist import MappingEngine
    engine = MappingEngine()
    return len(engine.mappings) > 0


@integration_test("Initialize MaturityCalculator")
def test_maturity_calculator():
    from nisify.nist import MaturityCalculator
    calc = MaturityCalculator()
    return calc is not None


# =============================================================================
# SECTION 3: Evidence Storage Tests
# =============================================================================

@integration_test("Initialize EvidenceStore in temp directory")
def test_init_store():
    global TEST_STORE_DIR, TEST_STORE
    from nisify.storage import EvidenceStore
    TEST_STORE_DIR = tempfile.mkdtemp(prefix="nisify_test_")
    TEST_STORE = EvidenceStore(data_dir=Path(TEST_STORE_DIR))
    return TEST_STORE is not None


@integration_test("Create Evidence object")
def test_create_evidence():
    global TEST_EVIDENCE
    from nisify.collectors.base import Evidence
    TEST_EVIDENCE = Evidence.create(
        platform="aws",
        evidence_type="iam_users",
        raw_data={"users": [{"name": "admin", "mfa_enabled": True}]},
    )
    return TEST_EVIDENCE.id is not None


@integration_test("Store evidence in database")
def test_store_evidence():
    global STORED_EVIDENCE
    STORED_EVIDENCE = TEST_STORE.store_evidence(TEST_EVIDENCE)
    return STORED_EVIDENCE is not None and STORED_EVIDENCE.id is not None


@integration_test("Retrieve stored evidence")
def test_retrieve_evidence():
    retrieved, data = TEST_STORE.get_evidence(STORED_EVIDENCE.id)
    return retrieved is not None and data is not None


@integration_test("Get storage statistics")
def test_storage_stats():
    stats = TEST_STORE.get_statistics()
    return stats.get("total_evidence", 0) >= 1


@integration_test("Save maturity snapshot")
def test_save_snapshot():
    from nisify.storage import MaturitySnapshot
    snapshot = MaturitySnapshot.create(
        function_id="PR",
        maturity_level=2,
        evidence_count=5,
        confidence=0.8,
    )
    TEST_STORE.save_maturity_snapshot(snapshot)
    return True


@integration_test("Retrieve maturity history")
def test_get_history():
    snapshots = TEST_STORE.get_maturity_history(function_id="PR")
    return len(snapshots) >= 1


# =============================================================================
# SECTION 4: Collector Registry Tests
# =============================================================================

@integration_test("Get all registered collectors")
def test_collector_registry():
    from nisify.collectors import CollectorRegistry
    platforms = CollectorRegistry.get_platforms()
    expected = {"aws", "okta", "jamf", "google", "snowflake", "datadog", "gitlab", "jira", "zendesk", "zoom", "notion", "slab", "spotdraft"}
    return set(platforms) == expected


@integration_test("Get AWS collector class")
def test_aws_collector():
    from nisify.collectors import CollectorRegistry
    cls = CollectorRegistry.get_collector_class("aws")
    return cls is not None and hasattr(cls, 'collect')


@integration_test("Get Okta collector class")
def test_okta_collector():
    from nisify.collectors import CollectorRegistry
    cls = CollectorRegistry.get_collector_class("okta")
    return cls is not None and hasattr(cls, 'collect')


@integration_test("Create CollectionResult object")
def test_collection_result():
    from nisify.collectors.base import CollectionResult
    result = CollectionResult(
        platform="test",
        timestamp=datetime.now(UTC),
        success=True,
        evidence_items=[TEST_EVIDENCE],
        errors=[],
        duration_seconds=1.0,
    )
    return result.success and result.evidence_count == 1


# =============================================================================
# SECTION 5: Analysis Tests
# =============================================================================

@integration_test("Initialize GapAnalyzer")
def test_gap_analyzer_init():
    from nisify.analysis import GapAnalyzer
    analyzer = GapAnalyzer()
    return analyzer is not None


@integration_test("Perform gap analysis")
def test_gap_analysis():
    from nisify.analysis import GapAnalysis, GapAnalyzer
    from nisify.nist import EntityType, MaturityBreakdown, MaturityScore

    # Create mock maturity breakdown
    def make_score(entity_id, entity_type, score):
        return MaturityScore(
            entity_id=entity_id,
            entity_type=entity_type,
            level=int(score),
            score=score,
            evidence_count=5,
            last_evidence_date=datetime.now(UTC),
            confidence=0.8,
            explanation=f"Score for {entity_id}",
        )

    maturity = MaturityBreakdown(
        timestamp=datetime.now(UTC),
        overall=make_score("overall", EntityType.OVERALL, 2.4),
        by_function={
            "GV": make_score("GV", EntityType.FUNCTION, 2.0),
            "ID": make_score("ID", EntityType.FUNCTION, 2.5),
            "PR": make_score("PR", EntityType.FUNCTION, 3.0),
            "DE": make_score("DE", EntityType.FUNCTION, 2.5),
            "RS": make_score("RS", EntityType.FUNCTION, 2.0),
            "RC": make_score("RC", EntityType.FUNCTION, 2.5),
        },
        by_category={},
        by_subcategory={},
        statistics={"evidence_coverage": 0.5},
    )

    analyzer = GapAnalyzer()
    global GAP_ANALYSIS, MATURITY_BREAKDOWN
    MATURITY_BREAKDOWN = maturity
    GAP_ANALYSIS = analyzer.analyze_gaps(maturity)
    return isinstance(GAP_ANALYSIS, GapAnalysis)


@integration_test("Initialize TrendTracker")
def test_trend_tracker_init():
    from nisify.analysis import TrendTracker
    tracker = TrendTracker()
    return tracker is not None


# =============================================================================
# SECTION 6: Report Generation Tests
# =============================================================================

@integration_test("Initialize JsonExporter")
def test_json_exporter_init():
    from nisify.reports import JsonExporter
    exporter = JsonExporter(version="0.1.0")
    return exporter is not None


@integration_test("Export full report to JSON")
def test_json_export():
    from nisify.reports import JsonExporter
    exporter = JsonExporter(version="0.1.0")
    result = exporter.export_full(MATURITY_BREAKDOWN, GAP_ANALYSIS, output_dir=Path(TEST_STORE_DIR))
    return result.success and result.path and result.path.exists()


@integration_test("Initialize ExecutiveSummaryGenerator")
def test_exec_summary_init():
    from nisify.reports import ExecutiveSummaryGenerator
    gen = ExecutiveSummaryGenerator()
    return gen is not None


@integration_test("Generate executive summary")
def test_exec_summary():
    from nisify.reports import ExecutiveSummaryGenerator
    gen = ExecutiveSummaryGenerator()
    summary = gen.generate_summary(MATURITY_BREAKDOWN, GAP_ANALYSIS)
    return summary is not None and len(summary) > 100


@integration_test("Initialize PdfReportGenerator")
def test_pdf_gen_init():
    from nisify.reports import PdfReportGenerator, ReportConfig
    config = ReportConfig(organization="Test Corp")
    gen = PdfReportGenerator(config)
    return gen is not None


@integration_test("Generate HTML report")
def test_html_report():
    from nisify.reports import PdfReportGenerator, ReportConfig
    config = ReportConfig(organization="Test Corp")
    gen = PdfReportGenerator(config)
    result = gen.generate_report(MATURITY_BREAKDOWN, GAP_ANALYSIS, output_dir=Path(TEST_STORE_DIR))
    # Should succeed with at least HTML output
    return result.success and (result.html_path or result.pdf_path)


# =============================================================================
# SECTION 7: Dashboard Tests
# =============================================================================

@integration_test("Find available port")
def test_find_port():
    from nisify.dashboard import find_available_port
    port = find_available_port(8080, 8100)
    return 8080 <= port <= 8100


@integration_test("Initialize DashboardData")
def test_dashboard_data():
    from nisify.dashboard import DashboardData
    data = DashboardData()
    return data is not None


@integration_test("Create DashboardServer")
def test_dashboard_server():
    from nisify.dashboard import DashboardServer, find_available_port
    port = find_available_port(8080, 8100)
    server = DashboardServer(host="127.0.0.1", port=port)
    url = server.get_url()
    return url.startswith("http://127.0.0.1")


# =============================================================================
# SECTION 8: Configuration Tests
# =============================================================================

@integration_test("Load default configuration")
def test_load_config():
    from nisify.config import load_config
    settings = load_config()
    return settings.collection.retention_days == 365


@integration_test("Initialize CredentialStore")
def test_cred_store_init():
    global CRED_STORE_DIR
    from nisify.config import CredentialStore
    CRED_STORE_DIR = tempfile.mkdtemp(prefix="nisify_creds_")
    store = CredentialStore(config_dir=Path(CRED_STORE_DIR))
    store.initialize("test-passphrase-12345")
    return store.is_initialized()


@integration_test("Store and retrieve credential")
def test_cred_roundtrip():
    from nisify.config import CredentialStore
    store = CredentialStore(config_dir=Path(CRED_STORE_DIR))
    store.unlock("test-passphrase-12345")
    store.set_credential("aws", "access_key", "AKIATEST123")
    retrieved = store.get_credential("aws", "access_key")
    return retrieved == "AKIATEST123"


# =============================================================================
# SECTION 9: Scheduler Tests
# =============================================================================

@integration_test("Initialize Scheduler")
def test_scheduler_init():
    global SCHEDULER_DIR
    from nisify.scheduler import Scheduler
    SCHEDULER_DIR = tempfile.mkdtemp(prefix="nisify_sched_")
    scheduler = Scheduler(config_dir=Path(SCHEDULER_DIR))
    return scheduler is not None


@integration_test("Get schedule status")
def test_schedule_status():
    from nisify.scheduler import Scheduler
    scheduler = Scheduler(config_dir=Path(SCHEDULER_DIR))
    status = scheduler.get_schedule_status()
    return not status.enabled  # Should be disabled by default


@integration_test("ScheduleInterval enum values")
def test_schedule_intervals():
    from nisify.scheduler import ScheduleInterval
    return (
        ScheduleInterval.HOURLY.value == "hourly" and
        ScheduleInterval.DAILY.value == "daily" and
        ScheduleInterval.WEEKLY.value == "weekly"
    )


# =============================================================================
# SECTION 10: CLI Command Tests
# =============================================================================

@integration_test("CLI: nisify --version")
def test_cli_version():
    result = subprocess.run(
        ["nisify", "--version"],
        capture_output=True, text=True
    )
    return result.returncode == 0 and "0.1.0" in result.stdout


@integration_test("CLI: nisify info")
def test_cli_info():
    result = subprocess.run(
        ["nisify", "info"],
        capture_output=True, text=True
    )
    return result.returncode == 0 and "Version:" in result.stdout


@integration_test("CLI: nisify info --json")
def test_cli_info_json():
    result = subprocess.run(
        ["nisify", "info", "--json"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return False
    try:
        data = json.loads(result.stdout)
        return "version" in data
    except (json.JSONDecodeError, ValueError):
        return False


@integration_test("CLI: nisify status")
def test_cli_status():
    result = subprocess.run(
        ["nisify", "status"],
        capture_output=True, text=True
    )
    # May show "not initialized" but should not crash
    return result.returncode in [0, 1]


@integration_test("CLI: nisify collect --help")
def test_cli_collect_help():
    result = subprocess.run(
        ["nisify", "collect", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0 and "--platform" in result.stdout


@integration_test("CLI: nisify maturity --help")
def test_cli_maturity_help():
    result = subprocess.run(
        ["nisify", "maturity", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


@integration_test("CLI: nisify gaps --help")
def test_cli_gaps_help():
    result = subprocess.run(
        ["nisify", "gaps", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


@integration_test("CLI: nisify report --help")
def test_cli_report_help():
    result = subprocess.run(
        ["nisify", "report", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


@integration_test("CLI: nisify dashboard --help")
def test_cli_dashboard_help():
    result = subprocess.run(
        ["nisify", "dashboard", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


@integration_test("CLI: nisify schedule --help")
def test_cli_schedule_help():
    result = subprocess.run(
        ["nisify", "schedule", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


@integration_test("CLI: nisify cleanup --help")
def test_cli_cleanup_help():
    result = subprocess.run(
        ["nisify", "cleanup", "--help"],
        capture_output=True, text=True
    )
    return result.returncode == 0


# =============================================================================
# CLEANUP
# =============================================================================

def cleanup():
    """Clean up test directories."""
    for dir_path in [TEST_STORE_DIR, CRED_STORE_DIR, SCHEDULER_DIR]:
        try:
            if dir_path and Path(dir_path).exists():
                shutil.rmtree(dir_path)
        except OSError:
            pass


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "="*60)
    print("  NISIFY COMPREHENSIVE INTEGRATION TEST")
    print("="*60)
    print(f"\nStarted: {datetime.now().isoformat()}")
    print(f"Python: {sys.version.split()[0]}")

    try:
        section("1. Module Imports")
        test_import_nist()
        test_import_storage()
        test_import_collectors()
        test_import_analysis()
        test_import_reports()
        test_import_dashboard()
        test_import_scheduler()
        test_import_config()

        section("2. NIST Framework")
        test_nist_functions()
        test_nist_categories()
        test_nist_subcategories()
        test_get_function()
        test_get_category()
        test_get_subcategory()
        test_mapping_engine()
        test_maturity_calculator()

        section("3. Evidence Storage")
        test_init_store()
        test_create_evidence()
        test_store_evidence()
        test_retrieve_evidence()
        test_storage_stats()
        test_save_snapshot()
        test_get_history()

        section("4. Collector Registry")
        test_collector_registry()
        test_aws_collector()
        test_okta_collector()
        test_collection_result()

        section("5. Analysis")
        test_gap_analyzer_init()
        test_gap_analysis()
        test_trend_tracker_init()

        section("6. Report Generation")
        test_json_exporter_init()
        test_json_export()
        test_exec_summary_init()
        test_exec_summary()
        test_pdf_gen_init()
        test_html_report()

        section("7. Dashboard")
        test_find_port()
        test_dashboard_data()
        test_dashboard_server()

        section("8. Configuration")
        test_load_config()
        test_cred_store_init()
        test_cred_roundtrip()

        section("9. Scheduler")
        test_scheduler_init()
        test_schedule_status()
        test_schedule_intervals()

        section("10. CLI Commands")
        test_cli_version()
        test_cli_info()
        test_cli_info_json()
        test_cli_status()
        test_cli_collect_help()
        test_cli_maturity_help()
        test_cli_gaps_help()
        test_cli_report_help()
        test_cli_dashboard_help()
        test_cli_schedule_help()
        test_cli_cleanup_help()

    finally:
        cleanup()

    # Print summary
    section("TEST SUMMARY")

    total = RESULTS["passed"] + RESULTS["failed"]
    pass_rate = (RESULTS["passed"] / total * 100) if total > 0 else 0

    print(f"Total Tests: {total}")
    print(f"Passed:      {RESULTS['passed']}")
    print(f"Failed:      {RESULTS['failed']}")
    print(f"Pass Rate:   {pass_rate:.1f}%")

    if RESULTS["failed"] > 0:
        print("\nFailed Tests:")
        for test in RESULTS["tests"]:
            if test["status"] != "PASS":
                error = test.get("error", "")
                print(f"  - {test['name']}: {test['status']}" + (f" ({error})" if error else ""))

    print("\n" + "="*60)
    if RESULTS["failed"] == 0:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  {RESULTS['failed']} TEST(S) FAILED")
    print("="*60 + "\n")

    return 0 if RESULTS["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
