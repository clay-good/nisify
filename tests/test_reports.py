"""
Tests for the reports module (json_exporter, executive_summary, pdf_generator).

Uses Python's unittest module with tempfile for file output tests.
Tests JSON export, executive summary generation, PDF report generation,
and data serialization.
"""

from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from nisify.analysis.gap_analyzer import (
    Effort,
    Gap,
    GapAnalysis,
    GapType,
    Impact,
    Priority,
    Recommendation,
)
from nisify.analysis.trend_tracker import (
    TrendAnalysis,
    TrendDirection,
    TrendItem,
)
from nisify.nist.maturity_calculator import (
    EntityType,
    MaturityBreakdown,
    MaturityScore,
)
from nisify.reports.executive_summary import (
    FUNCTION_DESCRIPTIONS,
    MATURITY_DESCRIPTIONS,
    ExecutiveSummaryGenerator,
    SummaryConfig,
)
from nisify.reports.json_exporter import (
    EVIDENCE_EXPORT_SCHEMA,
    FULL_EXPORT_SCHEMA,
    GAPS_EXPORT_SCHEMA,
    MATURITY_EXPORT_SCHEMA,
    ExportMetadata,
    ExportResult,
    JsonExporter,
)
from nisify.reports.pdf_generator import (
    REPORT_CSS,
    PdfReportGenerator,
    ReportConfig,
)
from nisify.reports.pdf_generator import (
    ReportResult as PdfReportResult,
)


class TestExportMetadata(unittest.TestCase):
    """Tests for ExportMetadata dataclass."""

    def test_metadata_creation(self) -> None:
        """Test creating ExportMetadata."""
        now = datetime.now(UTC)
        metadata = ExportMetadata(
            export_type="maturity",
            timestamp=now,
            version="0.1.0",
            organization="Test Org",
        )

        self.assertEqual(metadata.export_type, "maturity")
        self.assertEqual(metadata.version, "0.1.0")
        self.assertEqual(metadata.organization, "Test Org")

    def test_metadata_to_dict(self) -> None:
        """Test ExportMetadata to_dict method."""
        now = datetime.now(UTC)
        period_start = now - timedelta(days=30)
        metadata = ExportMetadata(
            export_type="evidence",
            timestamp=now,
            version="0.1.0",
            organization="Test Org",
            period_start=period_start,
            period_end=now,
        )

        result = metadata.to_dict()

        self.assertEqual(result["export_type"], "evidence")
        self.assertEqual(result["version"], "0.1.0")
        self.assertEqual(result["format_version"], "1.0")
        self.assertIsNotNone(result["period_start"])
        self.assertIsNotNone(result["period_end"])

    def test_metadata_without_period(self) -> None:
        """Test ExportMetadata without period dates."""
        now = datetime.now(UTC)
        metadata = ExportMetadata(
            export_type="gaps",
            timestamp=now,
            version="0.1.0",
        )

        result = metadata.to_dict()

        self.assertIsNone(result["period_start"])
        self.assertIsNone(result["period_end"])
        self.assertIsNone(result["organization"])


class TestExportResult(unittest.TestCase):
    """Tests for ExportResult dataclass."""

    def test_result_success(self) -> None:
        """Test successful ExportResult."""
        result = ExportResult(
            success=True,
            path=Path("/tmp/test.json"),
            size_bytes=1024,
            record_count=50,
            export_type="maturity",
            compressed=False,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.size_bytes, 1024)
        self.assertIsNone(result.error)

    def test_result_failure(self) -> None:
        """Test failed ExportResult."""
        result = ExportResult(
            success=False,
            path=None,
            size_bytes=0,
            record_count=0,
            export_type="gaps",
            compressed=False,
            error="File write failed",
        )

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertEqual(result.error, "File write failed")

    def test_result_to_dict(self) -> None:
        """Test ExportResult to_dict method."""
        result = ExportResult(
            success=True,
            path=Path("/tmp/test.json"),
            size_bytes=2048,
            record_count=100,
            export_type="full",
            compressed=True,
        )

        data = result.to_dict()

        self.assertTrue(data["success"])
        self.assertEqual(data["path"], "/tmp/test.json")
        self.assertEqual(data["size_bytes"], 2048)
        self.assertTrue(data["compressed"])


class TestJsonExporter(unittest.TestCase):
    """Tests for JsonExporter class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.exporter = JsonExporter(version="0.1.0", organization="Test Org")
        self.now = datetime.now(UTC)
        self.temp_dir = tempfile.mkdtemp()

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        score: float,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.SUBCATEGORY,
            level=level,
            score=score,
            evidence_count=5,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(self) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score("overall", 2, 2.5),
            by_function={
                "GV": self._create_maturity_score("GV", 2, 2.3),
                "PR": self._create_maturity_score("PR", 3, 3.0),
            },
            by_category={
                "GV.OC": self._create_maturity_score("GV.OC", 2, 2.5),
                "PR.AC": self._create_maturity_score("PR.AC", 3, 3.2),
            },
            by_subcategory={
                "GV.OC-01": self._create_maturity_score("GV.OC-01", 2, 2.5),
                "PR.AC-01": self._create_maturity_score("PR.AC-01", 3, 3.2),
            },
            timestamp=self.now,
            statistics={"total_subcategories": 106, "subcategories_with_evidence": 2},
        )

    def _create_gap_analysis(self) -> GapAnalysis:
        """Helper to create GapAnalysis."""
        gap = Gap(
            control_id="PR.AC-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.HIGH,
            explanation="Control needs improvement.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-01",
                    action="Enable MFA",
                    platform="okta",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Enable MFA.",
                )
            ],
        )

        return GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=25,
            gap_percentage=25.0,
            gaps_by_priority={"critical": 5, "high": 10, "medium": 7, "low": 3},
            gaps_by_function={"PR": [gap]},
            gaps_by_type={"low_maturity": 25},
            all_gaps=[gap],
            top_recommendations=[gap.recommendations[0]],
            quick_wins=[gap],
            critical_gaps=[],
        )

    def test_exporter_initialization(self) -> None:
        """Test JsonExporter initialization."""
        exporter = JsonExporter()
        self.assertEqual(exporter.version, "0.1.0")
        self.assertIsNone(exporter.organization)

    def test_exporter_with_organization(self) -> None:
        """Test JsonExporter with organization."""
        exporter = JsonExporter(version="1.0.0", organization="Acme Corp")
        self.assertEqual(exporter.version, "1.0.0")
        self.assertEqual(exporter.organization, "Acme Corp")

    def test_export_maturity(self) -> None:
        """Test maturity export."""
        breakdown = self._create_maturity_breakdown()
        result = self.exporter.export_maturity(breakdown, Path(self.temp_dir))

        self.assertTrue(result.success)
        self.assertIsNotNone(result.path)
        self.assertTrue(result.path.exists())
        self.assertGreater(result.size_bytes, 0)
        self.assertEqual(result.export_type, "maturity")
        self.assertFalse(result.compressed)

        # Verify JSON content
        with open(result.path) as f:
            data = json.load(f)

        self.assertIn("metadata", data)
        self.assertIn("overall", data)
        self.assertIn("by_function", data)
        self.assertEqual(data["metadata"]["export_type"], "maturity")

    def test_export_maturity_compressed(self) -> None:
        """Test compressed maturity export."""
        breakdown = self._create_maturity_breakdown()
        result = self.exporter.export_maturity(
            breakdown, Path(self.temp_dir), compress=True
        )

        self.assertTrue(result.success)
        self.assertTrue(result.compressed)
        self.assertTrue(str(result.path).endswith(".json.gz"))

        # Verify gzip content
        with gzip.open(result.path, "rt") as f:
            data = json.load(f)

        self.assertIn("overall", data)

    def test_export_gaps(self) -> None:
        """Test gap analysis export."""
        gaps = self._create_gap_analysis()
        result = self.exporter.export_gaps(gaps, Path(self.temp_dir))

        self.assertTrue(result.success)
        self.assertIsNotNone(result.path)
        self.assertEqual(result.export_type, "gaps")
        self.assertEqual(result.record_count, 1)

        # Verify JSON content
        with open(result.path) as f:
            data = json.load(f)

        self.assertIn("summary", data)
        self.assertIn("gaps", data)
        self.assertIn("recommendations", data)
        self.assertEqual(data["summary"]["total_controls"], 100)

    def test_export_evidence(self) -> None:
        """Test evidence export."""
        evidence_items = [
            {
                "platform": "okta",
                "evidence_type": "user_inventory",
                "collected_at": self.now.isoformat(),
                "raw_data": {"users": 50},
            },
            {
                "platform": "aws",
                "evidence_type": "mfa_status",
                "collected_at": self.now.isoformat(),
                "raw_data": {"mfa_enabled": True},
            },
        ]

        result = self.exporter.export_evidence(evidence_items, output_dir=Path(self.temp_dir))

        self.assertTrue(result.success)
        self.assertEqual(result.record_count, 2)
        self.assertEqual(result.export_type, "evidence")

        # Verify JSON content
        with open(result.path) as f:
            data = json.load(f)

        self.assertEqual(data["statistics"]["total_items"], 2)
        self.assertIn("okta", data["statistics"]["platforms"])
        self.assertIn("aws", data["statistics"]["platforms"])

    def test_export_evidence_empty(self) -> None:
        """Test evidence export with empty list."""
        result = self.exporter.export_evidence([], output_dir=Path(self.temp_dir))

        self.assertTrue(result.success)
        self.assertEqual(result.record_count, 0)

    def test_export_full(self) -> None:
        """Test full export."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        evidence = [
            {
                "platform": "okta",
                "evidence_type": "user_inventory",
                "raw_data": {},
            }
        ]

        result = self.exporter.export_full(
            maturity=maturity,
            gaps=gaps,
            evidence=evidence,
            output_dir=Path(self.temp_dir),
        )

        self.assertTrue(result.success)
        self.assertEqual(result.export_type, "full")

        # Verify JSON content
        with open(result.path) as f:
            data = json.load(f)

        self.assertIn("maturity", data)
        self.assertIn("gaps", data)
        self.assertIn("evidence", data)

    def test_export_full_without_evidence(self) -> None:
        """Test full export without evidence."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        result = self.exporter.export_full(
            maturity=maturity,
            gaps=gaps,
            output_dir=Path(self.temp_dir),
        )

        self.assertTrue(result.success)

        with open(result.path) as f:
            data = json.load(f)

        self.assertNotIn("evidence", data)

    def test_export_full_with_trends(self) -> None:
        """Test full export with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        trend_item = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=TrendDirection.IMPROVING,
            current_score=2.5,
            previous_score=2.0,
            score_delta=0.5,
            score_delta_percent=25.0,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
        )

        trends = TrendAnalysis(
            timestamp=self.now,
            period_days=30,
            overall_trend=trend_item,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={"total_controls_analyzed": 100},
            chart_data={},
        )

        result = self.exporter.export_full(
            maturity=maturity,
            gaps=gaps,
            trends=trends,
            output_dir=Path(self.temp_dir),
        )

        self.assertTrue(result.success)

        with open(result.path) as f:
            data = json.load(f)

        self.assertIn("trends", data)

    def test_get_schema(self) -> None:
        """Test getting export schemas."""
        self.assertEqual(
            self.exporter.get_schema("maturity"),
            MATURITY_EXPORT_SCHEMA,
        )
        self.assertEqual(
            self.exporter.get_schema("gaps"),
            GAPS_EXPORT_SCHEMA,
        )
        self.assertEqual(
            self.exporter.get_schema("evidence"),
            EVIDENCE_EXPORT_SCHEMA,
        )
        self.assertEqual(
            self.exporter.get_schema("full"),
            FULL_EXPORT_SCHEMA,
        )
        self.assertEqual(self.exporter.get_schema("unknown"), {})

    def test_export_schema(self) -> None:
        """Test exporting schema to file."""
        schema_path = Path(self.temp_dir) / "schema.json"
        result = self.exporter.export_schema("maturity", schema_path)

        self.assertTrue(result)
        self.assertTrue(schema_path.exists())

        with open(schema_path) as f:
            schema = json.load(f)

        self.assertEqual(schema["title"], "Nisify Maturity Export")

    def test_export_schema_invalid_type(self) -> None:
        """Test exporting schema with invalid type."""
        schema_path = Path(self.temp_dir) / "schema.json"
        result = self.exporter.export_schema("invalid", schema_path)

        self.assertFalse(result)

    def test_generate_filename(self) -> None:
        """Test filename generation."""
        filename = self.exporter._generate_filename("maturity", False)
        self.assertTrue(filename.endswith("_maturity_export.json"))

        filename_compressed = self.exporter._generate_filename("gaps", True)
        self.assertTrue(filename_compressed.endswith("_gaps_export.json.gz"))

    def test_export_evidence_default_output_dir(self) -> None:
        """Test evidence export with default output directory."""
        import os
        original_dir = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            result = self.exporter.export_evidence([])
            self.assertTrue(result.success)
        finally:
            os.chdir(original_dir)

    def test_export_full_default_output_dir(self) -> None:
        """Test full export with default output directory."""
        import os
        original_dir = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            maturity = self._create_maturity_breakdown()
            gaps = self._create_gap_analysis()
            result = self.exporter.export_full(maturity=maturity, gaps=gaps)
            self.assertTrue(result.success)
        finally:
            os.chdir(original_dir)

    def test_export_evidence_with_invalid_date_format(self) -> None:
        """Test evidence export handles invalid date format."""
        evidence_items = [
            {
                "platform": "okta",
                "evidence_type": "user_inventory",
                "collected_at": "invalid-date-format",  # Invalid ISO format
            },
            {
                "platform": "aws",
                "evidence_type": "mfa_status",
                "collected_at": self.now.isoformat(),  # Valid
            },
        ]

        result = self.exporter.export_evidence(evidence_items, output_dir=Path(self.temp_dir))

        # Should still succeed, just ignoring invalid dates
        self.assertTrue(result.success)
        self.assertEqual(result.record_count, 2)

    def test_export_evidence_with_non_string_date(self) -> None:
        """Test evidence export handles non-string date value."""
        evidence_items = [
            {
                "platform": "okta",
                "evidence_type": "user_inventory",
                "collected_at": 12345,  # Wrong type
            },
        ]

        result = self.exporter.export_evidence(evidence_items, output_dir=Path(self.temp_dir))

        # Should still succeed, just ignoring wrong types
        self.assertTrue(result.success)


class TestJsonExporterErrorHandling(unittest.TestCase):
    """Tests for error handling in JsonExporter."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.exporter = JsonExporter(version="0.1.0")
        self.now = datetime.now(UTC)

    def _create_maturity_breakdown(self) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=MaturityScore(
                entity_id="overall",
                entity_type=EntityType.SUBCATEGORY,
                level=2,
                score=2.5,
                evidence_count=5,
                last_evidence_date=self.now,
                confidence=0.9,
                explanation="Test",
            ),
            by_function={},
            by_category={},
            by_subcategory={},
            timestamp=self.now,
            statistics={},
        )

    def _create_gap_analysis(self) -> GapAnalysis:
        """Helper to create GapAnalysis."""
        return GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=0,
            gap_percentage=0.0,
            gaps_by_priority={},
            gaps_by_function={},
            gaps_by_type={},
            all_gaps=[],
            top_recommendations=[],
            quick_wins=[],
            critical_gaps=[],
        )

    def test_export_maturity_invalid_path(self) -> None:
        """Test maturity export with invalid path returns error."""
        breakdown = self._create_maturity_breakdown()
        # Use a path that we can't write to
        invalid_path = Path("/nonexistent/deeply/nested/path/that/should/fail")

        result = self.exporter.export_maturity(breakdown, invalid_path)

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.export_type, "maturity")

    def test_export_gaps_invalid_path(self) -> None:
        """Test gaps export with invalid path returns error."""
        gaps = self._create_gap_analysis()
        invalid_path = Path("/nonexistent/deeply/nested/path/that/should/fail")

        result = self.exporter.export_gaps(gaps, invalid_path)

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.export_type, "gaps")

    def test_export_evidence_invalid_path(self) -> None:
        """Test evidence export with invalid path returns error."""
        invalid_path = Path("/nonexistent/deeply/nested/path/that/should/fail")

        result = self.exporter.export_evidence([], output_dir=invalid_path)

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.export_type, "evidence")

    def test_export_full_invalid_path(self) -> None:
        """Test full export with invalid path returns error."""
        breakdown = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        invalid_path = Path("/nonexistent/deeply/nested/path/that/should/fail")

        result = self.exporter.export_full(breakdown, gaps, output_dir=invalid_path)

        self.assertFalse(result.success)
        self.assertIsNone(result.path)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.export_type, "full")

    def test_export_schema_invalid_path(self) -> None:
        """Test schema export with invalid path returns False."""
        invalid_path = Path("/nonexistent/deeply/nested/path/schema.json")

        result = self.exporter.export_schema("maturity", invalid_path)

        self.assertFalse(result)


class TestSummaryConfig(unittest.TestCase):
    """Tests for SummaryConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = SummaryConfig()

        self.assertEqual(config.organization, "Organization")
        self.assertTrue(config.include_recommendations)
        self.assertEqual(config.max_recommendations, 5)
        self.assertTrue(config.include_trends)
        self.assertIsNone(config.report_date)

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        report_date = datetime.now(UTC)
        config = SummaryConfig(
            organization="Acme Corp",
            include_recommendations=False,
            max_recommendations=3,
            include_trends=False,
            report_date=report_date,
        )

        self.assertEqual(config.organization, "Acme Corp")
        self.assertFalse(config.include_recommendations)
        self.assertEqual(config.max_recommendations, 3)
        self.assertFalse(config.include_trends)
        self.assertEqual(config.report_date, report_date)


class TestExecutiveSummaryGenerator(unittest.TestCase):
    """Tests for ExecutiveSummaryGenerator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.config = SummaryConfig(organization="Test Corp")
        self.generator = ExecutiveSummaryGenerator(self.config)
        self.now = datetime.now(UTC)

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        score: float,
        evidence_count: int = 10,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.FUNCTION,
            level=level,
            score=score,
            evidence_count=evidence_count,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(self, overall_level: int = 2) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score("overall", overall_level, float(overall_level) + 0.5),
            by_function={
                "GV": self._create_maturity_score("GV", 2, 2.3),
                "ID": self._create_maturity_score("ID", 2, 2.1),
                "PR": self._create_maturity_score("PR", 3, 3.0),
                "DE": self._create_maturity_score("DE", 2, 2.5),
                "RS": self._create_maturity_score("RS", 1, 1.5),
                "RC": self._create_maturity_score("RC", 2, 2.0),
            },
            by_category={},
            by_subcategory={},
            timestamp=self.now,
            statistics={
                "total_subcategories": 106,
                "subcategories_with_evidence": 50,
            },
        )

    def _create_gap_analysis(self, has_critical: bool = True) -> GapAnalysis:
        """Helper to create GapAnalysis."""
        gap = Gap(
            control_id="PR.AC-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.CRITICAL if has_critical else Priority.MEDIUM,
            explanation="Control needs improvement.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-01",
                    action="Enable MFA enforcement",
                    platform="okta",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Enable MFA.",
                )
            ],
        )

        return GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=25,
            gap_percentage=25.0,
            gaps_by_priority={
                "critical": 5 if has_critical else 0,
                "high": 10,
                "medium": 7,
                "low": 3,
            },
            gaps_by_function={"PR": [gap]},
            gaps_by_type={"low_maturity": 25},
            all_gaps=[gap],
            top_recommendations=[gap.recommendations[0]],
            quick_wins=[gap],
            critical_gaps=[gap] if has_critical else [],
        )

    def _create_trend_analysis(
        self, direction: TrendDirection = TrendDirection.IMPROVING
    ) -> TrendAnalysis:
        """Helper to create TrendAnalysis."""
        trend_item = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=direction,
            current_score=2.5,
            previous_score=2.0,
            score_delta=0.5 if direction == TrendDirection.IMPROVING else -0.5,
            score_delta_percent=25.0,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
        )

        return TrendAnalysis(
            timestamp=self.now,
            period_days=30,
            overall_trend=trend_item,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={
                "total_controls_analyzed": 100,
                "improving_count": 10 if direction == TrendDirection.IMPROVING else 0,
                "regressing_count": 5 if direction == TrendDirection.REGRESSING else 0,
            },
            chart_data={},
        )

    def test_generator_initialization(self) -> None:
        """Test ExecutiveSummaryGenerator initialization."""
        generator = ExecutiveSummaryGenerator()
        self.assertIsNotNone(generator.config)
        self.assertEqual(generator.config.organization, "Organization")

    def test_generator_with_config(self) -> None:
        """Test ExecutiveSummaryGenerator with custom config."""
        config = SummaryConfig(organization="Custom Org")
        generator = ExecutiveSummaryGenerator(config)
        self.assertEqual(generator.config.organization, "Custom Org")

    def test_generate_summary(self) -> None:
        """Test summary generation."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        summary = self.generator.generate_summary(maturity, gaps)

        self.assertIn("NIST CSF 2.0 COMPLIANCE SUMMARY", summary)
        self.assertIn("Test Corp", summary)
        self.assertIn("OVERVIEW", summary)
        self.assertIn("MATURITY SCORES", summary)
        self.assertIn("KEY FINDINGS", summary)
        self.assertIn("RECOMMENDED ACTIONS", summary)

    def test_generate_summary_with_trends(self) -> None:
        """Test summary generation with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        trends = self._create_trend_analysis()

        summary = self.generator.generate_summary(maturity, gaps, trends)

        self.assertIn("TREND ANALYSIS", summary)
        self.assertIn("improving", summary.lower())

    def test_generate_email_body(self) -> None:
        """Test email body generation."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        email = self.generator.generate_email_body(maturity, gaps)

        self.assertIn("Subject:", email)
        self.assertIn("Team,", email)
        self.assertIn("Best regards,", email)
        self.assertIn("Current Maturity by Function:", email)

    def test_generate_email_with_trends(self) -> None:
        """Test email generation with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        trends = self._create_trend_analysis()

        email = self.generator.generate_email_body(maturity, gaps, trends)

        self.assertIn("Trend:", email)
        self.assertIn("Improving", email)

    def test_generate_markdown(self) -> None:
        """Test markdown generation."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        markdown = self.generator.generate_markdown(maturity, gaps)

        self.assertIn("# NIST CSF 2.0 Compliance Summary", markdown)
        self.assertIn("## Overview", markdown)
        self.assertIn("## Maturity Scores", markdown)
        self.assertIn("| Function |", markdown)
        self.assertIn("## Key Findings", markdown)
        self.assertIn("## Gap Summary", markdown)

    def test_generate_markdown_with_trends(self) -> None:
        """Test markdown generation with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        trends = self._create_trend_analysis()

        markdown = self.generator.generate_markdown(maturity, gaps, trends)

        self.assertIn("## Trends", markdown)

    def test_get_posture_rating_excellent(self) -> None:
        """Test posture rating for level 4."""
        maturity = self._create_maturity_breakdown(overall_level=4)
        rating = self.generator.get_posture_rating(maturity)
        self.assertEqual(rating, "Excellent")

    def test_get_posture_rating_strong(self) -> None:
        """Test posture rating for level 3."""
        maturity = self._create_maturity_breakdown(overall_level=3)
        rating = self.generator.get_posture_rating(maturity)
        self.assertEqual(rating, "Strong")

    def test_get_posture_rating_developing(self) -> None:
        """Test posture rating for level 2."""
        maturity = self._create_maturity_breakdown(overall_level=2)
        rating = self.generator.get_posture_rating(maturity)
        self.assertEqual(rating, "Developing")

    def test_get_posture_rating_foundational(self) -> None:
        """Test posture rating for level 1."""
        maturity = self._create_maturity_breakdown(overall_level=1)
        rating = self.generator.get_posture_rating(maturity)
        self.assertEqual(rating, "Foundational")

    def test_get_posture_rating_needs_improvement(self) -> None:
        """Test posture rating for level 0."""
        maturity = self._create_maturity_breakdown(overall_level=0)
        rating = self.generator.get_posture_rating(maturity)
        self.assertEqual(rating, "Needs Improvement")

    def test_overview_strong_posture(self) -> None:
        """Test overview for strong posture."""
        maturity = self._create_maturity_breakdown(overall_level=3)
        gaps = self._create_gap_analysis()

        overview = self.generator._generate_overview(maturity, gaps)

        self.assertIn("strong compliance posture", overview)

    def test_overview_needs_improvement(self) -> None:
        """Test overview for weak posture."""
        maturity = self._create_maturity_breakdown(overall_level=0)
        gaps = self._create_gap_analysis()

        overview = self.generator._generate_overview(maturity, gaps)

        self.assertIn("requires significant compliance improvements", overview)

    def test_overview_no_gaps(self) -> None:
        """Test overview with no gaps."""
        maturity = self._create_maturity_breakdown()
        gaps = GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=0,
            gap_percentage=0.0,
            gaps_by_priority={},
            gaps_by_function={},
            gaps_by_type={},
            all_gaps=[],
            top_recommendations=[],
            quick_wins=[],
            critical_gaps=[],
        )

        overview = self.generator._generate_overview(maturity, gaps)

        self.assertIn("No significant gaps", overview)

    def test_key_findings_include_strongest(self) -> None:
        """Test key findings includes strongest area."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        findings = self.generator._generate_key_findings(maturity, gaps)

        self.assertTrue(any("Strongest area" in f for f in findings))
        self.assertTrue(any("Protect" in f for f in findings))  # PR is strongest

    def test_key_findings_include_weakest(self) -> None:
        """Test key findings includes weakest area."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        findings = self.generator._generate_key_findings(maturity, gaps)

        self.assertTrue(any("needing attention" in f for f in findings))
        self.assertTrue(any("Respond" in f for f in findings))  # RS is weakest

    def test_key_findings_no_critical_gaps(self) -> None:
        """Test key findings shows 'No critical gaps identified' when none exist."""
        maturity = self._create_maturity_breakdown()
        # Create gap analysis with zero critical gaps
        gaps = GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=10,
            gap_percentage=10.0,
            gaps_by_priority={"critical": 0, "high": 5, "medium": 5},
            gaps_by_function={},
            gaps_by_type={},
            all_gaps=[],
            top_recommendations=[],
            quick_wins=[],
            critical_gaps=[],
        )

        findings = self.generator._generate_key_findings(maturity, gaps)

        self.assertTrue(any("No critical gaps identified" in f for f in findings))

    def test_trend_section_insufficient_data(self) -> None:
        """Test trend section with insufficient data."""
        trends = self._create_trend_analysis(TrendDirection.INSUFFICIENT_DATA)

        section = self.generator._generate_trend_section(trends)

        self.assertIn("Insufficient historical data", section)

    def test_trend_section_improving(self) -> None:
        """Test trend section for improving trend."""
        trends = self._create_trend_analysis(TrendDirection.IMPROVING)

        section = self.generator._generate_trend_section(trends)

        self.assertIn("improving", section)
        self.assertIn("10 controls showed improvement", section)

    def test_trend_section_regressing(self) -> None:
        """Test trend section for regressing trend."""
        trends = self._create_trend_analysis(TrendDirection.REGRESSING)

        section = self.generator._generate_trend_section(trends)

        self.assertIn("declining", section)

    def test_recommendations_include_critical(self) -> None:
        """Test recommendations include critical gaps."""
        gaps = self._create_gap_analysis(has_critical=True)

        recommendations = self.generator._generate_recommendations(gaps)

        self.assertTrue(any("critical" in r.lower() for r in recommendations))

    def test_recommendations_include_quick_wins(self) -> None:
        """Test recommendations include quick wins."""
        # Create gap analysis where quick win is NOT a critical gap
        gaps = self._create_gap_analysis(has_critical=False)

        recommendations = self.generator._generate_recommendations(gaps)

        self.assertTrue(any("quick win" in r.lower() for r in recommendations))

    def test_recommendations_generic_fallback(self) -> None:
        """Test recommendations with no specific items."""
        gaps = GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=0,
            gap_percentage=0.0,
            gaps_by_priority={},
            gaps_by_function={},
            gaps_by_type={},
            all_gaps=[],
            top_recommendations=[],
            quick_wins=[],
            critical_gaps=[],
        )

        recommendations = self.generator._generate_recommendations(gaps)

        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("evidence collection" in r.lower() for r in recommendations))

    def test_overview_foundational_posture(self) -> None:
        """Test overview for foundational posture (level 1)."""
        maturity = self._create_maturity_breakdown(overall_level=1)
        gaps = self._create_gap_analysis()

        overview = self.generator._generate_overview(maturity, gaps)

        self.assertIn("foundational compliance measures in place", overview)

    def test_email_trend_without_score_delta(self) -> None:
        """Test email generation with trend that has no score delta."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        # Create trend with direction but no score_delta
        trend_item = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=TrendDirection.STABLE,
            current_score=2.5,
            previous_score=2.5,
            score_delta=None,  # No delta
            score_delta_percent=0.0,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
        )

        trends = TrendAnalysis(
            timestamp=self.now,
            period_days=30,
            overall_trend=trend_item,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={"total_controls_analyzed": 100},
            chart_data={},
        )

        email = self.generator.generate_email_body(maturity, gaps, trends)

        # Should have trend line without delta parenthetical
        self.assertIn("Trend: Stable", email)
        # Should NOT have score delta in parentheses
        self.assertNotIn("(+", email)
        self.assertNotIn("(-", email)

    def test_recommendations_break_at_max_for_quick_wins(self) -> None:
        """Test that quick wins loop breaks when max_recommendations reached."""
        # Create generator with low max_recommendations
        config = SummaryConfig(max_recommendations=2)
        generator = ExecutiveSummaryGenerator(config)

        # Create gap analysis with critical gaps that fill recommendations
        gap1 = Gap(
            control_id="PR.AC-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.CRITICAL,
            explanation="Control needs improvement.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-01",
                    action="Enable MFA",
                    platform="okta",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Enable MFA.",
                )
            ],
        )
        gap2 = Gap(
            control_id="PR.AC-02",
            control_name="Access Control",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.CRITICAL,
            explanation="Access control needs work.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-02",
                    action="Implement RBAC",
                    platform="okta",
                    effort=Effort.MEDIUM,
                    impact=Impact.HIGH,
                    details="Implement RBAC.",
                )
            ],
        )
        # Quick win that would exceed max_recommendations
        quick_win = Gap(
            control_id="DE.CM-01",
            control_name="Network Monitoring",
            function_id="DE",
            category_id="DE.CM",
            current_maturity=2,
            target_maturity=3,
            gap_type=GapType.PARTIAL_EVIDENCE,
            priority=Priority.MEDIUM,
            explanation="Quick win.",
            recommendations=[
                Recommendation(
                    gap_id="DE.CM-01",
                    action="Quick fix",
                    platform="datadog",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Quick fix.",
                )
            ],
        )

        gaps = GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=3,
            gap_percentage=3.0,
            gaps_by_priority={"critical": 2, "medium": 1},
            gaps_by_function={"PR": [gap1, gap2], "DE": [quick_win]},
            gaps_by_type={"low_maturity": 2, "partial_evidence": 1},
            all_gaps=[gap1, gap2, quick_win],
            top_recommendations=[],
            quick_wins=[quick_win],
            critical_gaps=[gap1, gap2],
        )

        recommendations = generator._generate_recommendations(gaps)

        # Should have exactly 2 recommendations (max_recommendations)
        self.assertEqual(len(recommendations), 2)
        # Both should be from critical gaps, quick win should be excluded
        self.assertTrue(all("critical" in r.lower() for r in recommendations))

    def test_recommendations_break_at_max_for_top_recommendations(self) -> None:
        """Test that top recommendations loop breaks when max_recommendations reached."""
        # Create generator with low max_recommendations
        config = SummaryConfig(max_recommendations=2)
        generator = ExecutiveSummaryGenerator(config)

        # Create gap analysis with no critical gaps but multiple top recommendations
        rec1 = Recommendation(
            gap_id="PR.AC-01",
            action="First action",
            platform="okta",
            effort=Effort.LOW,
            impact=Impact.HIGH,
            details="First.",
        )
        rec2 = Recommendation(
            gap_id="PR.AC-02",
            action="Second action",
            platform="okta",
            effort=Effort.MEDIUM,
            impact=Impact.HIGH,
            details="Second.",
        )
        rec3 = Recommendation(
            gap_id="DE.CM-01",
            action="Third action",
            platform="datadog",
            effort=Effort.LOW,
            impact=Impact.MEDIUM,
            details="Third.",
        )

        gaps = GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=3,
            gap_percentage=3.0,
            gaps_by_priority={"high": 2, "medium": 1},
            gaps_by_function={},
            gaps_by_type={"low_maturity": 3},
            all_gaps=[],
            top_recommendations=[rec1, rec2, rec3],
            quick_wins=[],
            critical_gaps=[],  # No critical gaps
        )

        recommendations = generator._generate_recommendations(gaps)

        # Should have exactly 2 recommendations (max_recommendations)
        self.assertEqual(len(recommendations), 2)
        # Should be from top_recommendations
        self.assertIn("First action", recommendations[0])
        self.assertIn("Second action", recommendations[1])


class TestDescriptionDictionaries(unittest.TestCase):
    """Tests for description dictionaries."""

    def test_maturity_descriptions_complete(self) -> None:
        """Test maturity descriptions has all levels."""
        for level in range(5):
            self.assertIn(level, MATURITY_DESCRIPTIONS)
            self.assertIsInstance(MATURITY_DESCRIPTIONS[level], str)

    def test_function_descriptions_complete(self) -> None:
        """Test function descriptions has all functions."""
        expected_functions = ["GV", "ID", "PR", "DE", "RS", "RC"]
        for func in expected_functions:
            self.assertIn(func, FUNCTION_DESCRIPTIONS)
            self.assertIsInstance(FUNCTION_DESCRIPTIONS[func], str)


class TestReportConfig(unittest.TestCase):
    """Tests for ReportConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ReportConfig()

        self.assertEqual(config.organization, "Organization")
        self.assertIsNone(config.logo_path)
        self.assertTrue(config.include_evidence_appendix)
        self.assertFalse(config.include_all_gaps)
        self.assertTrue(config.include_trends)
        self.assertEqual(config.max_gaps_per_function, 5)
        self.assertIsNone(config.report_date)
        self.assertIn("Nisify", config.footer_text)

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        report_date = datetime.now(UTC)
        config = ReportConfig(
            organization="Acme Corp",
            logo_path=Path("/tmp/logo.png"),
            include_evidence_appendix=False,
            include_all_gaps=True,
            include_trends=False,
            max_gaps_per_function=10,
            report_date=report_date,
            footer_text="Custom Footer",
        )

        self.assertEqual(config.organization, "Acme Corp")
        self.assertEqual(config.logo_path, Path("/tmp/logo.png"))
        self.assertFalse(config.include_evidence_appendix)
        self.assertTrue(config.include_all_gaps)
        self.assertFalse(config.include_trends)
        self.assertEqual(config.max_gaps_per_function, 10)
        self.assertEqual(config.report_date, report_date)
        self.assertEqual(config.footer_text, "Custom Footer")


class TestPdfReportResult(unittest.TestCase):
    """Tests for PdfReportResult dataclass."""

    def test_success_result(self) -> None:
        """Test successful report result."""
        result = PdfReportResult(
            success=True,
            pdf_path=Path("/tmp/report.pdf"),
            html_path=Path("/tmp/report.html"),
            size_bytes=50000,
            page_count=5,
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.pdf_path)
        self.assertIsNotNone(result.html_path)
        self.assertEqual(result.size_bytes, 50000)
        self.assertEqual(result.page_count, 5)
        self.assertIsNone(result.error)

    def test_failure_result(self) -> None:
        """Test failed report result."""
        result = PdfReportResult(
            success=False,
            pdf_path=None,
            html_path=Path("/tmp/report.html"),
            size_bytes=1000,
            page_count=0,
            error="PDF generation failed",
        )

        self.assertFalse(result.success)
        self.assertIsNone(result.pdf_path)
        self.assertIsNotNone(result.html_path)
        self.assertEqual(result.error, "PDF generation failed")


class TestPdfReportGenerator(unittest.TestCase):
    """Tests for PdfReportGenerator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.config = ReportConfig(organization="Test Corp")
        self.generator = PdfReportGenerator(self.config)
        self.now = datetime.now(UTC)
        self.temp_dir = tempfile.mkdtemp()

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        score: float,
        evidence_count: int = 10,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.FUNCTION,
            level=level,
            score=score,
            evidence_count=evidence_count,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(self, overall_level: int = 2) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score(
                "overall", overall_level, float(overall_level) + 0.5
            ),
            by_function={
                "GV": self._create_maturity_score("GV", 2, 2.3),
                "ID": self._create_maturity_score("ID", 2, 2.1),
                "PR": self._create_maturity_score("PR", 3, 3.0),
                "DE": self._create_maturity_score("DE", 2, 2.5),
                "RS": self._create_maturity_score("RS", 1, 1.5),
                "RC": self._create_maturity_score("RC", 2, 2.0),
            },
            by_category={},
            by_subcategory={},
            timestamp=self.now,
            statistics={
                "total_subcategories": 106,
                "subcategories_with_evidence": 50,
            },
        )

    def _create_gap_analysis(self, has_critical: bool = True) -> GapAnalysis:
        """Helper to create GapAnalysis."""
        gap = Gap(
            control_id="PR.AC-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.CRITICAL if has_critical else Priority.HIGH,
            explanation="Control needs improvement due to lack of MFA enforcement.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-01",
                    action="Enable MFA enforcement for all users",
                    platform="okta",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Enable MFA.",
                )
            ],
        )

        high_gap = Gap(
            control_id="DE.CM-01",
            control_name="Network Monitoring",
            function_id="DE",
            category_id="DE.CM",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.PARTIAL_EVIDENCE,
            priority=Priority.HIGH,
            explanation="Limited network monitoring coverage.",
            recommendations=[
                Recommendation(
                    gap_id="DE.CM-01",
                    action="Expand monitoring coverage",
                    platform="datadog",
                    effort=Effort.MEDIUM,
                    impact=Impact.HIGH,
                    details="Expand monitoring.",
                )
            ],
        )

        all_gaps = [gap, high_gap]

        return GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=25,
            gap_percentage=25.0,
            gaps_by_priority={
                "critical": 5 if has_critical else 0,
                "high": 10,
                "medium": 7,
                "low": 3,
            },
            gaps_by_function={"PR": [gap], "DE": [high_gap]},
            gaps_by_type={"low_maturity": 20, "partial_evidence": 5},
            all_gaps=all_gaps,
            top_recommendations=[gap.recommendations[0], high_gap.recommendations[0]],
            quick_wins=[gap],
            critical_gaps=[gap] if has_critical else [],
        )

    def _create_trend_analysis(
        self, direction: TrendDirection = TrendDirection.IMPROVING
    ) -> TrendAnalysis:
        """Helper to create TrendAnalysis."""
        trend_item = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=direction,
            current_score=2.5,
            previous_score=2.0,
            score_delta=0.5 if direction == TrendDirection.IMPROVING else -0.5,
            score_delta_percent=25.0,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
        )

        return TrendAnalysis(
            timestamp=self.now,
            period_days=30,
            overall_trend=trend_item,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={
                "total_controls_analyzed": 100,
                "improving_count": 10 if direction == TrendDirection.IMPROVING else 0,
                "regressing_count": 5 if direction == TrendDirection.REGRESSING else 0,
                "stable_count": 80,
            },
            chart_data={},
        )

    def test_generator_initialization(self) -> None:
        """Test PdfReportGenerator initialization."""
        generator = PdfReportGenerator()
        self.assertIsNotNone(generator.config)
        self.assertEqual(generator.config.organization, "Organization")

    def test_generator_with_config(self) -> None:
        """Test PdfReportGenerator with custom config."""
        config = ReportConfig(organization="Custom Org")
        generator = PdfReportGenerator(config)
        self.assertEqual(generator.config.organization, "Custom Org")

    def test_pdf_available_property(self) -> None:
        """Test pdf_available property."""
        # This depends on whether weasyprint is installed
        result = self.generator.pdf_available
        self.assertIsInstance(result, bool)

    def test_generate_html(self) -> None:
        """Test HTML generation."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        html = self.generator.generate_html(maturity, gaps)

        # Verify HTML structure
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html lang=\"en\">", html)
        self.assertIn("</html>", html)
        self.assertIn("Test Corp", html)
        self.assertIn("NIST CSF 2.0", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Maturity Scores", html)
        self.assertIn("Gap Analysis", html)

    def test_generate_html_with_trends(self) -> None:
        """Test HTML generation with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        trends = self._create_trend_analysis()

        html = self.generator.generate_html(maturity, gaps, trends)

        self.assertIn("Trend Analysis", html)
        self.assertIn("Improving", html)

    def test_generate_html_with_evidence(self) -> None:
        """Test HTML generation with evidence appendix."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        evidence = [
            {"platform": "okta", "evidence_type": "user_inventory", "collected_at": self.now.isoformat()},
            {"platform": "aws", "evidence_type": "mfa_status", "collected_at": self.now.isoformat()},
        ]

        html = self.generator.generate_html(maturity, gaps, evidence_summary=evidence)

        self.assertIn("Evidence Appendix", html)
        self.assertIn("OKTA", html)
        self.assertIn("AWS", html)

    def test_generate_html_without_evidence(self) -> None:
        """Test HTML generation without evidence appendix."""
        config = ReportConfig(organization="Test Corp", include_evidence_appendix=False)
        generator = PdfReportGenerator(config)

        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        html = generator.generate_html(maturity, gaps)

        # The <h1>Evidence Appendix</h1> section should not be present
        self.assertNotIn("<h1>Evidence Appendix</h1>", html)

    def test_generate_report_creates_html(self) -> None:
        """Test report generation creates HTML file."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        result = self.generator.generate_report(
            maturity, gaps, output_dir=Path(self.temp_dir)
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.html_path)
        self.assertTrue(result.html_path.exists())
        self.assertGreater(result.size_bytes, 0)

    def test_generate_report_with_trends(self) -> None:
        """Test report generation with trends."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()
        trends = self._create_trend_analysis()

        result = self.generator.generate_report(
            maturity, gaps, trends=trends, output_dir=Path(self.temp_dir)
        )

        self.assertTrue(result.success)

        # Read HTML and verify trends section
        with open(result.html_path) as f:
            html = f.read()
        self.assertIn("Trend Analysis", html)

    def test_generate_report_default_output_dir(self) -> None:
        """Test report generation with default output directory."""
        import os

        # Change to temp dir to avoid polluting working directory
        original_dir = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            maturity = self._create_maturity_breakdown()
            gaps = self._create_gap_analysis()

            result = self.generator.generate_report(maturity, gaps)

            self.assertTrue(result.success)
            self.assertTrue(result.html_path.exists())
        finally:
            os.chdir(original_dir)

    def test_html_header(self) -> None:
        """Test HTML header generation."""
        header = self.generator._html_header()

        self.assertIn("<!DOCTYPE html>", header)
        self.assertIn("<html lang=\"en\">", header)
        self.assertIn("<meta charset=\"UTF-8\">", header)
        self.assertIn("Test Corp", header)
        self.assertIn("<style>", header)

    def test_generate_cover(self) -> None:
        """Test cover page generation."""
        cover = self.generator._generate_cover("January 01, 2025")

        self.assertIn('class="cover"', cover)
        self.assertIn("NIST CSF 2.0", cover)
        self.assertIn("Test Corp", cover)
        self.assertIn("January 01, 2025", cover)
        self.assertIn('class="page-break"', cover)

    def test_generate_cover_without_logo(self) -> None:
        """Test cover page without logo."""
        cover = self.generator._generate_cover("January 01, 2025")

        # Should not have img tag when no logo
        self.assertNotIn("<img", cover)

    def test_generate_cover_with_logo(self) -> None:
        """Test cover page with logo."""
        import tempfile

        # Create a temporary file to act as logo
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            logo_path = Path(f.name)
            f.write(b"fake png data")

        try:
            config = ReportConfig(organization="Test Corp", logo_path=logo_path)
            generator = PdfReportGenerator(config)

            cover = generator._generate_cover("January 01, 2025")

            # Should have img tag with logo path
            self.assertIn("<img", cover)
            self.assertIn(str(logo_path), cover)
            self.assertIn('class="logo"', cover)
        finally:
            logo_path.unlink()

    def test_generate_executive_section(self) -> None:
        """Test executive section generation."""
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        section = self.generator._generate_executive_section(maturity, gaps, None)

        self.assertIn("Executive Summary", section)
        self.assertIn('class="overall-score"', section)
        self.assertIn('class="stats-grid"', section)
        self.assertIn("Key Metrics", section)
        self.assertIn("Key Findings", section)

    def test_generate_maturity_section(self) -> None:
        """Test maturity scores section generation."""
        maturity = self._create_maturity_breakdown()

        section = self.generator._generate_maturity_section(maturity)

        self.assertIn("Maturity Scores by Function", section)
        self.assertIn("<table>", section)
        self.assertIn("Governance", section)
        self.assertIn("Protect", section)
        self.assertIn("Detect", section)
        self.assertIn('class="maturity-bar"', section)

    def test_generate_gaps_section(self) -> None:
        """Test gap analysis section generation."""
        gaps = self._create_gap_analysis()

        section = self.generator._generate_gaps_section(gaps)

        self.assertIn("Gap Analysis", section)
        self.assertIn('class="stats-grid"', section)
        self.assertIn("Gap Distribution", section)
        self.assertIn("Priority Gaps", section)
        self.assertIn('class="gap-card"', section)
        self.assertIn("PR.AC-01", section)
        self.assertIn('class="priority-badge', section)

    def test_generate_gaps_section_limits_gaps(self) -> None:
        """Test gap section limits number of displayed gaps."""
        config = ReportConfig(organization="Test Corp", include_all_gaps=False)
        generator = PdfReportGenerator(config)
        gaps = self._create_gap_analysis()

        section = generator._generate_gaps_section(gaps)

        # Should contain gaps (we only have 2 anyway)
        self.assertIn("gap-card", section)

    def test_generate_trends_section(self) -> None:
        """Test trends section generation."""
        trends = self._create_trend_analysis()

        section = self.generator._generate_trends_section(trends)

        self.assertIn("Trend Analysis", section)
        self.assertIn("Improving", section)
        self.assertIn("30 days", section)
        self.assertIn('class="stats-grid"', section)

    def test_generate_trends_section_negative_delta(self) -> None:
        """Test trends section with negative delta."""
        trends = self._create_trend_analysis(TrendDirection.REGRESSING)

        section = self.generator._generate_trends_section(trends)

        self.assertIn("Regressing", section)

    def test_generate_evidence_section(self) -> None:
        """Test evidence appendix section generation."""
        evidence = [
            {"platform": "okta", "evidence_type": "user_inventory", "collected_at": "2025-01-01T00:00:00Z"},
            {"platform": "okta", "evidence_type": "mfa_report", "collected_at": "2025-01-01T00:00:00Z"},
            {"platform": "aws", "evidence_type": "iam_users", "collected_at": "2025-01-01T00:00:00Z"},
        ]

        section = self.generator._generate_evidence_section(evidence)

        self.assertIn("Evidence Appendix", section)
        self.assertIn("OKTA", section)
        self.assertIn("AWS", section)
        self.assertIn('class="evidence-list"', section)

    def test_generate_footer(self) -> None:
        """Test footer generation."""
        footer = self.generator._generate_footer()

        self.assertIn('class="footer"', footer)
        self.assertIn("Nisify", footer)
        self.assertIn("Report generated:", footer)

    def test_generate_footer_custom_text(self) -> None:
        """Test footer with custom text."""
        config = ReportConfig(footer_text="Custom Footer Text")
        generator = PdfReportGenerator(config)

        footer = generator._generate_footer()

        self.assertIn("Custom Footer Text", footer)

    def test_get_report_metadata(self) -> None:
        """Test report metadata generation."""
        maturity = self._create_maturity_breakdown(overall_level=3)
        gaps = self._create_gap_analysis()

        metadata = self.generator.get_report_metadata(maturity, gaps)

        self.assertEqual(metadata["organization"], "Test Corp")
        self.assertEqual(metadata["overall_maturity"], 3)
        self.assertAlmostEqual(metadata["overall_score"], 3.5, places=1)
        self.assertEqual(metadata["total_gaps"], 25)
        self.assertIn("pdf_available", metadata)
        self.assertEqual(metadata["generator_version"], "0.1.0")

    def test_get_report_metadata_with_date(self) -> None:
        """Test report metadata with custom date."""
        report_date = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
        config = ReportConfig(organization="Test Corp", report_date=report_date)
        generator = PdfReportGenerator(config)

        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        metadata = generator.get_report_metadata(maturity, gaps)

        self.assertIn("2025-01-15", metadata["report_date"])


class TestPdfReportGeneratorWithWeasyprint(unittest.TestCase):
    """Tests for PDF generation with mocked weasyprint."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.config = ReportConfig(organization="Test Corp")
        self.now = datetime.now(UTC)
        self.temp_dir = tempfile.mkdtemp()

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        score: float,
        evidence_count: int = 10,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.FUNCTION,
            level=level,
            score=score,
            evidence_count=evidence_count,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(self, overall_level: int = 2) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score(
                "overall", overall_level, float(overall_level) + 0.5
            ),
            by_function={
                "GV": self._create_maturity_score("GV", 2, 2.3),
                "ID": self._create_maturity_score("ID", 2, 2.1),
                "PR": self._create_maturity_score("PR", 3, 3.0),
                "DE": self._create_maturity_score("DE", 2, 2.5),
                "RS": self._create_maturity_score("RS", 1, 1.5),
                "RC": self._create_maturity_score("RC", 2, 2.0),
            },
            by_category={},
            by_subcategory={},
            timestamp=self.now,
            statistics={
                "total_subcategories": 106,
                "subcategories_with_evidence": 50,
            },
        )

    def _create_gap_analysis(self) -> GapAnalysis:
        """Helper to create GapAnalysis."""
        gap = Gap(
            control_id="PR.AC-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AC",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.CRITICAL,
            explanation="Control needs improvement due to lack of MFA enforcement.",
            recommendations=[
                Recommendation(
                    gap_id="PR.AC-01",
                    action="Enable MFA enforcement for all users",
                    platform="okta",
                    effort=Effort.LOW,
                    impact=Impact.HIGH,
                    details="Enable MFA.",
                )
            ],
        )

        return GapAnalysis(
            timestamp=self.now,
            total_controls=100,
            controls_with_gaps=25,
            gap_percentage=25.0,
            gaps_by_priority={"critical": 5, "high": 10, "medium": 7, "low": 3},
            gaps_by_function={"PR": [gap]},
            gaps_by_type={"low_maturity": 25},
            all_gaps=[gap],
            top_recommendations=[gap.recommendations[0]],
            quick_wins=[gap],
            critical_gaps=[gap],
        )

    def test_generate_report_with_weasyprint_success(self) -> None:
        """Test PDF generation with mocked weasyprint."""
        from unittest.mock import MagicMock, patch

        import nisify.reports.pdf_generator as pdf_module

        # Create generator
        generator = PdfReportGenerator(self.config)
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        # Create mocks
        mock_html_class = MagicMock()
        mock_css_class = MagicMock()
        mock_html_instance = MagicMock()
        mock_html_class.return_value = mock_html_instance

        def write_pdf_side_effect(path, stylesheets=None):
            # Write the mock PDF content to the actual path
            path.write_bytes(b"mock pdf content" * 5000)  # ~80KB = ~1 page

        mock_html_instance.write_pdf.side_effect = write_pdf_side_effect

        # Patch module attributes
        with patch.object(pdf_module, "WEASYPRINT_AVAILABLE", True):
            with patch.object(pdf_module, "HTML", mock_html_class, create=True):
                with patch.object(pdf_module, "CSS", mock_css_class, create=True):
                    result = generator.generate_report(maturity, gaps, output_dir=Path(self.temp_dir))

                    # Verify HTML was created
                    self.assertTrue(result.success)
                    self.assertIsNotNone(result.html_path)
                    self.assertTrue(result.html_path.exists())

                    # Verify PDF was created and size calculated
                    self.assertIsNotNone(result.pdf_path)
                    self.assertTrue(result.pdf_path.exists())
                    self.assertGreater(result.size_bytes, 0)
                    self.assertGreater(result.page_count, 0)

                    # Verify mocks were called
                    mock_html_class.assert_called_once()
                    mock_css_class.assert_called_once()
                    mock_html_instance.write_pdf.assert_called_once()

    def test_generate_report_weasyprint_exception(self) -> None:
        """Test PDF generation when weasyprint throws an exception."""
        from unittest.mock import MagicMock, patch

        import nisify.reports.pdf_generator as pdf_module

        # Create generator
        generator = PdfReportGenerator(self.config)
        maturity = self._create_maturity_breakdown()
        gaps = self._create_gap_analysis()

        # Create mocks that raise exception
        mock_html_class = MagicMock(side_effect=Exception("PDF generation error"))
        mock_css_class = MagicMock()

        # Patch module attributes
        with patch.object(pdf_module, "WEASYPRINT_AVAILABLE", True):
            with patch.object(pdf_module, "HTML", mock_html_class, create=True):
                with patch.object(pdf_module, "CSS", mock_css_class, create=True):
                    result = generator.generate_report(maturity, gaps, output_dir=Path(self.temp_dir))

                    # Should fail but HTML should still exist
                    self.assertFalse(result.success)
                    self.assertIsNotNone(result.html_path)
                    self.assertTrue(result.html_path.exists())
                    self.assertIsNone(result.pdf_path)
                    self.assertIn("PDF generation failed", result.error)


class TestReportCSS(unittest.TestCase):
    """Tests for REPORT_CSS constant."""

    def test_css_contains_page_rules(self) -> None:
        """Test CSS contains page rules."""
        self.assertIn("@page", REPORT_CSS)
        self.assertIn("size: letter", REPORT_CSS)

    def test_css_contains_cover_styles(self) -> None:
        """Test CSS contains cover page styles."""
        self.assertIn(".cover", REPORT_CSS)
        self.assertIn("page: cover", REPORT_CSS)

    def test_css_contains_table_styles(self) -> None:
        """Test CSS contains table styles."""
        self.assertIn("table", REPORT_CSS)
        self.assertIn("border-collapse", REPORT_CSS)

    def test_css_contains_maturity_bar(self) -> None:
        """Test CSS contains maturity bar styles."""
        self.assertIn(".maturity-bar", REPORT_CSS)

    def test_css_contains_priority_badges(self) -> None:
        """Test CSS contains priority badge styles."""
        self.assertIn(".priority-badge", REPORT_CSS)
        self.assertIn(".priority-critical", REPORT_CSS)
        self.assertIn(".priority-high", REPORT_CSS)
        self.assertIn(".priority-medium", REPORT_CSS)
        self.assertIn(".priority-low", REPORT_CSS)

    def test_css_contains_gap_cards(self) -> None:
        """Test CSS contains gap card styles."""
        self.assertIn(".gap-card", REPORT_CSS)

    def test_css_contains_print_media(self) -> None:
        """Test CSS contains print media query."""
        self.assertIn("@media print", REPORT_CSS)

    def test_css_is_monochrome(self) -> None:
        """Test CSS uses monochrome color scheme."""
        # Should not contain typical color values like red, green, blue
        # (but #ffffff white is valid grayscale)
        self.assertNotIn("#ff0000", REPORT_CSS.lower())  # red
        self.assertNotIn("#00ff00", REPORT_CSS.lower())  # green
        self.assertNotIn("#0000ff", REPORT_CSS.lower())  # blue
        self.assertNotIn("rgb(", REPORT_CSS.lower())
        # Should contain grayscale colors
        self.assertIn("#333333", REPORT_CSS)
        self.assertIn("#666666", REPORT_CSS)
        self.assertIn("#ffffff", REPORT_CSS.lower())  # white is valid


if __name__ == "__main__":
    unittest.main()
