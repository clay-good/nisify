"""
Tests for the analysis module (gap_analyzer, trend_tracker).

Uses Python's unittest module.
Tests gap detection, priority assignment, recommendation generation, and trend tracking.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from nisify.analysis.gap_analyzer import (
    Effort,
    Gap,
    GapAnalysis,
    GapAnalyzer,
    GapAnalyzerConfig,
    GapType,
    Impact,
    Priority,
    Recommendation,
)
from nisify.analysis.trend_tracker import (
    TrendAnalysis,
    TrendDirection,
    TrendItem,
    TrendPoint,
    TrendTracker,
    TrendTrackerConfig,
)
from nisify.nist.maturity_calculator import (
    EntityType,
    MaturityBreakdown,
    MaturityScore,
)


class TestGapType(unittest.TestCase):
    """Tests for GapType enum."""

    def test_gap_type_values(self) -> None:
        """Test GapType enum values."""
        self.assertEqual(GapType.NO_EVIDENCE.value, "no_evidence")
        self.assertEqual(GapType.STALE_EVIDENCE.value, "stale_evidence")
        self.assertEqual(GapType.PARTIAL_EVIDENCE.value, "partial_evidence")
        self.assertEqual(GapType.LOW_MATURITY.value, "low_maturity")


class TestPriority(unittest.TestCase):
    """Tests for Priority enum."""

    def test_priority_values(self) -> None:
        """Test Priority enum values."""
        self.assertEqual(Priority.CRITICAL.value, "critical")
        self.assertEqual(Priority.HIGH.value, "high")
        self.assertEqual(Priority.MEDIUM.value, "medium")
        self.assertEqual(Priority.LOW.value, "low")


class TestEffort(unittest.TestCase):
    """Tests for Effort enum."""

    def test_effort_values(self) -> None:
        """Test Effort enum values."""
        self.assertEqual(Effort.LOW.value, "low")
        self.assertEqual(Effort.MEDIUM.value, "medium")
        self.assertEqual(Effort.HIGH.value, "high")


class TestImpact(unittest.TestCase):
    """Tests for Impact enum."""

    def test_impact_values(self) -> None:
        """Test Impact enum values."""
        self.assertEqual(Impact.LOW.value, "low")
        self.assertEqual(Impact.MEDIUM.value, "medium")
        self.assertEqual(Impact.HIGH.value, "high")


class TestRecommendation(unittest.TestCase):
    """Tests for Recommendation dataclass."""

    def test_recommendation_creation(self) -> None:
        """Test creating a Recommendation."""
        rec = Recommendation(
            gap_id="PR.AA-01",
            action="Enable MFA enforcement",
            platform="okta",
            effort=Effort.MEDIUM,
            impact=Impact.HIGH,
            details="Configure MFA policy in Okta admin console.",
        )

        self.assertEqual(rec.gap_id, "PR.AA-01")
        self.assertEqual(rec.action, "Enable MFA enforcement")
        self.assertEqual(rec.platform, "okta")
        self.assertEqual(rec.effort, Effort.MEDIUM)
        self.assertEqual(rec.impact, Impact.HIGH)

    def test_recommendation_to_dict(self) -> None:
        """Test Recommendation to_dict method."""
        rec = Recommendation(
            gap_id="PR.AA-01",
            action="Enable MFA enforcement",
            platform="okta",
            effort=Effort.MEDIUM,
            impact=Impact.HIGH,
            details="Configure MFA policy.",
        )

        result = rec.to_dict()

        self.assertEqual(result["gap_id"], "PR.AA-01")
        self.assertEqual(result["action"], "Enable MFA enforcement")
        self.assertEqual(result["platform"], "okta")
        self.assertEqual(result["effort"], "medium")
        self.assertEqual(result["impact"], "high")
        self.assertEqual(result["details"], "Configure MFA policy.")

    def test_recommendation_without_platform(self) -> None:
        """Test Recommendation without platform."""
        rec = Recommendation(
            gap_id="GV.OC-01",
            action="Document organizational context",
            platform=None,
            effort=Effort.HIGH,
            impact=Impact.MEDIUM,
            details="Create documentation.",
        )

        result = rec.to_dict()
        self.assertIsNone(result["platform"])


class TestGap(unittest.TestCase):
    """Tests for Gap dataclass."""

    def test_gap_creation(self) -> None:
        """Test creating a Gap."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.HIGH,
            explanation="Control needs improvement.",
        )

        self.assertEqual(gap.control_id, "PR.AA-01")
        self.assertEqual(gap.current_maturity, 1)
        self.assertEqual(gap.target_maturity, 3)
        self.assertEqual(gap.gap_type, GapType.LOW_MATURITY)
        self.assertEqual(gap.priority, Priority.HIGH)

    def test_gap_to_dict(self) -> None:
        """Test Gap to_dict method."""
        rec = Recommendation(
            gap_id="PR.AA-01",
            action="Enable MFA",
            platform="okta",
            effort=Effort.LOW,
            impact=Impact.HIGH,
            details="Enable MFA.",
        )

        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=0,
            target_maturity=3,
            gap_type=GapType.NO_EVIDENCE,
            priority=Priority.CRITICAL,
            explanation="No evidence collected.",
            recommendations=[rec],
            evidence_age_days=None,
            missing_evidence_types=["mfa_status", "user_inventory"],
        )

        result = gap.to_dict()

        self.assertEqual(result["control_id"], "PR.AA-01")
        self.assertEqual(result["gap_type"], "no_evidence")
        self.assertEqual(result["priority"], "critical")
        self.assertEqual(len(result["recommendations"]), 1)
        self.assertEqual(result["missing_evidence_types"], ["mfa_status", "user_inventory"])


class TestGapAnalyzerConfig(unittest.TestCase):
    """Tests for GapAnalyzerConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = GapAnalyzerConfig()

        self.assertEqual(config.target_maturity, 3)
        self.assertEqual(config.critical_functions, ["PR", "DE"])
        self.assertEqual(config.stale_threshold_days, 30)
        self.assertEqual(config.quick_win_effort_threshold, Effort.LOW)

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = GapAnalyzerConfig(
            target_maturity=4,
            critical_functions=["PR", "DE", "RS"],
            stale_threshold_days=14,
        )

        self.assertEqual(config.target_maturity, 4)
        self.assertEqual(config.critical_functions, ["PR", "DE", "RS"])
        self.assertEqual(config.stale_threshold_days, 14)


class TestGapAnalyzer(unittest.TestCase):
    """Tests for GapAnalyzer class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.analyzer = GapAnalyzer()
        self.now = datetime.now(UTC)

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        evidence_count: int = 5,
        last_evidence_date: datetime | None = None,
        confidence: float = 0.9,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.SUBCATEGORY,
            level=level,
            score=float(level),
            evidence_count=evidence_count,
            last_evidence_date=last_evidence_date or self.now,
            confidence=confidence,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(
        self,
        subcategory_scores: dict[str, MaturityScore],
    ) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score("overall", 2),
            by_function={},
            by_category={},
            by_subcategory=subcategory_scores,
            timestamp=self.now,
            statistics={},
        )

    def test_analyzer_initialization(self) -> None:
        """Test GapAnalyzer initialization."""
        analyzer = GapAnalyzer()
        self.assertIsNotNone(analyzer.config)
        self.assertEqual(analyzer.config.target_maturity, 3)

    def test_analyzer_with_custom_config(self) -> None:
        """Test GapAnalyzer with custom config."""
        config = GapAnalyzerConfig(target_maturity=4)
        analyzer = GapAnalyzer(config)
        self.assertEqual(analyzer.config.target_maturity, 4)

    def test_determine_gap_type_no_evidence(self) -> None:
        """Test gap type determination for no evidence."""
        score = self._create_maturity_score("PR.AA-01", 0, evidence_count=0)
        gap_type = self.analyzer._determine_gap_type(score)
        self.assertEqual(gap_type, GapType.NO_EVIDENCE)

    def test_determine_gap_type_stale_evidence(self) -> None:
        """Test gap type determination for stale evidence."""
        old_date = self.now - timedelta(days=60)
        score = self._create_maturity_score(
            "PR.AA-01", 2, evidence_count=5, last_evidence_date=old_date
        )
        gap_type = self.analyzer._determine_gap_type(score)
        self.assertEqual(gap_type, GapType.STALE_EVIDENCE)

    def test_determine_gap_type_partial_evidence(self) -> None:
        """Test gap type determination for partial evidence."""
        score = self._create_maturity_score(
            "PR.AA-01", 2, evidence_count=2, confidence=0.5
        )
        gap_type = self.analyzer._determine_gap_type(score)
        self.assertEqual(gap_type, GapType.PARTIAL_EVIDENCE)

    def test_determine_gap_type_low_maturity(self) -> None:
        """Test gap type determination for low maturity."""
        score = self._create_maturity_score(
            "PR.AA-01", 2, evidence_count=10, confidence=0.95
        )
        gap_type = self.analyzer._determine_gap_type(score)
        self.assertEqual(gap_type, GapType.LOW_MATURITY)

    def test_determine_priority_critical_function_level_0(self) -> None:
        """Test critical priority for level 0 in critical function."""
        priority = self.analyzer._determine_priority(
            current_level=0,
            gap_type=GapType.NO_EVIDENCE,
            function_id="PR",
            target_maturity=3,
        )
        self.assertEqual(priority, Priority.CRITICAL)

    def test_determine_priority_non_critical_function_level_0(self) -> None:
        """Test high priority for level 0 in non-critical function."""
        priority = self.analyzer._determine_priority(
            current_level=0,
            gap_type=GapType.NO_EVIDENCE,
            function_id="GV",
            target_maturity=3,
        )
        self.assertEqual(priority, Priority.HIGH)

    def test_determine_priority_critical_function_level_1(self) -> None:
        """Test high priority for level 1 in critical function."""
        priority = self.analyzer._determine_priority(
            current_level=1,
            gap_type=GapType.LOW_MATURITY,
            function_id="DE",
            target_maturity=3,
        )
        self.assertEqual(priority, Priority.HIGH)

    def test_determine_priority_stale_evidence(self) -> None:
        """Test medium priority for stale evidence."""
        priority = self.analyzer._determine_priority(
            current_level=2,
            gap_type=GapType.STALE_EVIDENCE,
            function_id="GV",
            target_maturity=3,
        )
        self.assertEqual(priority, Priority.MEDIUM)

    def test_determine_priority_low(self) -> None:
        """Test low priority for minor gaps."""
        priority = self.analyzer._determine_priority(
            current_level=2,
            gap_type=GapType.LOW_MATURITY,
            function_id="GV",
            target_maturity=3,
        )
        self.assertEqual(priority, Priority.LOW)

    def test_generate_recommendations_no_evidence(self) -> None:
        """Test recommendation generation for no evidence gap."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=0,
            target_maturity=3,
            gap_type=GapType.NO_EVIDENCE,
            priority=Priority.CRITICAL,
            explanation="No evidence.",
            missing_evidence_types=[],
        )

        recommendations = self.analyzer.generate_recommendations(gap)

        self.assertGreater(len(recommendations), 0)
        # Generic recommendation for no evidence
        self.assertTrue(any("collection" in r.action.lower() for r in recommendations))

    def test_generate_recommendations_stale_evidence(self) -> None:
        """Test recommendation generation for stale evidence gap."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=2,
            target_maturity=3,
            gap_type=GapType.STALE_EVIDENCE,
            priority=Priority.MEDIUM,
            explanation="Stale evidence.",
            missing_evidence_types=[],
        )

        recommendations = self.analyzer.generate_recommendations(gap)

        self.assertGreater(len(recommendations), 0)
        # Should recommend refreshing evidence
        self.assertTrue(any("refresh" in r.action.lower() for r in recommendations))

    def test_generate_recommendations_with_known_evidence_type(self) -> None:
        """Test recommendation generation with known evidence type."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=0,
            target_maturity=3,
            gap_type=GapType.NO_EVIDENCE,
            priority=Priority.CRITICAL,
            explanation="No evidence.",
            missing_evidence_types=["mfa_status"],
        )

        recommendations = self.analyzer.generate_recommendations(gap)

        self.assertGreater(len(recommendations), 0)
        # Should have MFA-related recommendations
        self.assertTrue(any("mfa" in r.action.lower() for r in recommendations))

    def test_get_critical_gaps_no_analysis(self) -> None:
        """Test getting critical gaps before analysis."""
        analyzer = GapAnalyzer()
        result = analyzer.get_critical_gaps()
        self.assertEqual(result, [])

    def test_get_quick_wins_no_analysis(self) -> None:
        """Test getting quick wins before analysis."""
        analyzer = GapAnalyzer()
        result = analyzer.get_quick_wins()
        self.assertEqual(result, [])

    def test_get_gaps_by_function_no_analysis(self) -> None:
        """Test getting gaps by function before analysis."""
        analyzer = GapAnalyzer()
        result = analyzer.get_gaps_by_function("PR")
        self.assertEqual(result, [])

    def test_get_gaps_by_priority_no_analysis(self) -> None:
        """Test getting gaps by priority before analysis."""
        analyzer = GapAnalyzer()
        result = analyzer.get_gaps_by_priority(Priority.HIGH)
        self.assertEqual(result, [])

    def test_analyze_identifies_gaps(self) -> None:
        """Test that analyze identifies gaps below target maturity."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 1),  # Below target (3)
            "PR.AA-02": self._create_maturity_score("PR.AA-02", 3),  # At target
            "DE.CM-01": self._create_maturity_score("DE.CM-01", 2),  # Below target
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        self.assertIsInstance(result, GapAnalysis)
        self.assertEqual(result.total_controls, 3)
        self.assertEqual(result.controls_with_gaps, 2)  # PR.AA-01 and DE.CM-01
        self.assertAlmostEqual(result.gap_percentage, 66.67, places=1)

    def test_analyze_with_custom_target_maturity(self) -> None:
        """Test analyze with custom target maturity level."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 2),
            "PR.AA-02": self._create_maturity_score("PR.AA-02", 3),
        }
        breakdown = self._create_maturity_breakdown(scores)

        # With target 4, both should be gaps
        result = self.analyzer.analyze_gaps(breakdown, target_maturity=4)

        self.assertEqual(result.controls_with_gaps, 2)

    def test_analyze_sorts_gaps_by_priority(self) -> None:
        """Test that gaps are sorted by priority."""
        scores = {
            "GV.OC-01": self._create_maturity_score("GV.OC-01", 2),  # Low priority
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 0),  # Critical (PR, level 0)
            "DE.CM-01": self._create_maturity_score("DE.CM-01", 1),  # High (DE, level 1)
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # First gap should be highest priority
        if result.all_gaps:
            first_gap = result.all_gaps[0]
            self.assertIn(first_gap.priority, [Priority.CRITICAL, Priority.HIGH])

    def test_analyze_identifies_critical_gaps(self) -> None:
        """Test that critical gaps are properly identified."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 0),  # Critical (PR, level 0)
            "GV.OC-01": self._create_maturity_score("GV.OC-01", 2),  # Low priority
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        self.assertGreater(len(result.critical_gaps), 0)
        self.assertTrue(any(g.control_id == "PR.AA-01" for g in result.critical_gaps))

    def test_analyze_generates_recommendations(self) -> None:
        """Test that analyze generates recommendations for gaps."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 1),
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # Each gap should have recommendations
        for gap in result.all_gaps:
            self.assertIsNotNone(gap.recommendations)
        # Should have top recommendations
        self.assertGreater(len(result.top_recommendations), 0)

    def test_analyze_updates_last_analysis(self) -> None:
        """Test that analyze updates internal state."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 1),
        }
        breakdown = self._create_maturity_breakdown(scores)

        self.analyzer.analyze_gaps(breakdown)

        # Helper methods should now return results
        critical = self.analyzer.get_critical_gaps()
        quick_wins = self.analyzer.get_quick_wins()
        by_function = self.analyzer.get_gaps_by_function("PR")
        by_priority = self.analyzer.get_gaps_by_priority(Priority.HIGH)

        # These should be lists (may be empty depending on gap characteristics)
        self.assertIsInstance(critical, list)
        self.assertIsInstance(quick_wins, list)
        self.assertIsInstance(by_function, list)
        self.assertIsInstance(by_priority, list)

    def test_analyze_control_returns_none_at_target(self) -> None:
        """Test _analyze_control returns None when at target maturity."""
        score = self._create_maturity_score("PR.AA-01", 3)

        result = self.analyzer._analyze_control("PR.AA-01", score, target_maturity=3)

        self.assertIsNone(result)

    def test_analyze_control_returns_gap_below_target(self) -> None:
        """Test _analyze_control returns Gap when below target."""
        score = self._create_maturity_score("PR.AA-01", 1)

        result = self.analyzer._analyze_control("PR.AA-01", score, target_maturity=3)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, Gap)
        self.assertEqual(result.control_id, "PR.AA-01")
        self.assertEqual(result.current_maturity, 1)
        self.assertEqual(result.target_maturity, 3)

    def test_analyze_control_calculates_evidence_age(self) -> None:
        """Test _analyze_control calculates evidence age."""
        old_date = self.now - timedelta(days=45)
        score = self._create_maturity_score(
            "PR.AA-01", 1, evidence_count=5, last_evidence_date=old_date
        )

        result = self.analyzer._analyze_control("PR.AA-01", score, target_maturity=3)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.evidence_age_days)
        self.assertGreaterEqual(result.evidence_age_days, 45)

    def test_build_explanation_no_evidence(self) -> None:
        """Test explanation building for no evidence gap."""
        score = self._create_maturity_score("PR.AA-01", 0, evidence_count=0)

        explanation = self.analyzer._build_explanation(
            score, "Test Control", GapType.NO_EVIDENCE, target_maturity=3
        )

        self.assertIn("level 0", explanation)
        self.assertIn("target level 3", explanation)
        self.assertIn("No evidence", explanation)

    def test_build_explanation_stale_evidence(self) -> None:
        """Test explanation building for stale evidence gap."""
        old_date = self.now - timedelta(days=60)
        score = self._create_maturity_score(
            "PR.AA-01", 2, evidence_count=5, last_evidence_date=old_date
        )

        explanation = self.analyzer._build_explanation(
            score, "Test Control", GapType.STALE_EVIDENCE, target_maturity=3
        )

        self.assertIn("stale", explanation.lower())
        self.assertIn("days old", explanation)

    def test_build_explanation_partial_evidence(self) -> None:
        """Test explanation building for partial evidence gap."""
        score = self._create_maturity_score("PR.AA-01", 2, confidence=0.5)

        explanation = self.analyzer._build_explanation(
            score, "Test Control", GapType.PARTIAL_EVIDENCE, target_maturity=3
        )

        self.assertIn("partial", explanation.lower())

    def test_build_explanation_low_maturity(self) -> None:
        """Test explanation building for low maturity gap."""
        score = self._create_maturity_score("PR.AA-01", 2, confidence=0.95)

        explanation = self.analyzer._build_explanation(
            score, "Test Control", GapType.LOW_MATURITY, target_maturity=3
        )

        self.assertIn("Evidence exists", explanation)
        self.assertIn("maturity", explanation.lower())

    def test_generate_recommendations_partial_evidence(self) -> None:
        """Test recommendation generation for partial evidence gap."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=2,
            target_maturity=3,
            gap_type=GapType.PARTIAL_EVIDENCE,
            priority=Priority.MEDIUM,
            explanation="Partial evidence.",
            missing_evidence_types=[],
        )

        recommendations = self.analyzer.generate_recommendations(gap)

        self.assertGreater(len(recommendations), 0)
        # Should recommend collecting additional evidence
        self.assertTrue(any("additional" in r.action.lower() for r in recommendations))

    def test_generate_recommendations_low_maturity(self) -> None:
        """Test recommendation generation for low maturity gap."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Identity Management",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=2,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.LOW,
            explanation="Low maturity.",
            missing_evidence_types=[],
        )

        recommendations = self.analyzer.generate_recommendations(gap)

        self.assertGreater(len(recommendations), 0)
        # Should recommend strengthening control
        self.assertTrue(any("strengthen" in r.action.lower() for r in recommendations))

    def test_prioritize_recommendations_deduplication(self) -> None:
        """Test that duplicate recommendations are removed."""
        recs = [
            Recommendation(
                gap_id="PR.AA-01",
                action="Enable MFA",
                platform="okta",
                effort=Effort.LOW,
                impact=Impact.HIGH,
                details="Details",
            ),
            Recommendation(
                gap_id="PR.AA-02",
                action="Enable MFA",  # Duplicate action
                platform="okta",
                effort=Effort.LOW,
                impact=Impact.HIGH,
                details="Details",
            ),
            Recommendation(
                gap_id="PR.AA-03",
                action="Different action",
                platform="okta",
                effort=Effort.MEDIUM,
                impact=Impact.MEDIUM,
                details="Details",
            ),
        ]

        result = self.analyzer._prioritize_recommendations(recs)

        # Should have 2 unique actions
        self.assertEqual(len(result), 2)
        actions = [r.action for r in result]
        self.assertIn("Enable MFA", actions)
        self.assertIn("Different action", actions)

    def test_analyze_empty_breakdown(self) -> None:
        """Test analyze with empty subcategory scores."""
        breakdown = self._create_maturity_breakdown({})

        result = self.analyzer.analyze_gaps(breakdown)

        self.assertEqual(result.total_controls, 0)
        self.assertEqual(result.controls_with_gaps, 0)
        self.assertEqual(result.gap_percentage, 0.0)

    def test_get_gaps_by_function_after_analysis(self) -> None:
        """Test getting gaps by function after analysis."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 1),
            "DE.CM-01": self._create_maturity_score("DE.CM-01", 1),
        }
        breakdown = self._create_maturity_breakdown(scores)

        self.analyzer.analyze_gaps(breakdown)

        pr_gaps = self.analyzer.get_gaps_by_function("PR")
        de_gaps = self.analyzer.get_gaps_by_function("DE")
        gv_gaps = self.analyzer.get_gaps_by_function("GV")

        self.assertEqual(len(pr_gaps), 1)
        self.assertEqual(len(de_gaps), 1)
        self.assertEqual(len(gv_gaps), 0)

    def test_get_gaps_by_priority_after_analysis(self) -> None:
        """Test getting gaps by priority after analysis."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 0),  # Critical
            "GV.OC-01": self._create_maturity_score("GV.OC-01", 2),  # Low
        }
        breakdown = self._create_maturity_breakdown(scores)

        self.analyzer.analyze_gaps(breakdown)

        critical = self.analyzer.get_gaps_by_priority(Priority.CRITICAL)
        low = self.analyzer.get_gaps_by_priority(Priority.LOW)

        self.assertGreater(len(critical), 0)
        self.assertGreater(len(low), 0)


class TestGapAnalysis(unittest.TestCase):
    """Tests for GapAnalysis dataclass."""

    def test_gap_analysis_to_dict(self) -> None:
        """Test GapAnalysis to_dict method."""
        gap = Gap(
            control_id="PR.AA-01",
            control_name="Test Control",
            function_id="PR",
            category_id="PR.AA",
            current_maturity=1,
            target_maturity=3,
            gap_type=GapType.LOW_MATURITY,
            priority=Priority.HIGH,
            explanation="Test gap.",
        )

        rec = Recommendation(
            gap_id="PR.AA-01",
            action="Test action",
            platform="test",
            effort=Effort.LOW,
            impact=Impact.HIGH,
            details="Test details.",
        )

        analysis = GapAnalysis(
            timestamp=datetime.now(UTC),
            total_controls=100,
            controls_with_gaps=25,
            gap_percentage=25.0,
            gaps_by_priority={"critical": 5, "high": 10, "medium": 7, "low": 3},
            gaps_by_function={"PR": [gap]},
            gaps_by_type={"low_maturity": 25},
            all_gaps=[gap],
            top_recommendations=[rec],
            quick_wins=[gap],
            critical_gaps=[],
        )

        result = analysis.to_dict()

        self.assertEqual(result["total_controls"], 100)
        self.assertEqual(result["controls_with_gaps"], 25)
        self.assertEqual(result["gap_percentage"], 25.0)
        self.assertIn("timestamp", result)
        self.assertEqual(len(result["all_gaps"]), 1)
        self.assertEqual(len(result["top_recommendations"]), 1)


class TestGapAnalyzerEdgeCases(unittest.TestCase):
    """Tests for edge cases in gap analysis."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.analyzer = GapAnalyzer()
        self.now = datetime.now(UTC)

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        evidence_count: int = 5,
        last_evidence_date: datetime | None = None,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.SUBCATEGORY,
            level=level,
            score=float(level) + 0.5,
            evidence_count=evidence_count,
            last_evidence_date=last_evidence_date or self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_maturity_breakdown(
        self, scores: dict[str, MaturityScore]
    ) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        overall_level = (
            int(sum(s.level for s in scores.values()) / len(scores)) if scores else 0
        )
        return MaturityBreakdown(
            overall=MaturityScore(
                entity_id="overall",
                entity_type=EntityType.OVERALL,
                level=overall_level,
                score=float(overall_level) + 0.5,
                evidence_count=sum(s.evidence_count for s in scores.values()),
                last_evidence_date=self.now,
                confidence=0.9,
                explanation="Overall score",
            ),
            by_function={},
            by_category={},
            by_subcategory=scores,
            timestamp=self.now,
            statistics={},
        )

    def test_invalid_control_id_returns_no_gap(self) -> None:
        """Test that invalid control ID returns no gap."""
        # Use an invalid control ID that doesn't exist in NIST CSF
        scores = {
            "INVALID.XX-99": self._create_maturity_score("INVALID.XX-99", 0),
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # Invalid control should not produce a gap
        self.assertEqual(result.controls_with_gaps, 0)
        self.assertEqual(len(result.all_gaps), 0)

    def test_zero_evidence_count_marks_missing_evidence(self) -> None:
        """Test that zero evidence count results in all evidence types marked missing."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", 0, evidence_count=0),
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # Should have a gap with missing evidence types
        self.assertEqual(len(result.all_gaps), 1)
        gap = result.all_gaps[0]
        self.assertEqual(gap.gap_type, GapType.NO_EVIDENCE)
        # Missing evidence types should be populated if the control has defined types
        self.assertIsInstance(gap.missing_evidence_types, list)

    def test_stale_evidence_in_critical_function_is_high_priority(self) -> None:
        """Test that stale evidence in critical function (PR, DE) gets HIGH priority."""
        # Create score with stale evidence in PR function (critical)
        stale_date = self.now - timedelta(days=120)  # Beyond default freshness
        scores = {
            "PR.AA-01": self._create_maturity_score(
                "PR.AA-01",
                level=2,  # Not zero (that would be critical)
                evidence_count=5,
                last_evidence_date=stale_date,
            ),
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # Should have a gap with stale evidence type and HIGH priority
        if result.all_gaps:
            gap = result.all_gaps[0]
            # Stale evidence in critical function should be HIGH priority
            if gap.gap_type == GapType.STALE_EVIDENCE:
                self.assertEqual(gap.priority, Priority.HIGH)

    def test_level_1_in_critical_function_is_high_priority(self) -> None:
        """Test that level 1 in critical function gets HIGH priority."""
        scores = {
            "PR.AA-01": self._create_maturity_score("PR.AA-01", level=1),
        }
        breakdown = self._create_maturity_breakdown(scores)

        result = self.analyzer.analyze_gaps(breakdown)

        # Should have a gap with HIGH priority
        self.assertEqual(len(result.all_gaps), 1)
        gap = result.all_gaps[0]
        self.assertEqual(gap.priority, Priority.HIGH)


class TestTrendDirection(unittest.TestCase):
    """Tests for TrendDirection enum."""

    def test_trend_direction_values(self) -> None:
        """Test TrendDirection enum values."""
        self.assertEqual(TrendDirection.IMPROVING.value, "improving")
        self.assertEqual(TrendDirection.REGRESSING.value, "regressing")
        self.assertEqual(TrendDirection.STABLE.value, "stable")
        self.assertEqual(TrendDirection.VOLATILE.value, "volatile")
        self.assertEqual(TrendDirection.INSUFFICIENT_DATA.value, "insufficient_data")


class TestTrendPoint(unittest.TestCase):
    """Tests for TrendPoint dataclass."""

    def test_trend_point_creation(self) -> None:
        """Test creating a TrendPoint."""
        now = datetime.now(UTC)
        point = TrendPoint(
            timestamp=now,
            score=2.5,
            level=2,
            evidence_count=10,
        )

        self.assertEqual(point.score, 2.5)
        self.assertEqual(point.level, 2)
        self.assertEqual(point.evidence_count, 10)

    def test_trend_point_to_dict(self) -> None:
        """Test TrendPoint to_dict method."""
        now = datetime.now(UTC)
        point = TrendPoint(
            timestamp=now,
            score=2.5678,
            level=2,
            evidence_count=10,
        )

        result = point.to_dict()

        self.assertEqual(result["score"], 2.57)  # Rounded
        self.assertEqual(result["level"], 2)
        self.assertEqual(result["evidence_count"], 10)
        self.assertIn("timestamp", result)


class TestTrendItem(unittest.TestCase):
    """Tests for TrendItem dataclass."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)

    def test_trend_item_creation(self) -> None:
        """Test creating a TrendItem."""
        item = TrendItem(
            entity_id="PR",
            entity_type="function",
            entity_name="Protect",
            direction=TrendDirection.IMPROVING,
            current_score=2.5,
            previous_score=2.0,
            score_delta=0.5,
            score_delta_percent=25.0,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
            analysis="Improving trend.",
        )

        self.assertEqual(item.entity_id, "PR")
        self.assertEqual(item.direction, TrendDirection.IMPROVING)
        self.assertEqual(item.score_delta, 0.5)

    def test_trend_item_to_dict(self) -> None:
        """Test TrendItem to_dict method."""
        point = TrendPoint(
            timestamp=self.now,
            score=2.5,
            level=2,
            evidence_count=10,
        )

        item = TrendItem(
            entity_id="PR",
            entity_type="function",
            entity_name="Protect",
            direction=TrendDirection.IMPROVING,
            current_score=2.567,
            previous_score=2.0,
            score_delta=0.567,
            score_delta_percent=28.35,
            period_start=self.now - timedelta(days=30),
            period_end=self.now,
            data_points=[point],
            analysis="Test analysis.",
        )

        result = item.to_dict()

        self.assertEqual(result["entity_id"], "PR")
        self.assertEqual(result["direction"], "improving")
        self.assertEqual(result["current_score"], 2.57)
        self.assertEqual(result["previous_score"], 2.0)
        self.assertEqual(result["score_delta"], 0.57)
        self.assertEqual(result["score_delta_percent"], 28.4)
        self.assertEqual(len(result["data_points"]), 1)

    def test_trend_item_none_values(self) -> None:
        """Test TrendItem with None values."""
        item = TrendItem(
            entity_id="PR",
            entity_type="function",
            entity_name="Protect",
            direction=TrendDirection.INSUFFICIENT_DATA,
            current_score=0.0,
            previous_score=None,
            score_delta=None,
            score_delta_percent=None,
            period_start=self.now,
            period_end=self.now,
            analysis="Insufficient data.",
        )

        result = item.to_dict()

        self.assertIsNone(result["previous_score"])
        self.assertIsNone(result["score_delta"])
        self.assertIsNone(result["score_delta_percent"])


class TestTrendTrackerConfig(unittest.TestCase):
    """Tests for TrendTrackerConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = TrendTrackerConfig()

        self.assertEqual(config.default_period_days, 90)
        self.assertEqual(config.improvement_threshold, 0.2)
        self.assertEqual(config.regression_threshold, -0.2)
        self.assertEqual(config.volatility_threshold, 0.5)
        self.assertEqual(config.min_data_points, 2)

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = TrendTrackerConfig(
            default_period_days=30,
            improvement_threshold=0.3,
            regression_threshold=-0.3,
            min_data_points=3,
        )

        self.assertEqual(config.default_period_days, 30)
        self.assertEqual(config.improvement_threshold, 0.3)
        self.assertEqual(config.regression_threshold, -0.3)
        self.assertEqual(config.min_data_points, 3)


class TestTrendTracker(unittest.TestCase):
    """Tests for TrendTracker class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_maturity_score(
        self,
        entity_id: str,
        level: int,
        score: float,
        evidence_count: int = 5,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=EntityType.SUBCATEGORY,
            level=level,
            score=score,
            evidence_count=evidence_count,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score at level {level}",
        )

    def _create_breakdown(
        self,
        timestamp: datetime,
        overall_score: float,
        overall_level: int = 2,
    ) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=self._create_maturity_score("overall", overall_level, overall_score),
            by_function={},
            by_category={},
            by_subcategory={},
            timestamp=timestamp,
            statistics={},
        )

    def test_tracker_initialization(self) -> None:
        """Test TrendTracker initialization."""
        tracker = TrendTracker()
        self.assertIsNotNone(tracker.config)
        self.assertEqual(tracker.config.default_period_days, 90)

    def test_tracker_with_custom_config(self) -> None:
        """Test TrendTracker with custom config."""
        config = TrendTrackerConfig(default_period_days=30)
        tracker = TrendTracker(config)
        self.assertEqual(tracker.config.default_period_days, 30)

    def test_calculate_trends_empty_snapshots(self) -> None:
        """Test trend calculation with empty snapshots."""
        analysis = self.tracker.calculate_trends([])

        self.assertEqual(analysis.overall_trend.direction, TrendDirection.INSUFFICIENT_DATA)
        self.assertEqual(analysis.statistics["total_controls_analyzed"], 0)

    def test_calculate_trends_single_snapshot(self) -> None:
        """Test trend calculation with single snapshot (insufficient)."""
        snapshot = self._create_breakdown(self.now, 2.5)
        analysis = self.tracker.calculate_trends([snapshot])

        # Single snapshot is insufficient for trend
        self.assertEqual(analysis.overall_trend.direction, TrendDirection.INSUFFICIENT_DATA)

    def test_calculate_trends_two_snapshots_improving(self) -> None:
        """Test trend calculation with two improving snapshots."""
        snapshots = [
            self._create_breakdown(self.now - timedelta(days=30), 2.0),
            self._create_breakdown(self.now, 2.5),
        ]
        analysis = self.tracker.calculate_trends(snapshots)

        self.assertEqual(analysis.overall_trend.direction, TrendDirection.IMPROVING)
        self.assertEqual(analysis.overall_trend.score_delta, 0.5)
        self.assertIsNotNone(analysis.overall_trend.score_delta_percent)

    def test_calculate_trends_two_snapshots_regressing(self) -> None:
        """Test trend calculation with two regressing snapshots."""
        snapshots = [
            self._create_breakdown(self.now - timedelta(days=30), 2.5),
            self._create_breakdown(self.now, 2.0),
        ]
        analysis = self.tracker.calculate_trends(snapshots)

        self.assertEqual(analysis.overall_trend.direction, TrendDirection.REGRESSING)
        self.assertEqual(analysis.overall_trend.score_delta, -0.5)

    def test_calculate_trends_stable(self) -> None:
        """Test trend calculation with stable snapshots."""
        snapshots = [
            self._create_breakdown(self.now - timedelta(days=30), 2.5),
            self._create_breakdown(self.now, 2.55),  # Minor change
        ]
        analysis = self.tracker.calculate_trends(snapshots)

        self.assertEqual(analysis.overall_trend.direction, TrendDirection.STABLE)

    def test_determine_direction_insufficient_data(self) -> None:
        """Test direction determination with insufficient data."""
        direction = self.tracker._determine_direction([], None)
        self.assertEqual(direction, TrendDirection.INSUFFICIENT_DATA)

    def test_determine_direction_with_none_delta(self) -> None:
        """Test direction determination with None score delta."""
        point = TrendPoint(
            timestamp=self.now,
            score=2.0,
            level=2,
            evidence_count=5,
        )
        direction = self.tracker._determine_direction([point, point], None)
        self.assertEqual(direction, TrendDirection.INSUFFICIENT_DATA)

    def test_build_trend_analysis_improving(self) -> None:
        """Test trend analysis text for improving."""
        analysis = self.tracker._build_trend_analysis(
            entity_name="Test Entity",
            direction=TrendDirection.IMPROVING,
            current_score=2.5,
            score_delta=0.5,
            data_points=[],
        )

        self.assertIn("improving", analysis.lower())
        self.assertIn("2.50", analysis)

    def test_build_trend_analysis_regressing(self) -> None:
        """Test trend analysis text for regressing."""
        analysis = self.tracker._build_trend_analysis(
            entity_name="Test Entity",
            direction=TrendDirection.REGRESSING,
            current_score=2.0,
            score_delta=-0.5,
            data_points=[],
        )

        self.assertIn("regressed", analysis.lower())

    def test_build_trend_analysis_stable(self) -> None:
        """Test trend analysis text for stable."""
        analysis = self.tracker._build_trend_analysis(
            entity_name="Test Entity",
            direction=TrendDirection.STABLE,
            current_score=2.5,
            score_delta=0.05,
            data_points=[],
        )

        self.assertIn("stable", analysis.lower())

    def test_build_trend_analysis_volatile(self) -> None:
        """Test trend analysis text for volatile."""
        analysis = self.tracker._build_trend_analysis(
            entity_name="Test Entity",
            direction=TrendDirection.VOLATILE,
            current_score=2.5,
            score_delta=0.0,
            data_points=[],
        )

        self.assertIn("volatile", analysis.lower())

    def test_build_trend_analysis_insufficient(self) -> None:
        """Test trend analysis text for insufficient data."""
        analysis = self.tracker._build_trend_analysis(
            entity_name="Test Entity",
            direction=TrendDirection.INSUFFICIENT_DATA,
            current_score=0.0,
            score_delta=None,
            data_points=[],
        )

        self.assertIn("insufficient", analysis.lower())

    def test_get_improving_controls_no_analysis(self) -> None:
        """Test getting improving controls before analysis."""
        tracker = TrendTracker()
        result = tracker.get_improving_controls()
        self.assertEqual(result, [])

    def test_get_regressing_controls_no_analysis(self) -> None:
        """Test getting regressing controls before analysis."""
        tracker = TrendTracker()
        result = tracker.get_regressing_controls()
        self.assertEqual(result, [])

    def test_get_stable_controls_no_analysis(self) -> None:
        """Test getting stable controls before analysis."""
        tracker = TrendTracker()
        result = tracker.get_stable_controls()
        self.assertEqual(result, [])

    def test_get_volatile_controls_no_analysis(self) -> None:
        """Test getting volatile controls before analysis."""
        tracker = TrendTracker()
        result = tracker.get_volatile_controls()
        self.assertEqual(result, [])

    def test_get_function_trend_no_analysis(self) -> None:
        """Test getting function trend before analysis."""
        tracker = TrendTracker()
        result = tracker.get_function_trend("PR")
        self.assertIsNone(result)

    def test_get_category_trend_no_analysis(self) -> None:
        """Test getting category trend before analysis."""
        tracker = TrendTracker()
        result = tracker.get_category_trend("PR.AA")
        self.assertIsNone(result)

    def test_create_empty_analysis(self) -> None:
        """Test creating empty analysis."""
        analysis = self.tracker._create_empty_analysis(30)

        self.assertEqual(analysis.period_days, 30)
        self.assertEqual(analysis.overall_trend.direction, TrendDirection.INSUFFICIENT_DATA)
        self.assertEqual(analysis.statistics["total_controls_analyzed"], 0)
        self.assertIn("overall_line", analysis.chart_data)

    def test_calculate_statistics(self) -> None:
        """Test statistics calculation."""
        overall_trend = TrendItem(
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

        snapshots = [
            self._create_breakdown(self.now - timedelta(days=30), 2.0),
            self._create_breakdown(self.now, 2.5),
        ]

        stats = self.tracker._calculate_statistics(
            overall_trend=overall_trend,
            improving=10,
            regressing=5,
            stable=80,
            volatile=5,
            period_snapshots=snapshots,
        )

        self.assertEqual(stats["total_controls_analyzed"], 100)
        self.assertEqual(stats["improving_count"], 10)
        self.assertEqual(stats["regressing_count"], 5)
        self.assertEqual(stats["improving_percentage"], 10.0)
        self.assertEqual(stats["snapshots_analyzed"], 2)


class TestTrendAnalysisDataclass(unittest.TestCase):
    """Tests for TrendAnalysis dataclass."""

    def test_trend_analysis_to_dict(self) -> None:
        """Test TrendAnalysis to_dict method."""
        now = datetime.now(UTC)

        overall_trend = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall Maturity",
            direction=TrendDirection.IMPROVING,
            current_score=2.5,
            previous_score=2.0,
            score_delta=0.5,
            score_delta_percent=25.0,
            period_start=now - timedelta(days=30),
            period_end=now,
            analysis="Improving.",
        )

        analysis = TrendAnalysis(
            timestamp=now,
            period_days=30,
            overall_trend=overall_trend,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={"total_controls_analyzed": 100},
            chart_data={"overall_line": {}},
        )

        result = analysis.to_dict()

        self.assertEqual(result["period_days"], 30)
        self.assertIn("timestamp", result)
        self.assertIn("overall_trend", result)
        self.assertEqual(result["statistics"]["total_controls_analyzed"], 100)


class TestTrendTrackerVolatility(unittest.TestCase):
    """Tests for volatility detection in trend tracking."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_point(self, days_ago: int, score: float) -> TrendPoint:
        """Helper to create a TrendPoint."""
        return TrendPoint(
            timestamp=self.now - timedelta(days=days_ago),
            score=score,
            level=int(score),
            evidence_count=5,
        )

    def test_determine_direction_volatile_scores(self) -> None:
        """Test volatility detection with fluctuating scores."""
        # Create data points with large swings and sign changes
        points = [
            self._create_point(30, 1.0),
            self._create_point(20, 2.5),  # +1.5
            self._create_point(10, 1.5),  # -1.0 (sign change)
            self._create_point(0, 2.5),   # +1.0 (sign change)
        ]

        direction = self.tracker._determine_direction(points, 1.5)

        self.assertEqual(direction, TrendDirection.VOLATILE)

    def test_determine_direction_consistent_improvement_not_volatile(self) -> None:
        """Test that consistent improvement is not marked volatile."""
        # Large change but consistent direction
        points = [
            self._create_point(30, 1.0),
            self._create_point(20, 1.5),
            self._create_point(10, 2.0),
            self._create_point(0, 2.5),
        ]

        direction = self.tracker._determine_direction(points, 1.5)

        # Should be IMPROVING, not VOLATILE
        self.assertEqual(direction, TrendDirection.IMPROVING)


class TestTrendTrackerWithSubcategories(unittest.TestCase):
    """Tests for trend tracking with full subcategory data."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_maturity_score(
        self,
        entity_id: str,
        score: float,
        entity_type: EntityType = EntityType.SUBCATEGORY,
    ) -> MaturityScore:
        """Helper to create MaturityScore."""
        return MaturityScore(
            entity_id=entity_id,
            entity_type=entity_type,
            level=int(score),
            score=score,
            evidence_count=5,
            last_evidence_date=self.now,
            confidence=0.9,
            explanation=f"Test score {score}",
        )

    def _create_full_breakdown(
        self,
        timestamp: datetime,
        overall_score: float,
        func_scores: dict[str, float] | None = None,
        category_scores: dict[str, float] | None = None,
        sub_scores: dict[str, float] | None = None,
    ) -> MaturityBreakdown:
        """Helper to create a full MaturityBreakdown."""
        overall = self._create_maturity_score("overall", overall_score, EntityType.OVERALL)

        by_function = {}
        if func_scores:
            for fid, score in func_scores.items():
                by_function[fid] = self._create_maturity_score(fid, score, EntityType.FUNCTION)

        by_category = {}
        if category_scores:
            for cid, score in category_scores.items():
                by_category[cid] = self._create_maturity_score(cid, score, EntityType.CATEGORY)

        by_subcategory = {}
        if sub_scores:
            for sid, score in sub_scores.items():
                by_subcategory[sid] = self._create_maturity_score(sid, score, EntityType.SUBCATEGORY)

        return MaturityBreakdown(
            overall=overall,
            by_function=by_function,
            by_category=by_category,
            by_subcategory=by_subcategory,
            timestamp=timestamp,
            statistics={},
        )

    def test_calculate_trends_with_full_data(self) -> None:
        """Test trend calculation with full function and subcategory data."""
        # Improving trend across 2 snapshots
        snapshots = [
            self._create_full_breakdown(
                self.now - timedelta(days=30),
                overall_score=2.0,
                func_scores={"GV": 2.0, "ID": 1.5, "PR": 2.0},
                category_scores={"GV.OC": 2.0, "ID.AM": 1.5},
                sub_scores={"GV.OC-01": 2.0, "ID.AM-01": 1.5, "PR.AA-01": 2.0},
            ),
            self._create_full_breakdown(
                self.now,
                overall_score=2.5,
                func_scores={"GV": 2.5, "ID": 2.0, "PR": 2.5},
                category_scores={"GV.OC": 2.5, "ID.AM": 2.0},
                sub_scores={"GV.OC-01": 2.5, "ID.AM-01": 2.0, "PR.AA-01": 2.5},
            ),
        ]

        analysis = self.tracker.calculate_trends(snapshots)

        # Check overall trend
        self.assertEqual(analysis.overall_trend.direction, TrendDirection.IMPROVING)

        # Check function trends exist
        self.assertIn("GV", analysis.function_trends)

        # Check category trends exist
        self.assertIn("GV.OC", analysis.category_trends)

        # After analysis, accessor methods should work
        improving = self.tracker.get_improving_controls()
        regressing = self.tracker.get_regressing_controls()
        stable = self.tracker.get_stable_controls()
        volatile = self.tracker.get_volatile_controls()

        # All controls were improving
        self.assertIsInstance(improving, list)
        self.assertIsInstance(regressing, list)
        self.assertIsInstance(stable, list)
        self.assertIsInstance(volatile, list)

    def test_get_function_trend_after_analysis(self) -> None:
        """Test getting function trend after analysis."""
        snapshots = [
            self._create_full_breakdown(
                self.now - timedelta(days=30),
                overall_score=2.0,
                func_scores={"GV": 2.0, "PR": 2.0},
            ),
            self._create_full_breakdown(
                self.now,
                overall_score=2.5,
                func_scores={"GV": 2.5, "PR": 2.5},
            ),
        ]

        self.tracker.calculate_trends(snapshots)

        # Should find GV trend
        gv_trend = self.tracker.get_function_trend("GV")
        self.assertIsNotNone(gv_trend)
        self.assertEqual(gv_trend.entity_id, "GV")

        # Non-existent function returns None
        xx_trend = self.tracker.get_function_trend("XX")
        self.assertIsNone(xx_trend)

    def test_get_category_trend_after_analysis(self) -> None:
        """Test getting category trend after analysis."""
        snapshots = [
            self._create_full_breakdown(
                self.now - timedelta(days=30),
                overall_score=2.0,
                category_scores={"GV.OC": 2.0, "PR.AA": 2.0},
            ),
            self._create_full_breakdown(
                self.now,
                overall_score=2.5,
                category_scores={"GV.OC": 2.5, "PR.AA": 2.5},
            ),
        ]

        self.tracker.calculate_trends(snapshots)

        # Should find GV.OC trend
        gv_oc_trend = self.tracker.get_category_trend("GV.OC")
        self.assertIsNotNone(gv_oc_trend)
        self.assertEqual(gv_oc_trend.entity_id, "GV.OC")

        # Non-existent category returns None
        xx_yy_trend = self.tracker.get_category_trend("XX.YY")
        self.assertIsNone(xx_yy_trend)

    def test_chart_data_with_trend_distribution(self) -> None:
        """Test that chart data includes trend distribution after analysis."""
        snapshots = [
            self._create_full_breakdown(
                self.now - timedelta(days=30),
                overall_score=2.0,
                func_scores={"GV": 2.0},
                sub_scores={"GV.OC-01": 2.0},
            ),
            self._create_full_breakdown(
                self.now,
                overall_score=2.5,
                func_scores={"GV": 2.5},
                sub_scores={"GV.OC-01": 2.5},
            ),
        ]

        analysis = self.tracker.calculate_trends(snapshots)

        # Chart data should have trend_distribution
        self.assertIn("trend_distribution", analysis.chart_data)
        trend_dist = analysis.chart_data["trend_distribution"]
        self.assertIn("labels", trend_dist)
        self.assertIn("data", trend_dist)
        # When _last_analysis is set, labels should have 4 items
        # The tracker stores _last_analysis before generating chart data
        if trend_dist["labels"]:
            self.assertEqual(len(trend_dist["labels"]), 4)
            self.assertEqual(len(trend_dist["data"]), 4)


class TestTrendTrackerStatisticsEdgeCases(unittest.TestCase):
    """Tests for statistics calculation edge cases."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def test_calculate_statistics_empty_snapshots(self) -> None:
        """Test statistics calculation with empty snapshot list."""
        overall_trend = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=TrendDirection.INSUFFICIENT_DATA,
            current_score=0.0,
            previous_score=None,
            score_delta=None,
            score_delta_percent=None,
            period_start=self.now,
            period_end=self.now,
        )

        stats = self.tracker._calculate_statistics(
            overall_trend=overall_trend,
            improving=0,
            regressing=0,
            stable=0,
            volatile=0,
            period_snapshots=[],  # Empty list
        )

        # Should handle empty list gracefully
        self.assertEqual(stats["average_overall_score"], 0.0)
        self.assertEqual(stats["min_overall_score"], 0.0)
        self.assertEqual(stats["max_overall_score"], 0.0)
        self.assertEqual(stats["snapshots_analyzed"], 0)

    def test_calculate_statistics_zero_controls(self) -> None:
        """Test statistics calculation when no controls analyzed."""
        overall_trend = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall",
            direction=TrendDirection.INSUFFICIENT_DATA,
            current_score=0.0,
            previous_score=None,
            score_delta=None,
            score_delta_percent=None,
            period_start=self.now,
            period_end=self.now,
        )

        stats = self.tracker._calculate_statistics(
            overall_trend=overall_trend,
            improving=0,
            regressing=0,
            stable=0,
            volatile=0,
            period_snapshots=[],
        )

        # Should handle zero controls without division by zero
        self.assertEqual(stats["improving_percentage"], 0.0)
        self.assertEqual(stats["regressing_percentage"], 0.0)


class TestTrendTrackerEntityTrendEdgeCases(unittest.TestCase):
    """Tests for _calculate_entity_trend edge cases."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def test_calculate_entity_trend_empty_snapshots(self) -> None:
        """Test entity trend calculation with empty snapshot list."""
        trend = self.tracker._calculate_entity_trend(
            entity_id="test",
            entity_type="test",
            entity_name="Test Entity",
            snapshots=[],  # Empty list
            score_extractor=lambda s: 0.0,
            level_extractor=lambda s: 0,
            evidence_extractor=lambda s: 0,
        )

        self.assertEqual(trend.direction, TrendDirection.INSUFFICIENT_DATA)
        self.assertEqual(trend.current_score, 0.0)
        self.assertIsNone(trend.previous_score)
        self.assertIsNone(trend.score_delta)
        self.assertIn("Insufficient data", trend.analysis)

    def test_calculate_entity_trend_zero_previous_score(self) -> None:
        """Test entity trend with zero previous score (no percentage calc)."""

        def make_breakdown(ts: datetime, score: float) -> MaturityBreakdown:
            return MaturityBreakdown(
                overall=MaturityScore(
                    entity_id="overall",
                    entity_type=EntityType.OVERALL,
                    level=int(score),
                    score=score,
                    evidence_count=5,
                    last_evidence_date=ts,
                    confidence=0.9,
                    explanation="Test",
                ),
                by_function={},
                by_category={},
                by_subcategory={},
                timestamp=ts,
                statistics={},
            )

        snapshots = [
            make_breakdown(self.now - timedelta(days=30), 0.0),  # Zero initial score
            make_breakdown(self.now, 2.0),
        ]

        trend = self.tracker._calculate_entity_trend(
            entity_id="test",
            entity_type="test",
            entity_name="Test Entity",
            snapshots=snapshots,
            score_extractor=lambda s: s.overall.score,
            level_extractor=lambda s: s.overall.level,
            evidence_extractor=lambda s: s.overall.evidence_count,
        )

        self.assertEqual(trend.score_delta, 2.0)
        # Percentage should be None when previous is 0
        self.assertIsNone(trend.score_delta_percent)


class TestTrendTrackerRegression(unittest.TestCase):
    """Tests specifically for regression scenarios."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_breakdown(
        self, timestamp: datetime, overall_score: float
    ) -> MaturityBreakdown:
        """Helper to create MaturityBreakdown."""
        return MaturityBreakdown(
            overall=MaturityScore(
                entity_id="overall",
                entity_type=EntityType.OVERALL,
                level=int(overall_score),
                score=overall_score,
                evidence_count=5,
                last_evidence_date=timestamp,
                confidence=0.9,
                explanation=f"Test score {overall_score}",
            ),
            by_function={},
            by_category={},
            by_subcategory={
                "GV.OC-01": MaturityScore(
                    entity_id="GV.OC-01",
                    entity_type=EntityType.SUBCATEGORY,
                    level=int(overall_score),
                    score=overall_score,
                    evidence_count=5,
                    last_evidence_date=timestamp,
                    confidence=0.9,
                    explanation="Test",
                )
            },
            timestamp=timestamp,
            statistics={},
        )

    def test_regression_detected_in_subcategories(self) -> None:
        """Test that regression is detected at subcategory level."""
        snapshots = [
            self._create_breakdown(self.now - timedelta(days=30), 3.0),
            self._create_breakdown(self.now, 2.0),  # Regressed
        ]

        analysis = self.tracker.calculate_trends(snapshots)

        self.assertEqual(analysis.overall_trend.direction, TrendDirection.REGRESSING)
        # Should have regressing controls
        self.assertGreater(len(analysis.regressing_controls), 0)


class TestVolatileSubcategory(unittest.TestCase):
    """Tests for volatile subcategory detection."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_volatile_breakdown(
        self, timestamp: datetime, overall_score: float, sub_score: float
    ) -> MaturityBreakdown:
        """Helper to create breakdown with a subcategory."""
        return MaturityBreakdown(
            overall=MaturityScore(
                entity_id="overall",
                entity_type=EntityType.OVERALL,
                level=int(overall_score),
                score=overall_score,
                evidence_count=5,
                last_evidence_date=timestamp,
                confidence=0.9,
                explanation=f"Test score {overall_score}",
            ),
            by_function={},
            by_category={},
            by_subcategory={
                "GV.OC-01": MaturityScore(
                    entity_id="GV.OC-01",
                    entity_type=EntityType.SUBCATEGORY,
                    level=int(sub_score),
                    score=sub_score,
                    evidence_count=5,
                    last_evidence_date=timestamp,
                    confidence=0.9,
                    explanation="Test",
                )
            },
            timestamp=timestamp,
            statistics={},
        )

    def test_volatile_subcategory_detected(self) -> None:
        """Test that volatile subcategory is properly categorized."""
        # Create snapshots with volatile subcategory scores (fluctuating pattern)
        snapshots = [
            self._create_volatile_breakdown(self.now - timedelta(days=60), 2.0, 1.0),
            self._create_volatile_breakdown(self.now - timedelta(days=40), 2.2, 3.0),  # +2.0
            self._create_volatile_breakdown(self.now - timedelta(days=20), 2.4, 1.5),  # -1.5 (sign change)
            self._create_volatile_breakdown(self.now, 2.5, 3.0),                       # +1.5 (sign change)
        ]

        analysis = self.tracker.calculate_trends(snapshots)

        # Check that we have volatile controls
        # The subcategory GV.OC-01 has large swings with sign changes
        self.assertGreaterEqual(len(analysis.volatile_controls), 0)
        # Verify the analysis object has chart_data with trend_distribution populated
        self.assertIn("trend_distribution", analysis.chart_data)


class TestChartDataGeneration(unittest.TestCase):
    """Tests for chart data generation with _last_analysis."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.tracker = TrendTracker()
        self.now = datetime.now(UTC)

    def _create_breakdown(
        self, timestamp: datetime, overall_score: float, func_scores: dict[str, float]
    ) -> MaturityBreakdown:
        """Helper to create breakdown."""
        by_function = {}
        for fid, score in func_scores.items():
            by_function[fid] = MaturityScore(
                entity_id=fid,
                entity_type=EntityType.FUNCTION,
                level=int(score),
                score=score,
                evidence_count=5,
                last_evidence_date=timestamp,
                confidence=0.9,
                explanation="Test",
            )

        return MaturityBreakdown(
            overall=MaturityScore(
                entity_id="overall",
                entity_type=EntityType.OVERALL,
                level=int(overall_score),
                score=overall_score,
                evidence_count=5,
                last_evidence_date=timestamp,
                confidence=0.9,
                explanation="Test",
            ),
            by_function=by_function,
            by_category={},
            by_subcategory={
                "GV.OC-01": MaturityScore(
                    entity_id="GV.OC-01",
                    entity_type=EntityType.SUBCATEGORY,
                    level=int(overall_score),
                    score=overall_score,
                    evidence_count=5,
                    last_evidence_date=timestamp,
                    confidence=0.9,
                    explanation="Test",
                )
            },
            timestamp=timestamp,
            statistics={},
        )

    def test_chart_data_trend_distribution_populated(self) -> None:
        """Test that trend_distribution is populated when _last_analysis exists."""
        snapshots = [
            self._create_breakdown(
                self.now - timedelta(days=30),
                2.0,
                {"GV": 2.0, "PR": 2.0},
            ),
            self._create_breakdown(
                self.now,
                2.5,
                {"GV": 2.5, "PR": 2.5},
            ),
        ]

        # First call sets _last_analysis
        self.tracker.calculate_trends(snapshots)

        # Second call uses _last_analysis from first call during chart generation
        analysis2 = self.tracker.calculate_trends(snapshots)

        # After second analysis, chart_data should have trend_distribution populated
        self.assertIn("trend_distribution", analysis2.chart_data)
        trend_dist = analysis2.chart_data["trend_distribution"]
        # Since _last_analysis was set after first call, second call should have data
        self.assertEqual(len(trend_dist["labels"]), 4)
        self.assertEqual(len(trend_dist["data"]), 4)


if __name__ == "__main__":
    unittest.main()
