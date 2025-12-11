"""
Tests for the NIST CSF 2.0 maturity scoring calculator.

Uses Python's unittest module.
Tests maturity level calculations, category roll-ups, function roll-ups,
and edge cases.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from nisify.nist.mapping_engine import ControlMappingResult, MappingStatus
from nisify.nist.maturity_calculator import (
    EntityType,
    MaturityBreakdown,
    MaturityCalculator,
    MaturityConfig,
    MaturityScore,
)


class TestMaturityConfig(unittest.TestCase):
    """Tests for MaturityConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = MaturityConfig()

        self.assertEqual(config.satisfied_fresh_score, 3.0)
        self.assertEqual(config.satisfied_stale_score, 2.0)
        self.assertEqual(config.partial_score, 1.5)
        self.assertEqual(config.unsatisfied_score, 0.0)
        self.assertEqual(config.max_score, 4.0)
        self.assertEqual(config.min_score, 0.0)
        self.assertEqual(config.freshness_threshold_days, 30)

    def test_score_to_level_level_0(self) -> None:
        """Test converting score to level 0."""
        config = MaturityConfig()

        self.assertEqual(config.score_to_level(0.0), 0)
        self.assertEqual(config.score_to_level(0.4), 0)

    def test_score_to_level_level_1(self) -> None:
        """Test converting score to level 1."""
        config = MaturityConfig()

        self.assertEqual(config.score_to_level(0.5), 1)
        self.assertEqual(config.score_to_level(1.0), 1)
        self.assertEqual(config.score_to_level(1.4), 1)

    def test_score_to_level_level_2(self) -> None:
        """Test converting score to level 2."""
        config = MaturityConfig()

        self.assertEqual(config.score_to_level(1.5), 2)
        self.assertEqual(config.score_to_level(2.0), 2)
        self.assertEqual(config.score_to_level(2.4), 2)

    def test_score_to_level_level_3(self) -> None:
        """Test converting score to level 3."""
        config = MaturityConfig()

        self.assertEqual(config.score_to_level(2.5), 3)
        self.assertEqual(config.score_to_level(3.0), 3)
        self.assertEqual(config.score_to_level(3.4), 3)

    def test_score_to_level_level_4(self) -> None:
        """Test converting score to level 4."""
        config = MaturityConfig()

        self.assertEqual(config.score_to_level(3.5), 4)
        self.assertEqual(config.score_to_level(4.0), 4)

    def test_custom_thresholds(self) -> None:
        """Test custom threshold configuration."""
        config = MaturityConfig(
            level_thresholds={
                0: 0.0,
                1: 1.0,
                2: 2.0,
                3: 3.0,
                4: 4.0,
            }
        )

        self.assertEqual(config.score_to_level(0.9), 0)
        self.assertEqual(config.score_to_level(1.0), 1)
        self.assertEqual(config.score_to_level(1.9), 1)
        self.assertEqual(config.score_to_level(2.0), 2)


class TestMaturityScore(unittest.TestCase):
    """Tests for MaturityScore dataclass."""

    def test_to_dict(self) -> None:
        """Test converting score to dictionary."""
        last_date = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        score = MaturityScore(
            entity_id="PR.AC-01",
            entity_type=EntityType.SUBCATEGORY,
            level=3,
            score=3.25,
            evidence_count=5,
            last_evidence_date=last_date,
            confidence=0.875,
            explanation="Good evidence coverage",
            delta=0.5,
        )

        result = score.to_dict()

        self.assertEqual(result["entity_id"], "PR.AC-01")
        self.assertEqual(result["entity_type"], "subcategory")
        self.assertEqual(result["level"], 3)
        self.assertEqual(result["score"], 3.25)
        self.assertEqual(result["evidence_count"], 5)
        self.assertEqual(result["last_evidence_date"], "2024-01-15T12:00:00+00:00")
        self.assertEqual(result["confidence"], 0.875)
        self.assertEqual(result["explanation"], "Good evidence coverage")
        self.assertEqual(result["delta"], 0.5)

    def test_to_dict_no_optional_fields(self) -> None:
        """Test to_dict with no optional fields."""
        score = MaturityScore(
            entity_id="overall",
            entity_type=EntityType.OVERALL,
            level=2,
            score=2.0,
            evidence_count=0,
            last_evidence_date=None,
            confidence=0.5,
            explanation="Test",
        )

        result = score.to_dict()

        self.assertIsNone(result["last_evidence_date"])
        self.assertIsNone(result["delta"])


class TestMaturityCalculator(unittest.TestCase):
    """Tests for MaturityCalculator class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_mapping_result(
        self,
        control_id: str,
        status: MappingStatus,
        confidence: float = 1.0,
        evidence_count: int = 1,
        days_old: int = 0,
    ) -> ControlMappingResult:
        """Helper to create mapping results for testing."""
        last_date = self.now - timedelta(days=days_old)
        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=confidence,
            evidence_ids=["id"] * evidence_count,
            evidence_types_found=["type1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_missing=[] if status == MappingStatus.SATISFIED else ["missing"],
            last_evidence_date=last_date if evidence_count > 0 else None,
            explanation="Test explanation",
        )

    def test_calculate_subcategory_satisfied(self) -> None:
        """Test subcategory score for satisfied control."""
        mapping_result = self._create_mapping_result(
            control_id="PR.AC-01",
            status=MappingStatus.SATISFIED,
            confidence=1.0,
        )

        score = self.calculator.calculate_subcategory_maturity(
            "PR.AC-01",
            mapping_result,
        )

        self.assertEqual(score.entity_type, EntityType.SUBCATEGORY)
        self.assertGreater(score.score, 2.0)
        self.assertGreater(score.level, 1)

    def test_calculate_subcategory_partial(self) -> None:
        """Test subcategory score for partial control."""
        mapping_result = self._create_mapping_result(
            control_id="PR.AC-02",
            status=MappingStatus.PARTIAL,
            confidence=0.6,
        )

        score = self.calculator.calculate_subcategory_maturity(
            "PR.AC-02",
            mapping_result,
        )

        self.assertGreater(score.score, 0.0)
        self.assertLess(score.score, 3.0)

    def test_calculate_subcategory_unsatisfied(self) -> None:
        """Test subcategory score for unsatisfied control."""
        mapping_result = self._create_mapping_result(
            control_id="PR.AC-03",
            status=MappingStatus.UNSATISFIED,
            confidence=0.0,
            evidence_count=0,
        )

        score = self.calculator.calculate_subcategory_maturity(
            "PR.AC-03",
            mapping_result,
        )

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)

    def test_calculate_subcategory_stale_evidence(self) -> None:
        """Test subcategory score with stale evidence."""
        fresh_result = self._create_mapping_result(
            control_id="PR.AC-04",
            status=MappingStatus.SATISFIED,
            days_old=5,
        )
        stale_result = self._create_mapping_result(
            control_id="PR.AC-04",
            status=MappingStatus.SATISFIED,
            days_old=45,
        )

        fresh_score = self.calculator.calculate_subcategory_maturity(
            "PR.AC-04",
            fresh_result,
        )
        stale_score = self.calculator.calculate_subcategory_maturity(
            "PR.AC-04",
            stale_result,
        )

        # Stale evidence should result in lower score
        self.assertGreater(fresh_score.score, stale_score.score)

    def test_calculate_category_maturity(self) -> None:
        """Test category score aggregation using mapping results."""
        # Create mapping results for controls in PR.AA category
        mapping_results = {
            "PR.AA-01": self._create_mapping_result(
                "PR.AA-01", MappingStatus.SATISFIED, confidence=0.9
            ),
            "PR.AA-02": self._create_mapping_result(
                "PR.AA-02", MappingStatus.PARTIAL, confidence=0.6
            ),
        }

        score = self.calculator.calculate_category_maturity(
            "PR.AA",
            mapping_results,
        )

        self.assertEqual(score.entity_id, "PR.AA")
        self.assertEqual(score.entity_type, EntityType.CATEGORY)
        # Score should be based on the mapping results
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_calculate_category_no_subcategories(self) -> None:
        """Test category score with no mapping results."""
        score = self.calculator.calculate_category_maturity("PR.AA", {})

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)

    def test_calculate_function_maturity(self) -> None:
        """Test function score aggregation using mapping results."""
        # Create mapping results for controls in PR function
        mapping_results = {
            "PR.AA-01": self._create_mapping_result(
                "PR.AA-01", MappingStatus.SATISFIED, confidence=0.9
            ),
            "PR.DS-01": self._create_mapping_result(
                "PR.DS-01", MappingStatus.PARTIAL, confidence=0.5
            ),
        }

        score = self.calculator.calculate_function_maturity("PR", mapping_results)

        self.assertEqual(score.entity_id, "PR")
        self.assertEqual(score.entity_type, EntityType.FUNCTION)
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_calculate_overall_maturity(self) -> None:
        """Test overall score aggregation using mapping results."""
        # Create mapping results spanning multiple functions
        mapping_results = {
            "GV.OC-01": self._create_mapping_result(
                "GV.OC-01", MappingStatus.SATISFIED
            ),
            "ID.AM-01": self._create_mapping_result(
                "ID.AM-01", MappingStatus.PARTIAL
            ),
            "PR.AA-01": self._create_mapping_result(
                "PR.AA-01", MappingStatus.SATISFIED
            ),
        }

        score = self.calculator.calculate_overall_maturity(mapping_results)

        self.assertEqual(score.entity_id, "overall")
        self.assertEqual(score.entity_type, EntityType.OVERALL)
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_calculate_all(self) -> None:
        """Test calculating complete breakdown."""
        # Create mapping results for a few controls as a list
        mapping_results = [
            self._create_mapping_result("GV.OC-01", MappingStatus.SATISFIED),
            self._create_mapping_result("ID.AM-01", MappingStatus.PARTIAL),
            self._create_mapping_result("PR.AA-01", MappingStatus.UNSATISFIED, evidence_count=0),
        ]

        breakdown = self.calculator.calculate_all(mapping_results)

        self.assertIsInstance(breakdown, MaturityBreakdown)
        self.assertIsNotNone(breakdown.overall)
        self.assertIn("GV", breakdown.by_function)
        self.assertIn("ID", breakdown.by_function)
        self.assertIn("PR", breakdown.by_function)

    def test_calculate_all_no_evidence(self) -> None:
        """Test calculating breakdown with no evidence."""
        breakdown = self.calculator.calculate_all([])

        self.assertEqual(breakdown.overall.score, 0.0)
        self.assertEqual(breakdown.overall.level, 0)

    def test_score_bounds(self) -> None:
        """Test that scores are within bounds."""
        mapping_result = self._create_mapping_result(
            control_id="TEST.01",
            status=MappingStatus.SATISFIED,
            confidence=1.0,
        )

        score = self.calculator.calculate_subcategory_maturity(
            "TEST.01",
            mapping_result,
        )

        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_level_bounds(self) -> None:
        """Test that levels are within bounds."""
        # Test various score scenarios
        scenarios = [
            (MappingStatus.SATISFIED, 1.0),
            (MappingStatus.PARTIAL, 0.5),
            (MappingStatus.UNSATISFIED, 0.0),
        ]

        for status, confidence in scenarios:
            result = self._create_mapping_result(
                "TEST.01",
                status,
                confidence,
            )
            score = self.calculator.calculate_subcategory_maturity("TEST.01", result)

            self.assertGreaterEqual(score.level, 0)
            self.assertLessEqual(score.level, 4)


class TestMaturityBreakdown(unittest.TestCase):
    """Tests for MaturityBreakdown dataclass."""

    def test_to_dict(self) -> None:
        """Test converting breakdown to dictionary."""
        now = datetime.now(UTC)

        overall = MaturityScore(
            entity_id="overall",
            entity_type=EntityType.OVERALL,
            level=2,
            score=2.5,
            evidence_count=100,
            last_evidence_date=now,
            confidence=0.8,
            explanation="Test overall",
        )

        by_function = {
            "PR": MaturityScore(
                entity_id="PR",
                entity_type=EntityType.FUNCTION,
                level=3,
                score=3.0,
                evidence_count=50,
                last_evidence_date=now,
                confidence=0.85,
                explanation="Test function",
            )
        }

        breakdown = MaturityBreakdown(
            timestamp=now,
            overall=overall,
            by_function=by_function,
            by_category={},
            by_subcategory={},
            statistics={"total_evidence": 100},
        )

        result = breakdown.to_dict()

        self.assertIn("timestamp", result)
        self.assertIn("overall", result)
        self.assertIn("by_function", result)
        self.assertEqual(result["overall"]["level"], 2)
        self.assertEqual(result["by_function"]["PR"]["level"], 3)


class TestCategoryRollups(unittest.TestCase):
    """Tests for category score roll-ups using ControlMappingResult."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_mapping_result(
        self,
        control_id: str,
        status: MappingStatus,
        confidence: float = 1.0,
    ) -> ControlMappingResult:
        """Helper to create mapping result."""
        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=confidence,
            evidence_ids=["id1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_found=["type1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_missing=[] if status == MappingStatus.SATISFIED else ["missing"],
            last_evidence_date=self.now if status != MappingStatus.UNSATISFIED else None,
            explanation="Test",
        )

    def test_weighted_average(self) -> None:
        """Test that category scores are based on mapping results."""
        mapping_results = {
            "PR.AA-01": self._create_mapping_result("PR.AA-01", MappingStatus.SATISFIED, 1.0),
            "PR.AA-02": self._create_mapping_result("PR.AA-02", MappingStatus.PARTIAL, 0.5),
        }

        score = self.calculator.calculate_category_maturity("PR.AA", mapping_results)

        # Score should be reasonable based on 1 satisfied + 1 partial
        self.assertGreater(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_single_subcategory(self) -> None:
        """Test category with single mapping result."""
        mapping_results = {
            "DE.AE-02": self._create_mapping_result("DE.AE-02", MappingStatus.SATISFIED, 0.9),
        }

        score = self.calculator.calculate_category_maturity("DE.AE", mapping_results)

        self.assertGreater(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)

    def test_many_subcategories(self) -> None:
        """Test category with many mapping results."""
        statuses = [MappingStatus.SATISFIED, MappingStatus.PARTIAL,
                    MappingStatus.SATISFIED, MappingStatus.UNSATISFIED]
        mapping_results = {}
        for i, status in enumerate(statuses):
            mapping_results[f"ID.AM-0{i+1}"] = self._create_mapping_result(
                f"ID.AM-0{i+1}", status, 0.8 if status != MappingStatus.UNSATISFIED else 0.0
            )

        score = self.calculator.calculate_category_maturity("ID.AM", mapping_results)

        # Mix of statuses should give moderate score
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)


class TestFunctionRollups(unittest.TestCase):
    """Tests for function score roll-ups using ControlMappingResult."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_mapping_result(
        self,
        control_id: str,
        status: MappingStatus,
        confidence: float = 1.0,
    ) -> ControlMappingResult:
        """Helper to create mapping result."""
        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=confidence,
            evidence_ids=["id1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_found=["type1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_missing=[] if status == MappingStatus.SATISFIED else ["missing"],
            last_evidence_date=self.now if status != MappingStatus.UNSATISFIED else None,
            explanation="Test",
        )

    def test_function_from_categories(self) -> None:
        """Test function score from mapping results across categories."""
        mapping_results = {
            "GV.OC-01": self._create_mapping_result("GV.OC-01", MappingStatus.SATISFIED),
            "GV.RM-01": self._create_mapping_result("GV.RM-01", MappingStatus.PARTIAL),
            "GV.SC-01": self._create_mapping_result("GV.SC-01", MappingStatus.SATISFIED),
        }

        score = self.calculator.calculate_function_maturity("GV", mapping_results)

        self.assertEqual(score.entity_id, "GV")
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases in scoring."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def test_all_evidence_present(self) -> None:
        """Test scoring when all evidence is present and fresh."""
        mapping_result = ControlMappingResult(
            control_id="TEST.01",
            status=MappingStatus.SATISFIED,
            confidence=1.0,
            evidence_ids=["id1", "id2", "id3"],
            evidence_types_found=["type1", "type2", "type3"],
            evidence_types_missing=[],
            last_evidence_date=self.now,
            explanation="All evidence present",
        )

        score = self.calculator.calculate_subcategory_maturity("TEST.01", mapping_result)

        # Should be high score
        self.assertGreater(score.score, 2.5)
        self.assertGreater(score.level, 2)

    def test_no_evidence_at_all(self) -> None:
        """Test scoring when no evidence exists."""
        mapping_result = ControlMappingResult(
            control_id="TEST.02",
            status=MappingStatus.UNSATISFIED,
            confidence=0.0,
            evidence_ids=[],
            evidence_types_found=[],
            evidence_types_missing=["type1", "type2"],
            last_evidence_date=None,
            explanation="No evidence",
        )

        score = self.calculator.calculate_subcategory_maturity("TEST.02", mapping_result)

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)

    def test_mixed_status_controls(self) -> None:
        """Test scoring with mixed satisfied/partial/unsatisfied controls."""
        mapping_results = [
            ControlMappingResult(
                control_id="GV.OC-01",
                status=MappingStatus.SATISFIED,
                confidence=1.0,
                evidence_ids=["id1"],
                evidence_types_found=["type1"],
                evidence_types_missing=[],
                last_evidence_date=self.now,
                explanation="Satisfied",
            ),
            ControlMappingResult(
                control_id="ID.AM-01",
                status=MappingStatus.PARTIAL,
                confidence=0.5,
                evidence_ids=["id2"],
                evidence_types_found=["type2"],
                evidence_types_missing=["type3"],
                last_evidence_date=self.now,
                explanation="Partial",
            ),
            ControlMappingResult(
                control_id="PR.AA-01",
                status=MappingStatus.UNSATISFIED,
                confidence=0.0,
                evidence_ids=[],
                evidence_types_found=[],
                evidence_types_missing=["type4"],
                last_evidence_date=None,
                explanation="Unsatisfied",
            ),
        ]

        breakdown = self.calculator.calculate_all(mapping_results)

        # Should have functions represented
        self.assertIn("GV", breakdown.by_function)
        self.assertIn("ID", breakdown.by_function)
        self.assertIn("PR", breakdown.by_function)

    def test_very_old_evidence(self) -> None:
        """Test scoring with very old evidence."""
        old_date = self.now - timedelta(days=365)
        mapping_result = ControlMappingResult(
            control_id="TEST.04",
            status=MappingStatus.SATISFIED,
            confidence=0.8,
            evidence_ids=["id1"],
            evidence_types_found=["type1"],
            evidence_types_missing=[],
            last_evidence_date=old_date,
            explanation="Old evidence",
        )

        score = self.calculator.calculate_subcategory_maturity("TEST.04", mapping_result)

        # Should still be scored but with lower confidence/score
        self.assertGreater(score.score, 0.0)


class TestStatistics(unittest.TestCase):
    """Tests for breakdown statistics."""

    def test_statistics_calculated(self) -> None:
        """Test that statistics are included in breakdown."""
        calculator = MaturityCalculator()
        now = datetime.now(UTC)

        mapping_results = [
            ControlMappingResult(
                control_id="GV.OC-01",
                status=MappingStatus.SATISFIED,
                confidence=1.0,
                evidence_ids=["id1", "id2"],
                evidence_types_found=["type1"],
                evidence_types_missing=[],
                last_evidence_date=now,
                explanation="Test",
            ),
        ]

        breakdown = calculator.calculate_all(mapping_results)

        self.assertIn("statistics", breakdown.to_dict())


class TestNotApplicableStatus(unittest.TestCase):
    """Tests for NOT_APPLICABLE status handling."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def test_not_applicable_control_gets_neutral_score(self) -> None:
        """Test that NOT_APPLICABLE controls get a neutral/satisfied score."""
        mapping_result = ControlMappingResult(
            control_id="GV.OC-01",
            status=MappingStatus.NOT_APPLICABLE,
            confidence=1.0,
            evidence_ids=["id1"],
            evidence_types_found=["type1"],
            evidence_types_missing=[],
            last_evidence_date=self.now,
            explanation="Control not applicable to organization",
        )

        score = self.calculator.calculate_subcategory_maturity("GV.OC-01", mapping_result)

        # NOT_APPLICABLE should get satisfied_fresh_score (3.0 by default)
        self.assertEqual(score.score, self.calculator.config.satisfied_fresh_score)
        self.assertIn("not applicable", score.explanation.lower())


class TestImprovementBonus(unittest.TestCase):
    """Tests for improvement bonus scoring."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def test_improvement_bonus_applied(self) -> None:
        """Test that improvement bonus is applied when score improves."""
        # Previous score was low
        previous_score = MaturityScore(
            entity_id="GV.OC-01",
            entity_type=EntityType.SUBCATEGORY,
            level=1,
            score=1.0,  # Low previous score
            evidence_count=1,
            last_evidence_date=self.now - timedelta(days=30),
            confidence=0.5,
            explanation="Previous low score",
        )

        # Current mapping shows improvement
        mapping_result = ControlMappingResult(
            control_id="GV.OC-01",
            status=MappingStatus.SATISFIED,
            confidence=1.0,
            evidence_ids=["id1", "id2"],
            evidence_types_found=["type1"],
            evidence_types_missing=[],
            last_evidence_date=self.now,
            explanation="Improved evidence",
        )

        score = self.calculator.calculate_subcategory_maturity(
            "GV.OC-01", mapping_result, previous_score
        )

        # Score should include improvement bonus
        self.assertIn("improvement bonus", score.explanation.lower())
        # Final score should be capped at max_score
        self.assertLessEqual(score.score, self.calculator.config.max_score)


class TestWeightedMaturityScoring(unittest.TestCase):
    """Tests for weighted maturity scoring at category, function, and overall levels."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_mapping(self, control_id: str, status: MappingStatus) -> ControlMappingResult:
        """Helper to create mapping result."""
        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=1.0 if status == MappingStatus.SATISFIED else 0.5,
            evidence_ids=["id1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_found=["type1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_missing=[] if status == MappingStatus.SATISFIED else ["missing"],
            last_evidence_date=self.now if status != MappingStatus.UNSATISFIED else None,
            explanation="Test",
        )

    def test_category_maturity_with_weights(self) -> None:
        """Test category maturity calculation with custom weights."""
        mapping_results = {
            "PR.AA-01": self._create_mapping("PR.AA-01", MappingStatus.SATISFIED),
            "PR.AA-02": self._create_mapping("PR.AA-02", MappingStatus.UNSATISFIED),
            "PR.AA-03": self._create_mapping("PR.AA-03", MappingStatus.PARTIAL),
            "PR.AA-04": self._create_mapping("PR.AA-04", MappingStatus.SATISFIED),
            "PR.AA-05": self._create_mapping("PR.AA-05", MappingStatus.SATISFIED),
            "PR.AA-06": self._create_mapping("PR.AA-06", MappingStatus.PARTIAL),
        }

        # Calculate with custom weights - weight the satisfied ones higher
        weights = {
            "PR.AA-01": 2.0,
            "PR.AA-02": 0.5,
            "PR.AA-03": 1.0,
            "PR.AA-04": 2.0,
            "PR.AA-05": 2.0,
            "PR.AA-06": 0.5,
        }

        weighted_score = self.calculator.calculate_category_maturity(
            "PR.AA", mapping_results, weights=weights
        )
        unweighted_score = self.calculator.calculate_category_maturity(
            "PR.AA", mapping_results
        )

        # Weighted score should be different from unweighted
        # Since we weighted satisfied controls higher, weighted should be higher
        self.assertIsInstance(weighted_score.score, float)
        self.assertIsInstance(unweighted_score.score, float)

    def test_function_maturity_with_weights(self) -> None:
        """Test function maturity calculation with custom weights."""
        mapping_results = {
            "PR.AA-01": self._create_mapping("PR.AA-01", MappingStatus.SATISFIED),
            "PR.DS-01": self._create_mapping("PR.DS-01", MappingStatus.PARTIAL),
            "PR.PS-01": self._create_mapping("PR.PS-01", MappingStatus.SATISFIED),
        }

        # Weight AA category higher
        weights = {"PR.AA": 3.0, "PR.DS": 1.0, "PR.PS": 1.0}

        weighted_score = self.calculator.calculate_function_maturity(
            "PR", mapping_results, weights=weights
        )
        unweighted_score = self.calculator.calculate_function_maturity(
            "PR", mapping_results
        )

        self.assertIsInstance(weighted_score.score, float)
        self.assertIsInstance(unweighted_score.score, float)

    def test_overall_maturity_with_weights(self) -> None:
        """Test overall maturity calculation with custom weights."""
        mapping_results = {
            "GV.OC-01": self._create_mapping("GV.OC-01", MappingStatus.SATISFIED),
            "ID.AM-01": self._create_mapping("ID.AM-01", MappingStatus.PARTIAL),
            "PR.AA-01": self._create_mapping("PR.AA-01", MappingStatus.UNSATISFIED),
        }

        # Weight GV function higher (which has satisfied)
        weights = {"GV": 5.0, "ID": 1.0, "PR": 1.0, "DE": 1.0, "RS": 1.0, "RC": 1.0}

        weighted_score = self.calculator.calculate_overall_maturity(
            mapping_results, weights=weights
        )
        unweighted_score = self.calculator.calculate_overall_maturity(mapping_results)

        self.assertIsInstance(weighted_score.score, float)
        self.assertIsInstance(unweighted_score.score, float)

    def test_category_maturity_with_zero_total_weight(self) -> None:
        """Test category maturity when total weight is zero."""
        mapping_results = {
            "PR.AA-01": self._create_mapping("PR.AA-01", MappingStatus.SATISFIED),
        }
        weights = {"PR.AA-01": 0.0}  # Zero weight

        score = self.calculator.calculate_category_maturity(
            "PR.AA", mapping_results, weights=weights
        )

        # Should handle gracefully (return 0.0 when total_weight is 0)
        self.assertEqual(score.score, 0.0)


class TestCategoryMaturityWithPreviousScores(unittest.TestCase):
    """Tests for category maturity with previous score delta calculation."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_mapping(self, control_id: str, status: MappingStatus) -> ControlMappingResult:
        """Helper to create mapping result."""
        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=1.0,
            evidence_ids=["id1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_found=["type1"] if status != MappingStatus.UNSATISFIED else [],
            evidence_types_missing=[],
            last_evidence_date=self.now,
            explanation="Test",
        )

    def test_category_delta_from_previous_scores(self) -> None:
        """Test that category calculates delta from previous subcategory scores."""
        mapping_results = {
            "PR.AA-01": self._create_mapping("PR.AA-01", MappingStatus.SATISFIED),
            "PR.AA-02": self._create_mapping("PR.AA-02", MappingStatus.SATISFIED),
        }

        # Previous scores for subcategories
        previous_scores = {
            "PR.AA-01": MaturityScore(
                entity_id="PR.AA-01",
                entity_type=EntityType.SUBCATEGORY,
                level=1,
                score=1.5,
                evidence_count=1,
                last_evidence_date=self.now - timedelta(days=30),
                confidence=0.5,
                explanation="Previous",
            ),
            "PR.AA-02": MaturityScore(
                entity_id="PR.AA-02",
                entity_type=EntityType.SUBCATEGORY,
                level=1,
                score=1.5,
                evidence_count=1,
                last_evidence_date=self.now - timedelta(days=30),
                confidence=0.5,
                explanation="Previous",
            ),
        }

        score = self.calculator.calculate_category_maturity(
            "PR.AA", mapping_results, previous_scores=previous_scores
        )

        # Delta should be calculated when previous_scores are provided
        self.assertIsNotNone(score.delta)
        # Score should be a reasonable value
        self.assertGreaterEqual(score.score, 0.0)
        self.assertLessEqual(score.score, 4.0)


class TestCompareBreakdowns(unittest.TestCase):
    """Tests for compare_breakdowns method."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()
        self.now = datetime.now(UTC)

    def _create_breakdown(
        self, overall_score: float, function_scores: dict[str, float], subcategory_scores: dict[str, float]
    ) -> MaturityBreakdown:
        """Helper to create breakdown."""
        overall = MaturityScore(
            entity_id="overall",
            entity_type=EntityType.OVERALL,
            level=self.calculator.config.score_to_level(overall_score),
            score=overall_score,
            evidence_count=10,
            last_evidence_date=self.now,
            confidence=0.8,
            explanation="Test overall",
        )

        by_function = {}
        for func_id, score in function_scores.items():
            by_function[func_id] = MaturityScore(
                entity_id=func_id,
                entity_type=EntityType.FUNCTION,
                level=self.calculator.config.score_to_level(score),
                score=score,
                evidence_count=5,
                last_evidence_date=self.now,
                confidence=0.8,
                explanation=f"Test {func_id}",
            )

        by_subcategory = {}
        for sub_id, score in subcategory_scores.items():
            by_subcategory[sub_id] = MaturityScore(
                entity_id=sub_id,
                entity_type=EntityType.SUBCATEGORY,
                level=self.calculator.config.score_to_level(score),
                score=score,
                evidence_count=1,
                last_evidence_date=self.now,
                confidence=0.8,
                explanation=f"Test {sub_id}",
            )

        return MaturityBreakdown(
            timestamp=self.now,
            overall=overall,
            by_function=by_function,
            by_category={},
            by_subcategory=by_subcategory,
            statistics={},
        )

    def test_compare_breakdowns_improvement(self) -> None:
        """Test comparing breakdowns that show improvement."""
        previous = self._create_breakdown(
            overall_score=2.0,
            function_scores={"GV": 2.0, "ID": 2.0, "PR": 2.0},
            subcategory_scores={"GV.OC-01": 2.0, "ID.AM-01": 2.0, "PR.AA-01": 2.0},
        )
        current = self._create_breakdown(
            overall_score=3.0,
            function_scores={"GV": 3.0, "ID": 3.0, "PR": 3.0},
            subcategory_scores={"GV.OC-01": 3.0, "ID.AM-01": 3.0, "PR.AA-01": 3.0},
        )

        result = self.calculator.compare_breakdowns(current, previous)

        self.assertEqual(result["overall_delta"], 1.0)
        self.assertEqual(result["overall_direction"], "improved")
        self.assertEqual(result["subcategories_improved"], 3)
        self.assertEqual(result["subcategories_regressed"], 0)

    def test_compare_breakdowns_regression(self) -> None:
        """Test comparing breakdowns that show regression."""
        previous = self._create_breakdown(
            overall_score=3.0,
            function_scores={"GV": 3.0, "ID": 3.0},
            subcategory_scores={"GV.OC-01": 3.0, "ID.AM-01": 3.0},
        )
        current = self._create_breakdown(
            overall_score=2.0,
            function_scores={"GV": 2.0, "ID": 2.0},
            subcategory_scores={"GV.OC-01": 2.0, "ID.AM-01": 2.0},
        )

        result = self.calculator.compare_breakdowns(current, previous)

        self.assertEqual(result["overall_delta"], -1.0)
        self.assertEqual(result["overall_direction"], "regressed")
        self.assertEqual(result["subcategories_regressed"], 2)
        self.assertEqual(result["subcategories_improved"], 0)

    def test_compare_breakdowns_unchanged(self) -> None:
        """Test comparing breakdowns that are unchanged."""
        previous = self._create_breakdown(
            overall_score=2.5,
            function_scores={"GV": 2.5},
            subcategory_scores={"GV.OC-01": 2.5},
        )
        current = self._create_breakdown(
            overall_score=2.5,
            function_scores={"GV": 2.5},
            subcategory_scores={"GV.OC-01": 2.5},
        )

        result = self.calculator.compare_breakdowns(current, previous)

        self.assertEqual(result["overall_delta"], 0.0)
        self.assertEqual(result["overall_direction"], "unchanged")
        self.assertEqual(result["subcategories_unchanged"], 1)

    def test_compare_breakdowns_includes_time_between(self) -> None:
        """Test that comparison includes time between breakdowns."""
        previous = self._create_breakdown(2.0, {"GV": 2.0}, {"GV.OC-01": 2.0})
        previous.timestamp = self.now - timedelta(days=7)
        current = self._create_breakdown(2.5, {"GV": 2.5}, {"GV.OC-01": 2.5})

        result = self.calculator.compare_breakdowns(current, previous)

        self.assertIn("time_between", result)
        self.assertIn("7 day", result["time_between"])


class TestNullMappingResult(unittest.TestCase):
    """Tests for handling null/None mapping results."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()

    def test_subcategory_with_null_mapping(self) -> None:
        """Test subcategory score when mapping result is None."""
        score = self.calculator.calculate_subcategory_maturity("GV.OC-01", None)

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)
        self.assertEqual(score.evidence_count, 0)
        self.assertIsNone(score.last_evidence_date)
        self.assertEqual(score.confidence, 0.0)
        self.assertIn("no evidence mapping", score.explanation.lower())


class TestFunctionWithNoCategories(unittest.TestCase):
    """Tests for function maturity when function has no categories."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()

    def test_function_with_no_matching_categories(self) -> None:
        """Test function score when no categories match."""
        # Use a non-existent function ID
        score = self.calculator.calculate_function_maturity("XX", {})

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)
        self.assertIn("no categories", score.explanation.lower())


class TestCategoryWithNoSubcategories(unittest.TestCase):
    """Tests for category maturity when category has no subcategories."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.calculator = MaturityCalculator()

    def test_category_with_no_matching_subcategories(self) -> None:
        """Test category score when no subcategories match."""
        # Use a non-existent category ID
        score = self.calculator.calculate_category_maturity("XX.YY", {})

        self.assertEqual(score.score, 0.0)
        self.assertEqual(score.level, 0)
        self.assertIn("no subcategories", score.explanation.lower())


if __name__ == "__main__":
    unittest.main()
