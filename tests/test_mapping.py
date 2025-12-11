"""
Tests for the NIST CSF 2.0 mapping engine.

Uses Python's unittest module.
Tests evidence-to-control mapping, confidence calculations,
freshness calculations, and all mapping logic types.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from nisify.collectors.base import Evidence
from nisify.nist.mapping_engine import (
    ControlMappingResult,
    EvidenceMapping,
    MappingEngine,
    MappingLogic,
    MappingStatus,
)


class TestMappingStatus(unittest.TestCase):
    """Tests for MappingStatus enum."""

    def test_status_values(self) -> None:
        """Test all status values are defined."""
        self.assertEqual(MappingStatus.SATISFIED.value, "satisfied")
        self.assertEqual(MappingStatus.PARTIAL.value, "partial")
        self.assertEqual(MappingStatus.UNSATISFIED.value, "unsatisfied")
        self.assertEqual(MappingStatus.NOT_APPLICABLE.value, "not_applicable")


class TestMappingLogic(unittest.TestCase):
    """Tests for MappingLogic enum."""

    def test_logic_values(self) -> None:
        """Test all logic types are defined."""
        self.assertEqual(MappingLogic.ALL_REQUIRED.value, "all_required")
        self.assertEqual(MappingLogic.ANY_REQUIRED.value, "any_required")
        self.assertEqual(MappingLogic.WEIGHTED.value, "weighted")


class TestEvidenceMapping(unittest.TestCase):
    """Tests for EvidenceMapping dataclass."""

    def test_from_dict_minimal(self) -> None:
        """Test creating mapping from minimal dictionary."""
        data = {
            "control_id": "PR.AC-01",
            "required_evidence_types": ["mfa_status"],
        }

        mapping = EvidenceMapping.from_dict(data)

        self.assertEqual(mapping.control_id, "PR.AC-01")
        self.assertEqual(mapping.required_evidence_types, ["mfa_status"])
        self.assertEqual(mapping.optional_evidence_types, [])
        self.assertEqual(mapping.platforms, [])
        self.assertEqual(mapping.logic, MappingLogic.ALL_REQUIRED)
        self.assertEqual(mapping.freshness_days, 30)

    def test_from_dict_full(self) -> None:
        """Test creating mapping from full dictionary."""
        data = {
            "control_id": "PR.AC-02",
            "required_evidence_types": ["user_inventory", "access_policies"],
            "optional_evidence_types": ["access_logs"],
            "platforms": ["okta", "google"],
            "logic": "any_required",
            "freshness_days": 14,
            "weights": {"user_inventory": 0.6, "access_policies": 0.4},
            "description": "Identity management controls",
        }

        mapping = EvidenceMapping.from_dict(data)

        self.assertEqual(mapping.control_id, "PR.AC-02")
        self.assertEqual(
            mapping.required_evidence_types,
            ["user_inventory", "access_policies"],
        )
        self.assertEqual(mapping.optional_evidence_types, ["access_logs"])
        self.assertEqual(mapping.platforms, ["okta", "google"])
        self.assertEqual(mapping.logic, MappingLogic.ANY_REQUIRED)
        self.assertEqual(mapping.freshness_days, 14)
        self.assertEqual(mapping.weights, {"user_inventory": 0.6, "access_policies": 0.4})
        self.assertEqual(mapping.description, "Identity management controls")


class TestControlMappingResult(unittest.TestCase):
    """Tests for ControlMappingResult dataclass."""

    def test_to_dict(self) -> None:
        """Test converting result to dictionary."""
        last_date = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        result = ControlMappingResult(
            control_id="PR.AC-01",
            status=MappingStatus.SATISFIED,
            confidence=0.85,
            evidence_ids=["id1", "id2"],
            evidence_types_found=["mfa_status"],
            evidence_types_missing=[],
            last_evidence_date=last_date,
            explanation="MFA evidence found for all users",
            freshness_penalty=0.05,
        )

        result_dict = result.to_dict()

        self.assertEqual(result_dict["control_id"], "PR.AC-01")
        self.assertEqual(result_dict["status"], "satisfied")
        self.assertEqual(result_dict["confidence"], 0.85)
        self.assertEqual(result_dict["evidence_ids"], ["id1", "id2"])
        self.assertEqual(result_dict["evidence_types_found"], ["mfa_status"])
        self.assertEqual(result_dict["evidence_types_missing"], [])
        self.assertEqual(result_dict["last_evidence_date"], "2024-01-15T12:00:00+00:00")
        self.assertEqual(result_dict["explanation"], "MFA evidence found for all users")
        self.assertEqual(result_dict["freshness_penalty"], 0.05)

    def test_to_dict_no_last_date(self) -> None:
        """Test converting result without last evidence date."""
        result = ControlMappingResult(
            control_id="PR.AC-01",
            status=MappingStatus.UNSATISFIED,
            confidence=0.0,
        )

        result_dict = result.to_dict()
        self.assertIsNone(result_dict["last_evidence_date"])


class TestMappingEngine(unittest.TestCase):
    """Tests for MappingEngine class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        # Create fresh evidence for testing
        self.now = datetime.now(UTC)
        self.fresh_evidence = self._create_evidence("mfa_status", self.now)
        self.stale_evidence = self._create_evidence(
            "mfa_status",
            self.now - timedelta(days=45),
        )
        self.very_stale_evidence = self._create_evidence(
            "mfa_status",
            self.now - timedelta(days=90),
        )

    def _create_evidence(
        self,
        evidence_type: str,
        collected_at: datetime,
        platform: str = "test",
        raw_data: dict[str, Any] | None = None,
    ) -> Evidence:
        """Helper to create evidence for testing."""
        evidence = Evidence.create(
            platform=platform,
            evidence_type=evidence_type,
            raw_data=raw_data or {"test": True},
        )
        # Override collected_at for testing
        evidence.collected_at = collected_at
        return evidence

    def _results_to_dict(self, results: list[ControlMappingResult]) -> dict[str, ControlMappingResult]:
        """Convert list of results to dict keyed by control_id."""
        return {r.control_id: r for r in results}

    def test_engine_initialization(self) -> None:
        """Test engine initializes and loads mappings."""
        engine = MappingEngine()

        # Should have loaded some mappings
        self.assertIsInstance(engine.mappings, dict)

    def test_get_mapping_for_control(self) -> None:
        """Test getting mapping configuration for a control."""
        engine = MappingEngine()

        # Add a test mapping
        engine.mappings["TEST.01"] = EvidenceMapping(
            control_id="TEST.01",
            required_evidence_types=["test_type"],
        )

        mapping = engine.mappings.get("TEST.01")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.control_id, "TEST.01")

    def test_map_evidence_satisfied(self) -> None:
        """Test mapping evidence that satisfies a control."""
        engine = MappingEngine()

        # Add test mapping
        engine.mappings["TEST.01"] = EvidenceMapping(
            control_id="TEST.01",
            required_evidence_types=["mfa_status"],
            logic=MappingLogic.ALL_REQUIRED,
            freshness_days=30,
        )

        evidence_items = [self.fresh_evidence]
        results = self._results_to_dict(engine.map_evidence(evidence_items))

        result = results.get("TEST.01")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, MappingStatus.SATISFIED)
        self.assertGreater(result.confidence, 0.5)
        self.assertEqual(result.evidence_types_found, ["mfa_status"])
        self.assertEqual(result.evidence_types_missing, [])

    def test_map_evidence_unsatisfied(self) -> None:
        """Test mapping with no matching evidence."""
        engine = MappingEngine()

        engine.mappings["TEST.02"] = EvidenceMapping(
            control_id="TEST.02",
            required_evidence_types=["password_policy"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        # Only have mfa_status, not password_policy
        evidence_items = [self.fresh_evidence]
        results = self._results_to_dict(engine.map_evidence(evidence_items))

        result = results.get("TEST.02")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, MappingStatus.UNSATISFIED)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.evidence_types_missing, ["password_policy"])

    def test_map_evidence_partial_all_required(self) -> None:
        """Test partial mapping with all_required logic."""
        engine = MappingEngine()

        engine.mappings["TEST.03"] = EvidenceMapping(
            control_id="TEST.03",
            required_evidence_types=["mfa_status", "password_policy"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        # Only have one of two required types
        evidence_items = [self.fresh_evidence]  # Only mfa_status
        results = self._results_to_dict(engine.map_evidence(evidence_items))

        result = results.get("TEST.03")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, MappingStatus.PARTIAL)
        self.assertIn("mfa_status", result.evidence_types_found)
        self.assertIn("password_policy", result.evidence_types_missing)

    def test_map_evidence_any_required_satisfied(self) -> None:
        """Test any_required logic is satisfied with one evidence type."""
        engine = MappingEngine()

        engine.mappings["TEST.04"] = EvidenceMapping(
            control_id="TEST.04",
            required_evidence_types=["mfa_status", "password_policy", "access_logs"],
            logic=MappingLogic.ANY_REQUIRED,
        )

        # Only have one of three required types
        evidence_items = [self.fresh_evidence]  # Only mfa_status
        results = self._results_to_dict(engine.map_evidence(evidence_items))

        result = results.get("TEST.04")
        self.assertIsNotNone(result)
        # With any_required logic, having one of multiple types should satisfy or partial
        self.assertIn(result.status, [MappingStatus.SATISFIED, MappingStatus.PARTIAL])
        self.assertIn("mfa_status", result.evidence_types_found)

    def test_freshness_penalty_applied(self) -> None:
        """Test that stale evidence reduces confidence."""
        engine = MappingEngine()

        engine.mappings["TEST.05"] = EvidenceMapping(
            control_id="TEST.05",
            required_evidence_types=["mfa_status"],
            logic=MappingLogic.ALL_REQUIRED,
            freshness_days=30,
        )

        # Test with fresh evidence
        fresh_results = self._results_to_dict(engine.map_evidence([self.fresh_evidence]))
        fresh_result = fresh_results.get("TEST.05")
        fresh_confidence = fresh_result.confidence

        # Test with stale evidence
        stale_results = self._results_to_dict(engine.map_evidence([self.stale_evidence]))
        stale_result = stale_results.get("TEST.05")
        stale_confidence = stale_result.confidence

        # Stale evidence should have lower confidence
        self.assertGreater(fresh_confidence, stale_confidence)
        self.assertGreater(stale_result.freshness_penalty, 0)

    def test_very_stale_evidence(self) -> None:
        """Test that very stale evidence has minimal confidence."""
        engine = MappingEngine()

        engine.mappings["TEST.06"] = EvidenceMapping(
            control_id="TEST.06",
            required_evidence_types=["mfa_status"],
            logic=MappingLogic.ALL_REQUIRED,
            freshness_days=30,
        )

        results = self._results_to_dict(engine.map_evidence([self.very_stale_evidence]))
        result = results.get("TEST.06")

        # Very stale evidence should still satisfy but with low confidence
        self.assertEqual(result.status, MappingStatus.SATISFIED)
        self.assertLessEqual(result.confidence, 0.5)

    def test_multiple_evidence_same_type(self) -> None:
        """Test handling multiple evidence items of same type."""
        engine = MappingEngine()

        engine.mappings["TEST.07"] = EvidenceMapping(
            control_id="TEST.07",
            required_evidence_types=["mfa_status"],
            logic=MappingLogic.ALL_REQUIRED,
            freshness_days=30,
        )

        # Multiple evidence items of same type
        evidence_items = [
            self._create_evidence("mfa_status", self.now - timedelta(days=10)),
            self._create_evidence("mfa_status", self.now - timedelta(days=5)),
            self._create_evidence("mfa_status", self.now - timedelta(days=1)),
        ]

        results = self._results_to_dict(engine.map_evidence(evidence_items))
        result = results.get("TEST.07")

        self.assertEqual(result.status, MappingStatus.SATISFIED)
        # Should use most recent evidence
        self.assertEqual(len(result.evidence_ids), 3)

    def test_weighted_logic(self) -> None:
        """Test weighted mapping logic."""
        engine = MappingEngine()

        engine.mappings["TEST.08"] = EvidenceMapping(
            control_id="TEST.08",
            required_evidence_types=["mfa_status", "password_policy"],
            logic=MappingLogic.WEIGHTED,
            weights={"mfa_status": 0.7, "password_policy": 0.3},
        )

        # Only have mfa_status which has higher weight
        evidence_items = [self.fresh_evidence]
        results = self._results_to_dict(engine.map_evidence(evidence_items))

        result = results.get("TEST.08")
        self.assertIsNotNone(result)
        # Should be partial with confidence based on weight
        self.assertEqual(result.status, MappingStatus.PARTIAL)

    def test_map_all_evidence(self) -> None:
        """Test mapping all evidence to all controls."""
        engine = MappingEngine()

        # Add multiple test mappings
        engine.mappings["TEST.A"] = EvidenceMapping(
            control_id="TEST.A",
            required_evidence_types=["mfa_status"],
            logic=MappingLogic.ALL_REQUIRED,
        )
        engine.mappings["TEST.B"] = EvidenceMapping(
            control_id="TEST.B",
            required_evidence_types=["password_policy"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        evidence_items = [
            self.fresh_evidence,
            self._create_evidence("password_policy", self.now),
        ]

        results = self._results_to_dict(engine.map_evidence(evidence_items))

        self.assertIn("TEST.A", results)
        self.assertIn("TEST.B", results)
        self.assertEqual(results["TEST.A"].status, MappingStatus.SATISFIED)
        self.assertEqual(results["TEST.B"].status, MappingStatus.SATISFIED)

    def test_get_evidence_for_control(self) -> None:
        """Test getting evidence that maps to a specific control."""
        engine = MappingEngine()

        engine.mappings["TEST.C"] = EvidenceMapping(
            control_id="TEST.C",
            required_evidence_types=["mfa_status", "access_logs"],
        )

        evidence_items = [
            self.fresh_evidence,  # mfa_status
            self._create_evidence("access_logs", self.now),
            self._create_evidence("other_type", self.now),
        ]

        matching = engine.get_evidence_for_control("TEST.C", evidence_items)

        self.assertEqual(len(matching), 2)
        evidence_types = {e.evidence_type for e in matching}
        self.assertEqual(evidence_types, {"mfa_status", "access_logs"})

    def test_get_unmapped_controls(self) -> None:
        """Test getting controls without evidence."""
        engine = MappingEngine()

        engine.mappings["TEST.D"] = EvidenceMapping(
            control_id="TEST.D",
            required_evidence_types=["mfa_status"],
        )
        engine.mappings["TEST.E"] = EvidenceMapping(
            control_id="TEST.E",
            required_evidence_types=["nonexistent_type"],
        )

        evidence_items = [self.fresh_evidence]  # Only mfa_status

        unmapped = engine.get_unmapped_controls(evidence_items)

        self.assertIn("TEST.E", unmapped)
        self.assertNotIn("TEST.D", unmapped)


class TestFreshnessCalculation(unittest.TestCase):
    """Tests specifically for freshness calculation logic."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

        # Add test mapping with 30-day freshness
        self.engine.mappings["FRESH.01"] = EvidenceMapping(
            control_id="FRESH.01",
            required_evidence_types=["test_type"],
            freshness_days=30,
        )

    def _create_evidence_at_age(self, days_old: int) -> Evidence:
        """Create evidence that is a certain number of days old."""
        evidence = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={},
        )
        evidence.collected_at = self.now - timedelta(days=days_old)
        return evidence

    def _results_to_dict(self, results: list[ControlMappingResult]) -> dict[str, ControlMappingResult]:
        """Convert list of results to dict keyed by control_id."""
        return {r.control_id: r for r in results}

    def test_fresh_evidence_no_penalty(self) -> None:
        """Test evidence within freshness window has no penalty."""
        evidence = self._create_evidence_at_age(0)
        results = self._results_to_dict(self.engine.map_evidence([evidence]))
        result = results.get("FRESH.01")

        self.assertEqual(result.freshness_penalty, 0.0)

    def test_edge_of_freshness_window(self) -> None:
        """Test evidence at edge of freshness window."""
        evidence = self._create_evidence_at_age(30)
        results = self._results_to_dict(self.engine.map_evidence([evidence]))
        result = results.get("FRESH.01")

        # Should have minimal or no penalty at exactly 30 days
        self.assertLessEqual(result.freshness_penalty, 0.1)

    def test_stale_evidence_linear_decay(self) -> None:
        """Test that stale evidence confidence decays linearly."""
        evidence_40_days = self._create_evidence_at_age(40)
        evidence_50_days = self._create_evidence_at_age(50)

        results_40 = self._results_to_dict(self.engine.map_evidence([evidence_40_days]))
        results_50 = self._results_to_dict(self.engine.map_evidence([evidence_50_days]))

        result_40 = results_40.get("FRESH.01")
        result_50 = results_50.get("FRESH.01")

        # Older evidence should have higher penalty
        self.assertGreater(result_50.freshness_penalty, result_40.freshness_penalty)

    def test_very_stale_evidence_maximum_penalty(self) -> None:
        """Test that very stale evidence has maximum penalty."""
        evidence = self._create_evidence_at_age(120)  # 4x freshness window
        results = self._results_to_dict(self.engine.map_evidence([evidence]))
        result = results.get("FRESH.01")

        # Should have significant penalty
        self.assertGreaterEqual(result.freshness_penalty, 0.5)


class TestConfidenceCalculation(unittest.TestCase):
    """Tests for confidence score calculation."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

    def _results_to_dict(self, results: list[ControlMappingResult]) -> dict[str, ControlMappingResult]:
        """Convert list of results to dict keyed by control_id."""
        return {r.control_id: r for r in results}

    def test_confidence_range(self) -> None:
        """Test confidence is always between 0 and 1."""
        # Add mapping
        self.engine.mappings["CONF.01"] = EvidenceMapping(
            control_id="CONF.01",
            required_evidence_types=["test_type"],
        )

        evidence = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={},
        )

        results = self._results_to_dict(self.engine.map_evidence([evidence]))
        result = results.get("CONF.01")

        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_unsatisfied_zero_confidence(self) -> None:
        """Test unsatisfied controls have zero confidence."""
        self.engine.mappings["CONF.02"] = EvidenceMapping(
            control_id="CONF.02",
            required_evidence_types=["missing_type"],
        )

        evidence = Evidence.create(
            platform="test",
            evidence_type="other_type",
            raw_data={},
        )

        results = self._results_to_dict(self.engine.map_evidence([evidence]))
        result = results.get("CONF.02")

        self.assertEqual(result.status, MappingStatus.UNSATISFIED)
        self.assertEqual(result.confidence, 0.0)


class TestMappingEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

    def _create_evidence(
        self,
        evidence_type: str,
        collected_at: datetime | None = None,
    ) -> Evidence:
        """Helper to create evidence."""
        evidence = Evidence.create(
            platform="test",
            evidence_type=evidence_type,
            raw_data={"test": True},
        )
        if collected_at:
            evidence.collected_at = collected_at
        return evidence

    def _results_to_dict(
        self, results: list[ControlMappingResult]
    ) -> dict[str, ControlMappingResult]:
        """Convert list of results to dict keyed by control_id."""
        return {r.control_id: r for r in results}

    def test_no_required_evidence_types_all_required(self) -> None:
        """Test all_required with empty required list returns NOT_APPLICABLE."""
        self.engine.mappings["EDGE.01"] = EvidenceMapping(
            control_id="EDGE.01",
            required_evidence_types=[],
            logic=MappingLogic.ALL_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("any_type")])
        )
        result = results.get("EDGE.01")

        self.assertEqual(result.status, MappingStatus.NOT_APPLICABLE)
        self.assertEqual(result.confidence, 0.0)

    def test_no_required_evidence_types_any_required(self) -> None:
        """Test any_required with empty required list returns NOT_APPLICABLE."""
        self.engine.mappings["EDGE.02"] = EvidenceMapping(
            control_id="EDGE.02",
            required_evidence_types=[],
            logic=MappingLogic.ANY_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("any_type")])
        )
        result = results.get("EDGE.02")

        self.assertEqual(result.status, MappingStatus.NOT_APPLICABLE)

    def test_no_required_evidence_types_weighted(self) -> None:
        """Test weighted with empty required list returns NOT_APPLICABLE."""
        self.engine.mappings["EDGE.03"] = EvidenceMapping(
            control_id="EDGE.03",
            required_evidence_types=[],
            logic=MappingLogic.WEIGHTED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("any_type")])
        )
        result = results.get("EDGE.03")

        self.assertEqual(result.status, MappingStatus.NOT_APPLICABLE)

    def test_weighted_zero_total_weight(self) -> None:
        """Test weighted logic with zero total weight."""
        self.engine.mappings["EDGE.04"] = EvidenceMapping(
            control_id="EDGE.04",
            required_evidence_types=["type_a"],
            logic=MappingLogic.WEIGHTED,
            weights={"type_a": 0.0},  # Zero weight
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("type_a")])
        )
        result = results.get("EDGE.04")

        self.assertEqual(result.status, MappingStatus.NOT_APPLICABLE)

    def test_weighted_high_ratio_satisfied(self) -> None:
        """Test weighted logic with high ratio is SATISFIED."""
        self.engine.mappings["EDGE.05"] = EvidenceMapping(
            control_id="EDGE.05",
            required_evidence_types=["type_a", "type_b"],
            logic=MappingLogic.WEIGHTED,
            weights={"type_a": 0.9, "type_b": 0.1},
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("type_a")])
        )
        result = results.get("EDGE.05")

        self.assertEqual(result.status, MappingStatus.SATISFIED)

    def test_weighted_medium_ratio_partial(self) -> None:
        """Test weighted logic with medium ratio is PARTIAL."""
        self.engine.mappings["EDGE.06"] = EvidenceMapping(
            control_id="EDGE.06",
            required_evidence_types=["type_a", "type_b"],
            logic=MappingLogic.WEIGHTED,
            weights={"type_a": 0.5, "type_b": 0.5},
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("type_a")])
        )
        result = results.get("EDGE.06")

        self.assertEqual(result.status, MappingStatus.PARTIAL)

    def test_weighted_low_ratio_partial(self) -> None:
        """Test weighted logic with low ratio is PARTIAL with lower confidence."""
        self.engine.mappings["EDGE.07"] = EvidenceMapping(
            control_id="EDGE.07",
            required_evidence_types=["type_a", "type_b", "type_c"],
            logic=MappingLogic.WEIGHTED,
            weights={"type_a": 0.2, "type_b": 0.4, "type_c": 0.4},
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("type_a")])
        )
        result = results.get("EDGE.07")

        self.assertEqual(result.status, MappingStatus.PARTIAL)
        # Low ratio should have lower confidence
        self.assertLess(result.confidence, 0.5)

    def test_weighted_no_evidence_unsatisfied(self) -> None:
        """Test weighted logic with no evidence is UNSATISFIED."""
        self.engine.mappings["EDGE.08"] = EvidenceMapping(
            control_id="EDGE.08",
            required_evidence_types=["type_a"],
            logic=MappingLogic.WEIGHTED,
            weights={"type_a": 1.0},
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("other_type")])
        )
        result = results.get("EDGE.08")

        self.assertEqual(result.status, MappingStatus.UNSATISFIED)
        self.assertEqual(result.confidence, 0.0)

    def test_any_required_high_ratio(self) -> None:
        """Test any_required with high ratio of evidence types."""
        self.engine.mappings["EDGE.09"] = EvidenceMapping(
            control_id="EDGE.09",
            required_evidence_types=["type_a", "type_b"],
            logic=MappingLogic.ANY_REQUIRED,
        )

        # Both types found = ratio >= 0.5, should be SATISFIED
        results = self._results_to_dict(
            self.engine.map_evidence([
                self._create_evidence("type_a"),
                self._create_evidence("type_b"),
            ])
        )
        result = results.get("EDGE.09")

        self.assertEqual(result.status, MappingStatus.SATISFIED)

    def test_optional_evidence_boost(self) -> None:
        """Test that optional evidence boosts confidence."""
        self.engine.mappings["EDGE.10"] = EvidenceMapping(
            control_id="EDGE.10",
            required_evidence_types=["req_type"],
            optional_evidence_types=["opt_type1", "opt_type2"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        # Without optional
        results_no_opt = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("req_type")])
        )
        conf_no_opt = results_no_opt.get("EDGE.10").confidence

        # With optional
        results_with_opt = self._results_to_dict(
            self.engine.map_evidence([
                self._create_evidence("req_type"),
                self._create_evidence("opt_type1"),
            ])
        )
        conf_with_opt = results_with_opt.get("EDGE.10").confidence

        # Optional should boost confidence (but not exceed 1.0)
        self.assertGreaterEqual(conf_with_opt, conf_no_opt)

    def test_reload_mappings(self) -> None:
        """Test reloading mappings clears and reloads."""
        # Add a custom mapping
        self.engine.mappings["CUSTOM.01"] = EvidenceMapping(
            control_id="CUSTOM.01",
            required_evidence_types=["test"],
        )

        # Reload should clear custom and reload from config
        self.engine.reload_mappings()

        # Custom mapping should be gone if not in config file
        # (or restored if it was in config)
        self.assertIsInstance(self.engine.mappings, dict)
        self.assertNotIn("CUSTOM.01", self.engine.mappings)

    def test_get_evidence_for_control_no_mapping(self) -> None:
        """Test getting evidence for unmapped control returns empty list."""
        evidence = [self._create_evidence("any_type")]
        result = self.engine.get_evidence_for_control("NONEXISTENT.99", evidence)
        self.assertEqual(result, [])


class TestMappingEngineConfiguration(unittest.TestCase):
    """Tests for mapping configuration handling."""

    def test_missing_config_file(self) -> None:
        """Test engine handles missing config file gracefully."""
        import tempfile
        from pathlib import Path

        # Create engine with non-existent config path
        engine = MappingEngine(config_path=Path(tempfile.gettempdir()) / "nonexistent.json")

        # Should have empty mappings, not crash
        self.assertEqual(engine.mappings, {})

    def test_invalid_config_json(self) -> None:
        """Test engine handles invalid JSON gracefully."""
        import tempfile
        from pathlib import Path

        # Create temp file with invalid JSON
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json}")
            temp_path = f.name

        try:
            engine = MappingEngine(config_path=Path(temp_path))
            # Should have empty mappings, not crash
            self.assertEqual(engine.mappings, {})
        finally:
            import os
            os.unlink(temp_path)


class TestMappingSummaryAndExplanation(unittest.TestCase):
    """Tests for get_mapping_summary and get_mapping_explanation."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

    def _create_evidence(self, evidence_type: str) -> Evidence:
        """Helper to create evidence."""
        return Evidence.create(
            platform="test",
            evidence_type=evidence_type,
            raw_data={"test": True},
        )

    def test_get_mapping_summary(self) -> None:
        """Test getting mapping summary statistics."""
        summary = self.engine.get_mapping_summary()

        self.assertIn("total_subcategories", summary)
        self.assertIn("configured_mappings", summary)
        self.assertIn("unconfigured_mappings", summary)
        self.assertIn("coverage_percent", summary)
        self.assertIn("by_function", summary)
        self.assertIn("evidence_types_used", summary)
        self.assertIn("platforms_used", summary)

        # Validate types
        self.assertIsInstance(summary["total_subcategories"], int)
        self.assertIsInstance(summary["configured_mappings"], int)
        self.assertIsInstance(summary["coverage_percent"], float)
        self.assertIsInstance(summary["by_function"], dict)

    def test_get_controls_without_mapping(self) -> None:
        """Test getting controls without mapping configuration."""
        unmapped = self.engine.get_controls_without_mapping()

        self.assertIsInstance(unmapped, list)
        # Should be control ID strings
        for control_id in unmapped:
            self.assertIsInstance(control_id, str)
            # Should look like a NIST control ID
            self.assertIn(".", control_id)

    def test_get_mapping_explanation_with_mapping(self) -> None:
        """Test getting explanation for control with mapping."""
        # Add a test mapping
        self.engine.mappings["TEST.EXP"] = EvidenceMapping(
            control_id="TEST.EXP",
            required_evidence_types=["test_type"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        evidence = [self._create_evidence("test_type")]
        explanation = self.engine.get_mapping_explanation("TEST.EXP", evidence)

        self.assertIsInstance(explanation, str)
        self.assertGreater(len(explanation), 0)
        self.assertIn("SATISFIED", explanation)

    def test_get_mapping_explanation_without_mapping(self) -> None:
        """Test getting explanation for control without mapping."""
        # Use a known valid but unmapped control ID pattern
        explanation = self.engine.get_mapping_explanation(
            "GV.OC-01",  # Valid NIST control
            [self._create_evidence("any_type")],
        )

        self.assertIsInstance(explanation, str)
        # Should indicate no mapping or manual evidence needed
        self.assertGreater(len(explanation), 0)

    def test_get_mapping_explanation_invalid_control(self) -> None:
        """Test getting explanation for invalid control ID."""
        explanation = self.engine.get_mapping_explanation(
            "INVALID.XX-99",
            [self._create_evidence("any_type")],
        )

        self.assertIsInstance(explanation, str)
        self.assertIn("not a valid", explanation.lower())


class TestExplanationGeneration(unittest.TestCase):
    """Tests for explanation generation in different scenarios."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

    def _create_evidence(
        self,
        evidence_type: str,
        days_old: int = 0,
    ) -> Evidence:
        """Helper to create evidence."""
        evidence = Evidence.create(
            platform="test",
            evidence_type=evidence_type,
            raw_data={"test": True},
        )
        evidence.collected_at = self.now - timedelta(days=days_old)
        return evidence

    def _results_to_dict(
        self, results: list[ControlMappingResult]
    ) -> dict[str, ControlMappingResult]:
        """Convert list of results to dict keyed by control_id."""
        return {r.control_id: r for r in results}

    def test_explanation_mentions_stale_evidence(self) -> None:
        """Test explanation mentions when evidence is stale."""
        self.engine.mappings["EXP.01"] = EvidenceMapping(
            control_id="EXP.01",
            required_evidence_types=["test_type"],
            freshness_days=30,
            logic=MappingLogic.ALL_REQUIRED,
        )

        # Create stale evidence
        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("test_type", days_old=45)])
        )
        result = results.get("EXP.01")

        # Explanation should mention staleness
        self.assertIn("days old", result.explanation)
        self.assertIn("Confidence reduced", result.explanation)

    def test_explanation_mentions_missing_evidence(self) -> None:
        """Test explanation mentions missing evidence types."""
        self.engine.mappings["EXP.02"] = EvidenceMapping(
            control_id="EXP.02",
            required_evidence_types=["type_a", "type_b"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("type_a")])
        )
        result = results.get("EXP.02")

        self.assertIn("Missing evidence", result.explanation)
        self.assertIn("type_b", result.explanation)

    def test_explanation_mentions_found_evidence(self) -> None:
        """Test explanation mentions found evidence."""
        self.engine.mappings["EXP.03"] = EvidenceMapping(
            control_id="EXP.03",
            required_evidence_types=["found_type"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("found_type")])
        )
        result = results.get("EXP.03")

        self.assertIn("Found evidence", result.explanation)
        self.assertIn("found_type", result.explanation)

    def test_explanation_mentions_optional_evidence(self) -> None:
        """Test explanation mentions optional evidence when found."""
        self.engine.mappings["EXP.04"] = EvidenceMapping(
            control_id="EXP.04",
            required_evidence_types=["req_type"],
            optional_evidence_types=["opt_type"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([
                self._create_evidence("req_type"),
                self._create_evidence("opt_type"),
            ])
        )
        result = results.get("EXP.04")

        self.assertIn("Optional evidence found", result.explanation)

    def test_explanation_mentions_logic_type(self) -> None:
        """Test explanation mentions the mapping logic used."""
        for logic, expected_text in [
            (MappingLogic.ALL_REQUIRED, "All"),
            (MappingLogic.ANY_REQUIRED, "At least one"),
            (MappingLogic.WEIGHTED, "Weighted scoring"),
        ]:
            self.engine.mappings[f"EXP.{logic.value}"] = EvidenceMapping(
                control_id=f"EXP.{logic.value}",
                required_evidence_types=["test_type"],
                logic=logic,
            )

            results = self._results_to_dict(
                self.engine.map_evidence([self._create_evidence("test_type")])
            )
            result = results.get(f"EXP.{logic.value}")

            self.assertIn(expected_text, result.explanation)

    def test_explanation_for_not_applicable(self) -> None:
        """Test explanation for NOT_APPLICABLE status."""
        self.engine.mappings["EXP.NA"] = EvidenceMapping(
            control_id="EXP.NA",
            required_evidence_types=[],  # Empty required = NOT_APPLICABLE
            logic=MappingLogic.ALL_REQUIRED,
        )

        results = self._results_to_dict(
            self.engine.map_evidence([self._create_evidence("any_type")])
        )
        result = results.get("EXP.NA")

        self.assertEqual(result.status, MappingStatus.NOT_APPLICABLE)
        self.assertIn("no mapping configuration", result.explanation)


class TestCsf2Controls(unittest.TestCase):
    """Tests for csf2_controls module functions."""

    def test_get_subcategories_by_evidence_type(self) -> None:
        """Test getting subcategories by evidence type."""
        from nisify.nist.csf2_controls import get_subcategories_by_evidence_type

        # Test with a common evidence type
        subcats = get_subcategories_by_evidence_type("mfa_status")
        self.assertIsInstance(subcats, list)
        # mfa_status should map to some subcategories
        if subcats:
            from nisify.nist.csf2_controls import NistSubcategory
            self.assertIsInstance(subcats[0], NistSubcategory)

        # Test with nonexistent evidence type
        empty = get_subcategories_by_evidence_type("nonexistent_evidence_xyz")
        self.assertEqual(empty, [])

    def test_get_function(self) -> None:
        """Test getting a function by ID."""
        from nisify.nist.csf2_controls import get_function

        # Test valid function
        func = get_function("GV")
        self.assertIsNotNone(func)
        self.assertEqual(func.id, "GV")
        self.assertEqual(func.name, "Govern")

        # Test case insensitivity
        func_lower = get_function("pr")
        self.assertIsNotNone(func_lower)
        self.assertEqual(func_lower.id, "PR")

        # Test invalid function
        invalid = get_function("XX")
        self.assertIsNone(invalid)

    def test_get_category(self) -> None:
        """Test getting a category by ID."""
        from nisify.nist.csf2_controls import get_category

        # Test valid category
        cat = get_category("GV.OC")
        self.assertIsNotNone(cat)
        self.assertEqual(cat.id, "GV.OC")

        # Test another category
        cat2 = get_category("PR.AA")
        self.assertIsNotNone(cat2)
        self.assertEqual(cat2.id, "PR.AA")

        # Test invalid category
        invalid = get_category("XX.YY")
        self.assertIsNone(invalid)

    def test_get_all_functions(self) -> None:
        """Test getting all functions."""
        from nisify.nist.csf2_controls import get_all_functions

        functions = get_all_functions()
        self.assertIsInstance(functions, list)
        self.assertEqual(len(functions), 6)

        # Check all expected function IDs
        func_ids = {f.id for f in functions}
        self.assertEqual(func_ids, {"GV", "ID", "PR", "DE", "RS", "RC"})

    def test_get_all_categories(self) -> None:
        """Test getting all categories."""
        from nisify.nist.csf2_controls import get_all_categories

        categories = get_all_categories()
        self.assertIsInstance(categories, list)
        self.assertEqual(len(categories), 22)  # CSF 2.0 has 22 categories

        # All should have valid function_id
        valid_functions = {"GV", "ID", "PR", "DE", "RS", "RC"}
        for cat in categories:
            self.assertIn(cat.function_id, valid_functions)

    def test_get_api_collectible_subcategories(self) -> None:
        """Test getting API-collectible subcategories."""
        from nisify.nist.csf2_controls import get_api_collectible_subcategories

        subcats = get_api_collectible_subcategories()
        self.assertIsInstance(subcats, list)
        self.assertGreater(len(subcats), 0)

        # All should be api_collectible
        for subcat in subcats:
            self.assertTrue(subcat.api_collectible)

    def test_get_manual_evidence_subcategories(self) -> None:
        """Test getting manual evidence subcategories."""
        from nisify.nist.csf2_controls import get_manual_evidence_subcategories

        subcats = get_manual_evidence_subcategories()
        self.assertIsInstance(subcats, list)

        # All should NOT be api_collectible
        for subcat in subcats:
            self.assertFalse(subcat.api_collectible)

    def test_get_evidence_types(self) -> None:
        """Test getting all evidence types."""
        from nisify.nist.csf2_controls import get_evidence_types

        evidence_types = get_evidence_types()
        self.assertIsInstance(evidence_types, list)
        self.assertGreater(len(evidence_types), 0)

        # Should be sorted
        self.assertEqual(evidence_types, sorted(evidence_types))

        # All should be strings
        for et in evidence_types:
            self.assertIsInstance(et, str)

    def test_get_statistics(self) -> None:
        """Test getting control statistics."""
        from nisify.nist.csf2_controls import get_statistics

        stats = get_statistics()
        self.assertIsInstance(stats, dict)

        # Check expected keys
        expected_keys = [
            "functions",
            "categories",
            "subcategories",
            "api_collectible",
            "manual_evidence",
            "evidence_types",
        ]
        for key in expected_keys:
            self.assertIn(key, stats)
            self.assertIsInstance(stats[key], int)

        # Sanity checks
        self.assertEqual(stats["functions"], 6)  # GV, ID, PR, DE, RS, RC
        self.assertEqual(stats["subcategories"], 106)  # CSF 2.0 has 106 subcategories
        self.assertEqual(
            stats["api_collectible"] + stats["manual_evidence"],
            stats["subcategories"],
        )

    def test_export_controls_json(self) -> None:
        """Test exporting controls to JSON file."""
        import json
        import tempfile
        from pathlib import Path

        from nisify.nist.csf2_controls import export_controls_json

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "subdir" / "controls.json"

            export_controls_json(output_path)

            # File should exist
            self.assertTrue(output_path.exists())

            # Should be valid JSON
            with open(output_path) as f:
                data = json.load(f)

            # Check structure
            self.assertEqual(data["version"], "2.0")
            self.assertIn("functions", data)
            self.assertIn("statistics", data)
            self.assertEqual(len(data["functions"]), 6)

    def test_dataclass_to_dict_methods(self) -> None:
        """Test to_dict methods on CSF 2.0 dataclasses."""
        from nisify.nist.csf2_controls import (
            MaturityCriteria,
            NistCategory,
            NistFunction,
            NistSubcategory,
        )

        # Test MaturityCriteria.to_dict
        criteria = MaturityCriteria(
            level_0="No evidence",
            level_1="Initial",
            level_2="Developing",
            level_3="Defined",
            level_4="Optimized",
        )
        criteria_dict = criteria.to_dict()
        self.assertEqual(criteria_dict["0"], "No evidence")
        self.assertEqual(criteria_dict["4"], "Optimized")

        # Test NistSubcategory.to_dict
        subcat = NistSubcategory(
            id="TEST.01",
            name="Test Subcategory",
            description="Test description",
            category_id="TEST",
            evidence_types=["test_type"],
            api_collectible=True,
            maturity_criteria=criteria,
        )
        subcat_dict = subcat.to_dict()
        self.assertEqual(subcat_dict["id"], "TEST.01")
        self.assertEqual(subcat_dict["evidence_types"], ["test_type"])
        self.assertIn("maturity_criteria", subcat_dict)

        # Test NistCategory.to_dict
        category = NistCategory(
            id="TEST",
            name="Test Category",
            description="Test category description",
            function_id="PR",
            subcategories=[subcat],
        )
        category_dict = category.to_dict()
        self.assertEqual(category_dict["id"], "TEST")
        self.assertEqual(len(category_dict["subcategories"]), 1)

        # Test NistFunction.to_dict
        function = NistFunction(
            id="PR",
            name="Protect",
            description="Test function description",
            categories=[category],
        )
        function_dict = function.to_dict()
        self.assertEqual(function_dict["id"], "PR")
        self.assertEqual(len(function_dict["categories"]), 1)


class TestMappingEngineEdgeCases(unittest.TestCase):
    """Tests for edge cases in MappingEngine."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.now = datetime.now(UTC)
        self.engine = MappingEngine()

    def _create_evidence(self, evidence_type: str) -> Evidence:
        """Helper to create evidence."""
        return Evidence.create(
            platform="test",
            evidence_type=evidence_type,
            raw_data={"test": True},
        )

    def test_load_mappings_with_exception(self) -> None:
        """Test loading mappings handles general exceptions."""
        from unittest.mock import patch

        # Mock open to raise an exception (not JSON error)
        with patch("builtins.open") as mock_open:
            mock_open.side_effect = PermissionError("Cannot read file")

            engine = MappingEngine()
            # Should not raise, should log error and have empty mappings
            # The exception is caught in lines 228-229

    def test_unknown_mapping_logic_defaults_to_unsatisfied(self) -> None:
        """Test that unknown mapping logic defaults to UNSATISFIED status."""
        from unittest.mock import MagicMock

        # Create a mapping with mocked invalid logic value
        mapping = EvidenceMapping(
            control_id="TEST.LOGIC",
            required_evidence_types=["test_type"],
            logic=MappingLogic.ALL_REQUIRED,  # Start with valid
        )

        # Create a custom class that's not equal to any MappingLogic value
        class UnknownLogic:
            def __eq__(self, other: object) -> bool:
                return False

            def __ne__(self, other: object) -> bool:
                return True

        # Replace the logic with our unknown value
        # This simulates a corrupted or future enum value
        object.__setattr__(mapping, "logic", UnknownLogic())

        # Call _map_control directly to trigger the else branch
        evidence_by_type: dict[str, list[Evidence]] = {
            "test_type": [self._create_evidence("test_type")],
        }
        result = self.engine._map_control(mapping, evidence_by_type, self.now)

        # Should default to UNSATISFIED with 0 confidence (lines 333-334)
        self.assertEqual(result.status, MappingStatus.UNSATISFIED)
        self.assertEqual(result.confidence, 0.0)

    def test_get_mapping_explanation_valid_unmapped_control(self) -> None:
        """Test get_mapping_explanation for valid control without mapping."""
        # GV.OC-01 is a valid NIST control - if not mapped, should show description
        # First ensure it's not mapped by removing it if present
        if "GV.OC-01" in self.engine.mappings:
            del self.engine.mappings["GV.OC-01"]

        explanation = self.engine.get_mapping_explanation(
            "GV.OC-01",
            [self._create_evidence("any_type")],
        )

        # Should mention manual evidence needed (line 637)
        self.assertIn("manual evidence", explanation.lower())

    def test_get_mapping_summary_all_functions_counted(self) -> None:
        """Test that get_mapping_summary includes all functions even if no mappings."""
        # Create a minimal engine with only one mapping
        engine = MappingEngine()

        # Clear all mappings to ensure some functions have no configured mappings
        engine.mappings.clear()

        # Add just one mapping for GV
        engine.mappings["GV.OC-01"] = EvidenceMapping(
            control_id="GV.OC-01",
            required_evidence_types=["test_type"],
            logic=MappingLogic.ALL_REQUIRED,
        )

        summary = engine.get_mapping_summary()

        # Should have all 6 functions in by_function even if some have 0 configured
        # This tests line 679 where function entry is created
        self.assertIn("by_function", summary)
        by_function = summary["by_function"]

        # All 6 NIST functions should be present
        expected_functions = {"GV", "ID", "PR", "DE", "RS", "RC"}
        for func_id in expected_functions:
            self.assertIn(func_id, by_function)
            self.assertIn("configured", by_function[func_id])
            self.assertIn("total", by_function[func_id])


if __name__ == "__main__":
    unittest.main()
