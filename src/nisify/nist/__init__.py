"""
NIST CSF 2.0 control definitions, mapping logic, and maturity scoring.

This module contains the complete NIST CSF 2.0 control hierarchy,
evidence-to-control mapping engine, and maturity scoring calculator.

All scoring logic is deterministic and auditable - no machine learning
or probabilistic inference is used.

Control Hierarchy:
    - 6 Functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE),
                   Respond (RS), Recover (RC)
    - 22 Categories
    - 106 Subcategories

Mapping Engine:
    The MappingEngine class maps evidence to controls using configurable
    rules defined in data/control_evidence_mappings.json. Supports three
    logic types: all_required, any_required, and weighted.

Maturity Calculator:
    The MaturityCalculator class calculates maturity levels (0-4) based on
    evidence mapping results. Scoring flows from subcategories up through
    categories and functions to an overall score. All thresholds are
    configurable via MaturityConfig.
"""

from nisify.nist.csf2_controls import (
    MaturityCriteria,
    NistCategory,
    NistFunction,
    NistSubcategory,
    export_controls_json,
    get_all_categories,
    get_all_functions,
    get_all_subcategories,
    get_api_collectible_subcategories,
    get_category,
    get_evidence_types,
    get_function,
    get_manual_evidence_subcategories,
    get_statistics,
    get_subcategories_by_evidence_type,
    get_subcategory,
)
from nisify.nist.mapping_engine import (
    ControlMappingResult,
    EvidenceMapping,
    MappingEngine,
    MappingLogic,
    MappingStatus,
)
from nisify.nist.maturity_calculator import (
    EntityType,
    MaturityBreakdown,
    MaturityCalculator,
    MaturityConfig,
    MaturityScore,
)

__all__ = [
    # Dataclasses
    "NistFunction",
    "NistCategory",
    "NistSubcategory",
    "MaturityCriteria",
    # Lookup functions
    "get_function",
    "get_category",
    "get_subcategory",
    "get_all_functions",
    "get_all_categories",
    "get_all_subcategories",
    "get_subcategories_by_evidence_type",
    "get_api_collectible_subcategories",
    "get_manual_evidence_subcategories",
    "get_evidence_types",
    "get_statistics",
    # Export
    "export_controls_json",
    # Mapping Engine
    "MappingEngine",
    "MappingStatus",
    "MappingLogic",
    "EvidenceMapping",
    "ControlMappingResult",
    # Maturity Calculator
    "MaturityCalculator",
    "MaturityConfig",
    "MaturityScore",
    "MaturityBreakdown",
    "EntityType",
]
