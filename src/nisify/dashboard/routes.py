"""
Route handlers for the Nisify dashboard.

This module provides dedicated handler functions for each dashboard page
and API endpoint. Handlers process requests and return appropriate responses.

Pages:
    - /: Index/landing page
    - /dashboard: Main dashboard with maturity overview
    - /gaps: Gap analysis browser
    - /evidence: Evidence explorer
    - /trends: Historical trend charts

API Endpoints:
    - /api/summary: Dashboard summary data
    - /api/maturity: Full maturity breakdown
    - /api/gaps: Gap analysis results
    - /api/evidence: Evidence listing and search
    - /api/trends: Trend analysis data
    - /api/functions: Function-level scores
    - /api/health: Health check
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from nisify.analysis.gap_analyzer import GapAnalysis
from nisify.analysis.trend_tracker import TrendAnalysis
from nisify.nist.csf2_controls import (
    get_all_categories,
    get_all_functions,
    get_all_subcategories,
)
from nisify.nist.maturity_calculator import MaturityBreakdown

logger = logging.getLogger(__name__)


# Function descriptions for display
FUNCTION_DISPLAY_NAMES = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}


class RouteContext:
    """
    Context object passed to route handlers.

    Contains references to dashboard data and utilities for
    rendering responses.

    Attributes:
        maturity: Current maturity breakdown.
        gaps: Current gap analysis.
        trends: Current trend analysis.
        evidence_store: Reference to evidence store.
        organization_name: Organization name.
        last_updated: When data was last refreshed.
    """

    def __init__(
        self,
        maturity: MaturityBreakdown | None = None,
        gaps: GapAnalysis | None = None,
        trends: TrendAnalysis | None = None,
        evidence_store: Any = None,
        organization_name: str = "Organization",
        last_updated: datetime | None = None,
    ) -> None:
        """Initialize route context."""
        self.maturity = maturity
        self.gaps = gaps
        self.trends = trends
        self.evidence_store = evidence_store
        self.organization_name = organization_name
        self.last_updated = last_updated


# Route handler type
RouteHandler = Callable[[RouteContext, dict[str, list[str]]], dict[str, Any]]


def handle_api_summary(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/summary endpoint.

    Returns a summary of dashboard data for quick overview.

    Args:
        context: Route context with dashboard data.
        query: Query parameters (unused).

    Returns:
        Summary data dictionary.
    """
    summary: dict[str, Any] = {
        "organization": context.organization_name,
        "last_updated": (
            context.last_updated.isoformat() if context.last_updated else None
        ),
        "has_data": context.maturity is not None,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    if context.maturity:
        summary["maturity"] = {
            "overall_score": round(context.maturity.overall.score, 2),
            "overall_level": context.maturity.overall.level,
            "evidence_count": context.maturity.overall.evidence_count,
            "functions": {
                func_id: {
                    "name": FUNCTION_DISPLAY_NAMES.get(func_id, func_id),
                    "score": round(score.score, 2),
                    "level": score.level,
                }
                for func_id, score in context.maturity.by_function.items()
            },
        }

    if context.gaps:
        summary["gaps"] = {
            "total": context.gaps.controls_with_gaps,
            "percentage": round(context.gaps.gap_percentage, 1),
            "by_priority": context.gaps.gaps_by_priority,
            "critical_count": len(context.gaps.critical_gaps),
            "quick_wins_count": len(context.gaps.quick_wins),
        }

    if context.trends:
        summary["trends"] = {
            "direction": context.trends.overall_trend.direction.value,
            "score_delta": context.trends.overall_trend.score_delta,
            "period_days": context.trends.period_days,
            "improving_count": len(context.trends.improving_controls),
            "regressing_count": len(context.trends.regressing_controls),
        }

    return summary


def handle_api_maturity(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/maturity endpoint.

    Returns full maturity breakdown data.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - function: Filter by function ID.
            - level: Filter by minimum level.

    Returns:
        Maturity data dictionary.
    """
    if not context.maturity:
        return {"error": "No maturity data available", "status": 404}

    # Check for filters
    function_filter = query.get("function", [None])[0]
    level_filter = query.get("level", [None])[0]

    result = context.maturity.to_dict()

    # Apply function filter
    if function_filter:
        if function_filter in result["by_function"]:
            result["by_function"] = {
                function_filter: result["by_function"][function_filter]
            }
            # Filter categories and subcategories
            result["by_category"] = {
                k: v for k, v in result["by_category"].items()
                if k.startswith(function_filter + ".")
            }
            result["by_subcategory"] = {
                k: v for k, v in result["by_subcategory"].items()
                if k.startswith(function_filter + ".")
            }

    # Apply level filter
    if level_filter:
        try:
            min_level = int(level_filter)
            result["by_subcategory"] = {
                k: v for k, v in result["by_subcategory"].items()
                if v["level"] >= min_level
            }
        except ValueError:
            pass

    return result


def handle_api_gaps(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/gaps endpoint.

    Returns gap analysis data.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - priority: Filter by priority (critical, high, medium, low).
            - function: Filter by function ID.
            - type: Filter by gap type.

    Returns:
        Gap analysis data dictionary.
    """
    if not context.gaps:
        return {"error": "No gap analysis available", "status": 404}

    result = context.gaps.to_dict()

    # Apply priority filter
    priority_filter = query.get("priority", [None])[0]
    if priority_filter:
        result["all_gaps"] = [
            g for g in result["all_gaps"]
            if g["priority"] == priority_filter
        ]

    # Apply function filter
    function_filter = query.get("function", [None])[0]
    if function_filter:
        result["all_gaps"] = [
            g for g in result["all_gaps"]
            if g["function_id"] == function_filter
        ]
        if function_filter in result["gaps_by_function"]:
            result["gaps_by_function"] = {
                function_filter: result["gaps_by_function"][function_filter]
            }

    # Apply type filter
    type_filter = query.get("type", [None])[0]
    if type_filter:
        result["all_gaps"] = [
            g for g in result["all_gaps"]
            if g["gap_type"] == type_filter
        ]

    return result


def handle_api_evidence(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/evidence endpoint.

    Returns evidence listing data.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - platform: Filter by platform.
            - type: Filter by evidence type.
            - limit: Maximum number of items.
            - offset: Pagination offset.

    Returns:
        Evidence listing dictionary.
    """
    store = context.evidence_store

    if not store:
        return {
            "error": "No evidence store configured",
            "status": 404,
            "evidence": [],
            "statistics": {},
        }

    # Get query parameters
    platform = query.get("platform", [None])[0]
    evidence_type = query.get("type", [None])[0]
    limit = int(query.get("limit", ["100"])[0])
    offset = int(query.get("offset", ["0"])[0])

    try:
        # Get evidence statistics
        stats = {}
        if hasattr(store, "get_statistics"):
            stats = store.get_statistics()

        # Get evidence items
        evidence_list = []
        if hasattr(store, "get_all_evidence"):
            all_evidence = store.get_all_evidence(limit=limit + offset)

            for ev in all_evidence:
                # Convert StoredEvidence dataclass to dict if needed
                ev_dict = ev.to_dict() if hasattr(ev, "to_dict") else ev
                # Apply filters
                if platform and ev_dict.get("platform") != platform:
                    continue
                if evidence_type and ev_dict.get("evidence_type") != evidence_type:
                    continue
                evidence_list.append(ev_dict)

            # Apply pagination
            evidence_list = evidence_list[offset:offset + limit]

        # Get available platforms and types for filtering UI
        platforms = set()
        evidence_types = set()
        if hasattr(store, "get_all_evidence"):
            for ev in store.get_all_evidence(limit=1000):
                # Convert StoredEvidence dataclass to dict if needed
                ev_dict = ev.to_dict() if hasattr(ev, "to_dict") else ev
                if ev_dict.get("platform"):
                    platforms.add(ev_dict["platform"])
                if ev_dict.get("evidence_type"):
                    evidence_types.add(ev_dict["evidence_type"])

        return {
            "evidence": evidence_list,
            "total": len(evidence_list),
            "limit": limit,
            "offset": offset,
            "statistics": stats,
            "filters": {
                "platforms": sorted(platforms),
                "evidence_types": sorted(evidence_types),
            },
        }

    except Exception as e:
        logger.error("Error fetching evidence: %s", e)
        return {
            "error": str(e),
            "status": 500,
            "evidence": [],
            "statistics": {},
        }


def handle_api_trends(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/trends endpoint.

    Returns trend analysis data.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - function: Filter by function ID.
            - direction: Filter by trend direction.

    Returns:
        Trend analysis data dictionary.
    """
    if not context.trends:
        return {"error": "No trend data available", "status": 404}

    result = context.trends.to_dict()

    # Apply function filter
    function_filter = query.get("function", [None])[0]
    if function_filter and function_filter in result["function_trends"]:
        result["function_trends"] = {
            function_filter: result["function_trends"][function_filter]
        }

    # Apply direction filter
    direction_filter = query.get("direction", [None])[0]
    if direction_filter:
        result["improving_controls"] = [
            c for c in result["improving_controls"]
            if c["direction"] == direction_filter
        ]
        result["regressing_controls"] = [
            c for c in result["regressing_controls"]
            if c["direction"] == direction_filter
        ]

    return result


def handle_api_functions(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/functions endpoint.

    Returns function-level maturity scores.

    Args:
        context: Route context with dashboard data.
        query: Query parameters (unused).

    Returns:
        Function scores dictionary.
    """
    if not context.maturity:
        return {"error": "No maturity data available", "status": 404}

    functions = []
    for func_id, score in context.maturity.by_function.items():
        func_data = score.to_dict()
        func_data["display_name"] = FUNCTION_DISPLAY_NAMES.get(func_id, func_id)

        # Get category count
        categories = [
            c for c in context.maturity.by_category.keys()
            if c.startswith(func_id + ".")
        ]
        func_data["category_count"] = len(categories)

        # Get subcategory count
        subcategories = [
            s for s in context.maturity.by_subcategory.keys()
            if s.startswith(func_id + ".")
        ]
        func_data["subcategory_count"] = len(subcategories)

        functions.append(func_data)

    # Sort by function ID
    functions.sort(key=lambda f: f["entity_id"])

    return {
        "functions": functions,
        "overall": context.maturity.overall.to_dict(),
    }


def handle_api_categories(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/categories endpoint.

    Returns category-level maturity scores.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - function: Filter by function ID.

    Returns:
        Category scores dictionary.
    """
    if not context.maturity:
        return {"error": "No maturity data available", "status": 404}

    function_filter = query.get("function", [None])[0]

    categories = []
    for cat_id, score in context.maturity.by_category.items():
        # Apply function filter
        if function_filter and not cat_id.startswith(function_filter + "."):
            continue

        cat_data = score.to_dict()

        # Get subcategory count
        subcategories = [
            s for s in context.maturity.by_subcategory.keys()
            if s.startswith(cat_id)
        ]
        cat_data["subcategory_count"] = len(subcategories)

        categories.append(cat_data)

    # Sort by category ID
    categories.sort(key=lambda c: c["entity_id"])

    return {"categories": categories}


def handle_api_subcategories(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/subcategories endpoint.

    Returns subcategory-level maturity scores.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - function: Filter by function ID.
            - category: Filter by category ID.
            - level: Filter by minimum level.

    Returns:
        Subcategory scores dictionary.
    """
    if not context.maturity:
        return {"error": "No maturity data available", "status": 404}

    function_filter = query.get("function", [None])[0]
    category_filter = query.get("category", [None])[0]
    level_filter = query.get("level", [None])[0]

    subcategories = []
    for sub_id, score in context.maturity.by_subcategory.items():
        # Apply function filter
        if function_filter and not sub_id.startswith(function_filter + "."):
            continue

        # Apply category filter
        if category_filter and not sub_id.startswith(category_filter):
            continue

        # Apply level filter
        if level_filter:
            try:
                if score.level < int(level_filter):
                    continue
            except ValueError:
                pass

        subcategories.append(score.to_dict())

    # Sort by subcategory ID
    subcategories.sort(key=lambda s: s["entity_id"])

    return {"subcategories": subcategories}


def handle_api_health(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/health endpoint.

    Returns server health status.

    Args:
        context: Route context with dashboard data.
        query: Query parameters (unused).

    Returns:
        Health status dictionary.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "data_status": {
            "has_maturity_data": context.maturity is not None,
            "has_gap_data": context.gaps is not None,
            "has_trend_data": context.trends is not None,
            "has_evidence_store": context.evidence_store is not None,
        },
        "last_updated": (
            context.last_updated.isoformat() if context.last_updated else None
        ),
    }


def handle_api_controls(context: RouteContext, query: dict[str, list[str]]) -> dict[str, Any]:
    """
    Handle /api/controls endpoint.

    Returns NIST control hierarchy.

    Args:
        context: Route context with dashboard data.
        query: Query parameters (unused).

    Returns:
        Control hierarchy dictionary.
    """
    functions: list[dict[str, Any]] = []
    for func in get_all_functions():
        func_data: dict[str, Any] = {
            "id": func.id,
            "name": func.name,
            "description": func.description,
            "categories": [],
        }

        for cat in get_all_categories():
            if not cat.id.startswith(func.id + "."):
                continue

            cat_data: dict[str, Any] = {
                "id": cat.id,
                "name": cat.name,
                "description": cat.description,
                "subcategories": [],
            }

            for sub in get_all_subcategories():
                if not sub.id.startswith(cat.id):
                    continue

                sub_data = {
                    "id": sub.id,
                    "name": sub.name,
                    "description": sub.description,
                }
                cat_data["subcategories"].append(sub_data)

            func_data["categories"].append(cat_data)

        functions.append(func_data)

    return {"functions": functions}


def handle_api_control_detail(
    context: RouteContext, query: dict[str, list[str]]
) -> dict[str, Any]:
    """
    Handle /api/control endpoint.

    Returns detailed information about a specific NIST control including
    its description, maturity criteria, current score, and linked evidence.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - id: Control ID (required, e.g., "PR.AC-01").

    Returns:
        Control detail dictionary with evidence.
    """
    control_id = query.get("id", [None])[0]

    if not control_id:
        return {"error": "Control ID required", "status": 400}

    # Look up the control definition
    from nisify.nist import get_subcategory, get_category

    subcategory = get_subcategory(control_id)
    if not subcategory:
        return {"error": f"Control '{control_id}' not found", "status": 404}

    # Get category info
    category = get_category(subcategory.category_id)

    # Build response
    result: dict[str, Any] = {
        "control_id": control_id,
        "name": subcategory.name,
        "description": subcategory.description,
        "category_id": subcategory.category_id,
        "category_name": category.name if category else "",
        "function_id": subcategory.category_id.split(".")[0],
        "evidence_types": subcategory.evidence_types,
        "api_collectible": subcategory.api_collectible,
        "maturity_criteria": subcategory.maturity_criteria.to_dict(),
    }

    # Get current maturity score if available
    if context.maturity and control_id in context.maturity.by_subcategory:
        score_data = context.maturity.by_subcategory[control_id]
        result["maturity"] = {
            "score": round(score_data.score, 2),
            "level": score_data.level,
            "evidence_count": score_data.evidence_count,
            "confidence": round(score_data.confidence, 2),
        }
    else:
        result["maturity"] = {
            "score": 0,
            "level": 0,
            "evidence_count": 0,
            "confidence": 0,
        }

    # Get linked evidence if evidence store is available
    result["evidence"] = []
    store = context.evidence_store
    if store and hasattr(store, "get_evidence_for_control"):
        try:
            evidence_items = store.get_evidence_for_control(control_id)
            for ev in evidence_items[:20]:  # Limit to 20 most recent
                ev_dict = {
                    "id": ev.id,
                    "platform": ev.platform,
                    "evidence_type": ev.evidence_type,
                    "collected_at": ev.collected_at.isoformat(),
                    "file_hash": ev.file_hash[:16] + "...",
                }
                # Include metadata summary
                if ev.metadata:
                    ev_dict["metadata"] = ev.metadata
                result["evidence"].append(ev_dict)
        except Exception as e:
            logger.warning(f"Failed to get evidence for control {control_id}: {e}")

    # Get mappings for confidence info
    if store and hasattr(store, "get_mappings_for_control"):
        try:
            mappings = store.get_mappings_for_control(control_id)
            result["mappings"] = [
                {
                    "evidence_id": m.evidence_id,
                    "confidence": round(m.mapping_confidence, 2),
                    "reason": m.mapping_reason,
                }
                for m in mappings[:20]
            ]
        except Exception as e:
            logger.warning(f"Failed to get mappings for control {control_id}: {e}")

    return result


def handle_api_evidence_detail(
    context: RouteContext, query: dict[str, list[str]]
) -> dict[str, Any]:
    """
    Handle /api/evidence/detail endpoint.

    Returns detailed information about a specific evidence item including
    its raw data content.

    Args:
        context: Route context with dashboard data.
        query: Query parameters.
            - id: Evidence ID (required).

    Returns:
        Evidence detail dictionary with raw data.
    """
    evidence_id = query.get("id", [None])[0]

    if not evidence_id:
        return {"error": "Evidence ID required", "status": 400}

    store = context.evidence_store
    if not store:
        return {"error": "No evidence store configured", "status": 404}

    try:
        # Get the evidence metadata
        evidence = store.get_evidence_by_id(evidence_id)
        if not evidence:
            return {"error": f"Evidence '{evidence_id}' not found", "status": 404}

        result = {
            "id": evidence.id,
            "platform": evidence.platform,
            "evidence_type": evidence.evidence_type,
            "collected_at": evidence.collected_at.isoformat(),
            "file_path": evidence.file_path,
            "file_hash": evidence.file_hash,
            "metadata": evidence.metadata,
            "item_count": evidence.item_count,
        }

        # Try to load the raw evidence data
        if hasattr(store, "_read_evidence_file"):
            try:
                raw_data = store._read_evidence_file(evidence.file_path)
                result["raw_data"] = raw_data
            except Exception as e:
                result["raw_data_error"] = str(e)

        # Get controls this evidence maps to
        if hasattr(store, "get_mappings_for_evidence"):
            try:
                mappings = store.get_mappings_for_evidence(evidence_id)
                result["mapped_controls"] = [
                    {
                        "control_id": m.control_id,
                        "confidence": round(m.mapping_confidence, 2),
                        "reason": m.mapping_reason,
                    }
                    for m in mappings
                ]
            except Exception:
                pass

        return result

    except Exception as e:
        logger.error(f"Failed to get evidence detail: {e}")
        return {"error": str(e), "status": 500}


# Route registry
API_ROUTES: dict[str, RouteHandler] = {
    "/api/summary": handle_api_summary,
    "/api/maturity": handle_api_maturity,
    "/api/gaps": handle_api_gaps,
    "/api/evidence": handle_api_evidence,
    "/api/evidence/detail": handle_api_evidence_detail,
    "/api/trends": handle_api_trends,
    "/api/functions": handle_api_functions,
    "/api/categories": handle_api_categories,
    "/api/subcategories": handle_api_subcategories,
    "/api/health": handle_api_health,
    "/api/controls": handle_api_controls,
    "/api/control": handle_api_control_detail,
}


def get_route_handler(path: str) -> RouteHandler | None:
    """
    Get the route handler for a path.

    Args:
        path: URL path.

    Returns:
        Route handler function or None if not found.
    """
    return API_ROUTES.get(path)


def list_routes() -> list[str]:
    """
    List all registered API routes.

    Returns:
        List of route paths.
    """
    return list(API_ROUTES.keys())
