"""
Analysis components for gap identification and trend tracking.

This module identifies controls without sufficient evidence and provides
actionable recommendations for closing gaps. It also tracks compliance
posture changes over time.

Gap Analysis:
    The GapAnalyzer class identifies controls below target maturity,
    prioritizes gaps based on function criticality and effort required,
    and generates actionable recommendations for improvement.

Trend Tracking:
    The TrendTracker class analyzes historical maturity snapshots to
    identify improvements, regressions, and patterns over time. Provides
    data formatted for dashboard visualizations.

Example:
    from nisify.analysis import GapAnalyzer, TrendTracker

    # Analyze gaps from maturity breakdown
    analyzer = GapAnalyzer()
    gap_analysis = analyzer.analyze_gaps(maturity_breakdown)
    critical_gaps = analyzer.get_critical_gaps()
    quick_wins = analyzer.get_quick_wins()

    # Track trends over time
    tracker = TrendTracker()
    trends = tracker.calculate_trends(snapshots, days=90)
    improving = tracker.get_improving_controls()
"""

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

__all__ = [
    # Gap Analyzer
    "GapAnalyzer",
    "GapAnalyzerConfig",
    "Gap",
    "GapAnalysis",
    "GapType",
    "Priority",
    "Recommendation",
    "Effort",
    "Impact",
    # Trend Tracker
    "TrendTracker",
    "TrendTrackerConfig",
    "TrendAnalysis",
    "TrendItem",
    "TrendPoint",
    "TrendDirection",
]
