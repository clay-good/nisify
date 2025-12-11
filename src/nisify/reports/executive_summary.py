"""
Executive summary generation for compliance reports.

This module generates human-readable summaries of compliance posture
suitable for executives, board members, and stakeholders who need
high-level insights without technical details.

Output Formats:
    - Plain text summary (for reports)
    - Email body (suitable for distribution)
    - Markdown (for documentation)

All summaries use professional, clear language without jargon.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from nisify.analysis.gap_analyzer import GapAnalysis
from nisify.analysis.trend_tracker import TrendAnalysis, TrendDirection
from nisify.nist.maturity_calculator import MaturityBreakdown

logger = logging.getLogger(__name__)


# Maturity level descriptions for non-technical audiences
MATURITY_DESCRIPTIONS = {
    0: "Not Addressed - No evidence of control implementation",
    1: "Initial - Ad-hoc processes with informal documentation",
    2: "Developing - Documented processes with some automation",
    3: "Defined - Consistent, automated controls with measurement",
    4: "Optimized - Continuous improvement with advanced automation",
}

# Function descriptions for summaries
FUNCTION_DESCRIPTIONS = {
    "GV": "Governance - Organizational policies and risk management",
    "ID": "Identify - Asset management and risk assessment",
    "PR": "Protect - Access control and data security",
    "DE": "Detect - Security monitoring and event detection",
    "RS": "Respond - Incident response and mitigation",
    "RC": "Recover - Recovery planning and improvements",
}


@dataclass
class SummaryConfig:
    """
    Configuration for summary generation.

    Attributes:
        organization: Organization name.
        include_recommendations: Whether to include top recommendations.
        max_recommendations: Maximum recommendations to include.
        include_trends: Whether to include trend information.
        report_date: Date for the report (defaults to now).
    """

    organization: str = "Organization"
    include_recommendations: bool = True
    max_recommendations: int = 5
    include_trends: bool = True
    report_date: datetime | None = None


class ExecutiveSummaryGenerator:
    """
    Generator for executive-level compliance summaries.

    Creates professional, clear summaries suitable for board presentations,
    executive updates, and stakeholder communications. Uses plain language
    and focuses on business impact rather than technical details.

    Example:
        generator = ExecutiveSummaryGenerator(config)

        # Generate text summary
        summary = generator.generate_summary(maturity, gaps)

        # Generate email body
        email = generator.generate_email_body(maturity, gaps, trends)

        # Generate markdown
        markdown = generator.generate_markdown(maturity, gaps)

    Attributes:
        config: SummaryConfig with generation settings.
    """

    def __init__(self, config: SummaryConfig | None = None) -> None:
        """
        Initialize the summary generator.

        Args:
            config: SummaryConfig with generation settings.
        """
        self.config = config or SummaryConfig()

    def generate_summary(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None = None,
    ) -> str:
        """
        Generate a text-based executive summary.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            trends: Optional TrendAnalysis for historical context.

        Returns:
            Multi-paragraph text summary.
        """
        report_date = self.config.report_date or datetime.now(UTC)
        date_str = report_date.strftime("%B %d, %Y")

        sections = []

        # Header
        sections.append("NIST CSF 2.0 COMPLIANCE SUMMARY")
        sections.append(f"{self.config.organization}")
        sections.append(f"Report Date: {date_str}")
        sections.append("")

        # Overview paragraph
        overview = self._generate_overview(maturity, gaps)
        sections.append("OVERVIEW")
        sections.append("-" * 40)
        sections.append(overview)
        sections.append("")

        # Maturity scores
        scores_section = self._generate_scores_section(maturity)
        sections.append("MATURITY SCORES BY FUNCTION")
        sections.append("-" * 40)
        sections.append(scores_section)
        sections.append("")

        # Key findings
        findings = self._generate_key_findings(maturity, gaps)
        sections.append("KEY FINDINGS")
        sections.append("-" * 40)
        for i, finding in enumerate(findings, 1):
            sections.append(f"{i}. {finding}")
        sections.append("")

        # Trend information
        if self.config.include_trends and trends:
            trend_section = self._generate_trend_section(trends)
            sections.append("TREND ANALYSIS")
            sections.append("-" * 40)
            sections.append(trend_section)
            sections.append("")

        # Recommendations
        if self.config.include_recommendations:
            recommendations = self._generate_recommendations(gaps)
            sections.append("RECOMMENDED ACTIONS")
            sections.append("-" * 40)
            for i, rec in enumerate(recommendations[: self.config.max_recommendations], 1):
                sections.append(f"{i}. {rec}")
            sections.append("")

        return "\n".join(sections)

    def generate_email_body(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None = None,
    ) -> str:
        """
        Generate an email-suitable summary.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            trends: Optional TrendAnalysis for historical context.

        Returns:
            Email body text.
        """
        report_date = self.config.report_date or datetime.now(UTC)
        date_str = report_date.strftime("%B %d, %Y")

        lines = []

        # Subject line suggestion
        overall_level = maturity.overall.level
        lines.append(f"Subject: NIST CSF 2.0 Compliance Update - Level {overall_level} ({date_str})")
        lines.append("")

        # Greeting
        lines.append("Team,")
        lines.append("")

        # Opening paragraph
        overview = self._generate_overview(maturity, gaps)
        lines.append(overview)
        lines.append("")

        # Quick scores
        lines.append("Current Maturity by Function:")
        for func_id, func_score in maturity.by_function.items():
            func_name = FUNCTION_DESCRIPTIONS.get(func_id, func_id).split(" - ")[0]
            lines.append(f"  - {func_name}: Level {func_score.level} ({func_score.score:.1f}/4.0)")
        lines.append("")

        # Top priorities
        if gaps.critical_gaps:
            lines.append(f"Priority Items ({len(gaps.critical_gaps)} critical gaps identified):")
            for gap in gaps.critical_gaps[:3]:
                lines.append(f"  - {gap.control_id}: {gap.control_name}")
            lines.append("")

        # Trend note
        if trends and trends.overall_trend.direction != TrendDirection.INSUFFICIENT_DATA:
            direction = trends.overall_trend.direction.value.capitalize()
            delta = trends.overall_trend.score_delta
            if delta:
                delta_str = f"+{delta:.2f}" if delta > 0 else f"{delta:.2f}"
                lines.append(f"Trend: {direction} ({delta_str} over {trends.period_days} days)")
            else:
                lines.append(f"Trend: {direction}")
            lines.append("")

        # Closing
        lines.append("For detailed analysis, please review the full compliance report.")
        lines.append("")
        lines.append("Best regards,")
        lines.append("Security & Compliance Team")

        return "\n".join(lines)

    def generate_markdown(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None = None,
    ) -> str:
        """
        Generate a markdown-formatted summary.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            trends: Optional TrendAnalysis for historical context.

        Returns:
            Markdown-formatted summary.
        """
        report_date = self.config.report_date or datetime.now(UTC)
        date_str = report_date.strftime("%B %d, %Y")

        lines = []

        # Title
        lines.append("# NIST CSF 2.0 Compliance Summary")
        lines.append(f"**{self.config.organization}** | {date_str}")
        lines.append("")

        # Overview
        lines.append("## Overview")
        lines.append("")
        overview = self._generate_overview(maturity, gaps)
        lines.append(overview)
        lines.append("")

        # Maturity table
        lines.append("## Maturity Scores")
        lines.append("")
        lines.append("| Function | Level | Score | Description |")
        lines.append("|----------|-------|-------|-------------|")
        for func_id, func_score in maturity.by_function.items():
            func_desc = FUNCTION_DESCRIPTIONS.get(func_id, func_id)
            func_name = func_desc.split(" - ")[0]
            level_desc = MATURITY_DESCRIPTIONS.get(func_score.level, "").split(" - ")[0]
            lines.append(
                f"| {func_name} | {func_score.level} | {func_score.score:.2f} | {level_desc} |"
            )
        lines.append(
            f"| **Overall** | **{maturity.overall.level}** | "
            f"**{maturity.overall.score:.2f}** | |"
        )
        lines.append("")

        # Key findings
        lines.append("## Key Findings")
        lines.append("")
        findings = self._generate_key_findings(maturity, gaps)
        for finding in findings:
            lines.append(f"- {finding}")
        lines.append("")

        # Gap summary
        if gaps.controls_with_gaps > 0:
            lines.append("## Gap Summary")
            lines.append("")
            lines.append(f"- **Total Gaps:** {gaps.controls_with_gaps} controls ({gaps.gap_percentage:.1f}%)")
            lines.append(f"- **Critical:** {gaps.gaps_by_priority.get('critical', 0)}")
            lines.append(f"- **High:** {gaps.gaps_by_priority.get('high', 0)}")
            lines.append(f"- **Medium:** {gaps.gaps_by_priority.get('medium', 0)}")
            lines.append(f"- **Low:** {gaps.gaps_by_priority.get('low', 0)}")
            lines.append("")

        # Trends
        if self.config.include_trends and trends:
            lines.append("## Trends")
            lines.append("")
            trend_section = self._generate_trend_section(trends)
            lines.append(trend_section)
            lines.append("")

        # Recommendations
        if self.config.include_recommendations:
            lines.append("## Recommended Actions")
            lines.append("")
            recommendations = self._generate_recommendations(gaps)
            for i, rec in enumerate(recommendations[: self.config.max_recommendations], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    def _generate_overview(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
    ) -> str:
        """Generate overview paragraph."""
        overall = maturity.overall

        # Determine overall posture description
        if overall.level >= 3:
            posture = "demonstrates strong compliance posture"
        elif overall.level >= 2:
            posture = "shows developing compliance capabilities"
        elif overall.level >= 1:
            posture = "has foundational compliance measures in place"
        else:
            posture = "requires significant compliance improvements"

        overview = (
            f"{self.config.organization} currently {posture} with an overall "
            f"NIST CSF 2.0 maturity level of {overall.level} ({overall.score:.2f}/4.0). "
            f"This assessment is based on {overall.evidence_count} evidence items "
            f"collected from configured platforms. "
        )

        if gaps.controls_with_gaps > 0:
            overview += (
                f"Analysis identified {gaps.controls_with_gaps} controls "
                f"({gaps.gap_percentage:.1f}%) requiring attention, "
                f"including {gaps.gaps_by_priority.get('critical', 0)} critical gaps."
            )
        else:
            overview += "No significant gaps were identified in the current assessment."

        return overview

    def _generate_scores_section(self, maturity: MaturityBreakdown) -> str:
        """Generate scores section."""
        lines = []
        for func_id, func_score in maturity.by_function.items():
            func_desc = FUNCTION_DESCRIPTIONS.get(func_id, func_id)
            level_desc = MATURITY_DESCRIPTIONS.get(func_score.level, "").split(" - ")[0]
            lines.append(
                f"{func_desc}: Level {func_score.level} ({func_score.score:.2f}/4.0) - {level_desc}"
            )
        lines.append("")
        lines.append(
            f"Overall Maturity: Level {maturity.overall.level} "
            f"({maturity.overall.score:.2f}/4.0)"
        )
        return "\n".join(lines)

    def _generate_key_findings(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
    ) -> list[str]:
        """Generate list of key findings."""
        findings = []

        # Strongest function
        best_func = max(
            maturity.by_function.items(),
            key=lambda x: x[1].score,
        )
        best_name = FUNCTION_DESCRIPTIONS.get(best_func[0], best_func[0]).split(" - ")[0]
        findings.append(
            f"Strongest area: {best_name} at Level {best_func[1].level} "
            f"({best_func[1].score:.2f}/4.0)"
        )

        # Weakest function
        worst_func = min(
            maturity.by_function.items(),
            key=lambda x: x[1].score,
        )
        worst_name = FUNCTION_DESCRIPTIONS.get(worst_func[0], worst_func[0]).split(" - ")[0]
        findings.append(
            f"Area needing attention: {worst_name} at Level {worst_func[1].level} "
            f"({worst_func[1].score:.2f}/4.0)"
        )

        # Evidence coverage
        stats = maturity.statistics
        if "subcategories_with_evidence" in stats:
            with_evidence = stats["subcategories_with_evidence"]
            total = stats.get("total_subcategories", 106)
            coverage = with_evidence / total * 100 if total > 0 else 0
            findings.append(
                f"Evidence coverage: {with_evidence}/{total} controls ({coverage:.0f}%)"
            )

        # Critical gaps
        critical_count = gaps.gaps_by_priority.get("critical", 0)
        if critical_count > 0:
            findings.append(
                f"{critical_count} critical gaps require immediate attention"
            )
        else:
            findings.append("No critical gaps identified")

        # Quick wins
        if gaps.quick_wins:
            findings.append(
                f"{len(gaps.quick_wins)} quick wins identified for rapid improvement"
            )

        return findings

    def _generate_trend_section(self, trends: TrendAnalysis) -> str:
        """Generate trend analysis section."""
        overall = trends.overall_trend

        if overall.direction == TrendDirection.INSUFFICIENT_DATA:
            return "Insufficient historical data for trend analysis. Continue collecting evidence to enable trend tracking."

        direction_text = {
            TrendDirection.IMPROVING: "improving",
            TrendDirection.REGRESSING: "declining",
            TrendDirection.STABLE: "stable",
            TrendDirection.VOLATILE: "fluctuating",
        }

        direction = direction_text.get(overall.direction, "unknown")
        delta_str = ""
        if overall.score_delta:
            sign = "+" if overall.score_delta > 0 else ""
            delta_str = f" ({sign}{overall.score_delta:.2f})"

        lines = [
            f"Over the past {trends.period_days} days, overall compliance posture "
            f"has been {direction}{delta_str}."
        ]

        # Add statistics
        stats = trends.statistics
        improving = stats.get("improving_count", 0)
        regressing = stats.get("regressing_count", 0)

        if improving > 0:
            lines.append(f"{improving} controls showed improvement.")
        if regressing > 0:
            lines.append(f"{regressing} controls showed regression and may need attention.")

        return " ".join(lines)

    def _generate_recommendations(self, gaps: GapAnalysis) -> list[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Start with critical gaps
        for gap in gaps.critical_gaps[:2]:
            recommendations.append(
                f"Address critical gap in {gap.control_id} ({gap.control_name}): "
                f"{gap.recommendations[0].action if gap.recommendations else 'Review and implement control'}"
            )

        # Add quick wins
        for gap in gaps.quick_wins[:2]:
            if len(recommendations) >= self.config.max_recommendations:
                break
            if gap not in gaps.critical_gaps:
                recommendations.append(
                    f"Quick win: {gap.recommendations[0].action if gap.recommendations else gap.control_name} "
                    f"(low effort, high impact)"
                )

        # Add from top recommendations
        for rec in gaps.top_recommendations:
            if len(recommendations) >= self.config.max_recommendations:
                break
            rec_text = f"{rec.action}"
            if rec_text not in [r.split(":")[0] for r in recommendations]:
                recommendations.append(rec_text)

        # Generic if no specific recommendations
        if not recommendations:
            recommendations = [
                "Enable evidence collection for uncovered controls",
                "Review and refresh stale evidence",
                "Document processes for controls requiring manual evidence",
            ]

        return recommendations

    def get_posture_rating(self, maturity: MaturityBreakdown) -> str:
        """
        Get a simple posture rating for quick reference.

        Args:
            maturity: MaturityBreakdown from calculator.

        Returns:
            Rating string (e.g., "Strong", "Developing", "Needs Improvement").
        """
        level = maturity.overall.level
        if level >= 4:
            return "Excellent"
        elif level >= 3:
            return "Strong"
        elif level >= 2:
            return "Developing"
        elif level >= 1:
            return "Foundational"
        else:
            return "Needs Improvement"
