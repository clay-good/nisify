"""
Gap analysis generator for NIST CSF 2.0 compliance.

This module identifies controls without sufficient evidence and provides
actionable recommendations for closing gaps. All analysis is deterministic
and fully auditable.

Gap Types:
    - no_evidence: Control has no mapped evidence
    - stale_evidence: Evidence exists but is older than freshness threshold
    - partial_evidence: Some but not all required evidence types present
    - low_maturity: Evidence exists but maturity level is below target

Priority Levels:
    - critical: Level 0 in Protect or Detect functions
    - high: Level 0-1 in any function, or critical function gaps
    - medium: Level 2 with stale evidence
    - low: Minor gaps in non-critical controls
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from nisify.nist.csf2_controls import (
    get_all_functions,
    get_subcategory,
)
from nisify.nist.maturity_calculator import MaturityBreakdown, MaturityScore

logger = logging.getLogger(__name__)


class GapType(str, Enum):
    """Type of compliance gap."""

    NO_EVIDENCE = "no_evidence"
    STALE_EVIDENCE = "stale_evidence"
    PARTIAL_EVIDENCE = "partial_evidence"
    LOW_MATURITY = "low_maturity"


class Priority(str, Enum):
    """Gap priority level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Effort(str, Enum):
    """Effort required to close gap."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Impact(str, Enum):
    """Impact of closing gap."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Recommendation:
    """
    Actionable recommendation for closing a gap.

    Attributes:
        gap_id: Reference to the gap this addresses.
        action: What action to take.
        platform: Which platform to configure (if applicable).
        effort: Effort level required.
        impact: Impact of completing this action.
        details: Detailed instructions.
    """

    gap_id: str
    action: str
    platform: str | None
    effort: Effort
    impact: Impact
    details: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "gap_id": self.gap_id,
            "action": self.action,
            "platform": self.platform,
            "effort": self.effort.value,
            "impact": self.impact.value,
            "details": self.details,
        }


@dataclass
class Gap:
    """
    A compliance gap in a NIST control.

    Attributes:
        control_id: NIST subcategory ID.
        control_name: Human-readable control name.
        function_id: Parent function ID.
        category_id: Parent category ID.
        current_maturity: Current maturity level (0-4).
        target_maturity: Target maturity level (default 3).
        gap_type: Type of gap identified.
        priority: Priority level for addressing.
        explanation: Human-readable explanation of the gap.
        recommendations: List of actionable recommendations.
        evidence_age_days: Age of most recent evidence (if any).
        missing_evidence_types: Evidence types that are missing.
    """

    control_id: str
    control_name: str
    function_id: str
    category_id: str
    current_maturity: int
    target_maturity: int
    gap_type: GapType
    priority: Priority
    explanation: str
    recommendations: list[Recommendation] = field(default_factory=list)
    evidence_age_days: int | None = None
    missing_evidence_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "function_id": self.function_id,
            "category_id": self.category_id,
            "current_maturity": self.current_maturity,
            "target_maturity": self.target_maturity,
            "gap_type": self.gap_type.value,
            "priority": self.priority.value,
            "explanation": self.explanation,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "evidence_age_days": self.evidence_age_days,
            "missing_evidence_types": self.missing_evidence_types,
        }


@dataclass
class GapAnalysis:
    """
    Complete gap analysis results.

    Attributes:
        timestamp: When the analysis was performed.
        total_controls: Total number of NIST subcategories.
        controls_with_gaps: Number of controls with identified gaps.
        gap_percentage: Percentage of controls with gaps.
        gaps_by_priority: Count of gaps by priority level.
        gaps_by_function: Gaps organized by NIST function.
        gaps_by_type: Count of gaps by type.
        all_gaps: Complete list of all gaps.
        top_recommendations: Prioritized list of top recommendations.
        quick_wins: Gaps that are easy to close.
        critical_gaps: Gaps requiring immediate attention.
    """

    timestamp: datetime
    total_controls: int
    controls_with_gaps: int
    gap_percentage: float
    gaps_by_priority: dict[str, int]
    gaps_by_function: dict[str, list[Gap]]
    gaps_by_type: dict[str, int]
    all_gaps: list[Gap]
    top_recommendations: list[Recommendation]
    quick_wins: list[Gap]
    critical_gaps: list[Gap]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_controls": self.total_controls,
            "controls_with_gaps": self.controls_with_gaps,
            "gap_percentage": round(self.gap_percentage, 2),
            "gaps_by_priority": self.gaps_by_priority,
            "gaps_by_function": {
                k: [g.to_dict() for g in v] for k, v in self.gaps_by_function.items()
            },
            "gaps_by_type": self.gaps_by_type,
            "all_gaps": [g.to_dict() for g in self.all_gaps],
            "top_recommendations": [r.to_dict() for r in self.top_recommendations],
            "quick_wins": [g.to_dict() for g in self.quick_wins],
            "critical_gaps": [g.to_dict() for g in self.critical_gaps],
        }


@dataclass
class GapAnalyzerConfig:
    """
    Configuration for gap analysis.

    Attributes:
        target_maturity: Default target maturity level.
        critical_functions: Functions considered critical (gaps are higher priority).
        stale_threshold_days: Days before evidence is considered stale.
        quick_win_effort_threshold: Maximum effort level for quick wins.
    """

    target_maturity: int = 3
    critical_functions: list[str] = field(
        default_factory=lambda: ["PR", "DE"]  # Protect and Detect
    )
    stale_threshold_days: int = 30
    quick_win_effort_threshold: Effort = Effort.LOW


# Built-in recommendations for common gaps
RECOMMENDATION_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    # Identity and Access Management
    "mfa_status": [
        {
            "action": "Enable MFA enforcement for all users",
            "platform": "okta",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Configure Okta sign-on policies to require MFA for all users. "
                "Enable the Okta collector to gather MFA enrollment evidence. "
                "Verify MFA is enforced for privileged accounts first."
            ),
        },
        {
            "action": "Enable MFA for AWS IAM users",
            "platform": "aws",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Enable virtual MFA or hardware MFA for all IAM users. "
                "Create IAM policy requiring MFA for console access. "
                "The AWS collector will automatically gather MFA status."
            ),
        },
    ],
    "user_inventory": [
        {
            "action": "Configure identity provider collector",
            "platform": "okta",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "Enable the Okta collector with okta.users.read permission. "
                "This provides complete user inventory with status and attributes. "
                "Run collection to populate user inventory evidence."
            ),
        },
        {
            "action": "Enable Google Workspace directory sync",
            "platform": "google",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Configure Google Workspace collector with Admin SDK Directory API. "
                "Requires service account with domain-wide delegation. "
                "Provides user inventory with 2SV status."
            ),
        },
    ],
    "access_logs": [
        {
            "action": "Enable audit logging",
            "platform": "aws",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "Ensure CloudTrail is enabled in all regions. "
                "Enable multi-region trail with log file validation. "
                "The AWS collector will gather CloudTrail configuration as evidence."
            ),
        },
        {
            "action": "Configure Okta system log collection",
            "platform": "okta",
            "effort": Effort.LOW,
            "impact": Impact.MEDIUM,
            "details": (
                "Enable the Okta collector with okta.logs.read permission. "
                "System logs capture authentication and admin events. "
                "Default collection covers last 30 days of activity."
            ),
        },
    ],
    "security_findings": [
        {
            "action": "Enable AWS Security Hub",
            "platform": "aws",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Enable Security Hub in all active regions. "
                "Enable AWS Foundational Security Best Practices standard. "
                "The AWS collector will gather all findings as evidence."
            ),
        },
        {
            "action": "Configure Datadog security monitoring",
            "platform": "datadog",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Enable Datadog Cloud SIEM and configure detection rules. "
                "Enable the Datadog collector to gather security signals. "
                "Review and enable relevant out-of-box detection rules."
            ),
        },
    ],
    "device_inventory": [
        {
            "action": "Configure Jamf Pro collector",
            "platform": "jamf",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "Enable the Jamf collector with read access to Computers. "
                "This provides complete inventory of managed macOS devices. "
                "Includes OS version, last check-in, and management status."
            ),
        },
        {
            "action": "Enable Google Workspace mobile device management",
            "platform": "google",
            "effort": Effort.MEDIUM,
            "impact": Impact.MEDIUM,
            "details": (
                "Configure Google Workspace MDM for mobile devices. "
                "Enable the Google collector to gather device inventory. "
                "Provides visibility into managed mobile endpoints."
            ),
        },
    ],
    "encryption_status": [
        {
            "action": "Enable FileVault monitoring via Jamf",
            "platform": "jamf",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "Enable FileVault inventory collection in Jamf Pro. "
                "The Jamf collector will gather encryption status per device. "
                "Verify recovery key escrow is enabled."
            ),
        },
        {
            "action": "Enable S3 bucket encryption",
            "platform": "aws",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Enable default encryption on all S3 buckets. "
                "Use SSE-S3 or SSE-KMS for encryption at rest. "
                "The AWS collector will verify encryption configuration."
            ),
        },
    ],
    "endpoint_compliance": [
        {
            "action": "Deploy macOS Security Compliance Project baselines",
            "platform": "jamf",
            "effort": Effort.HIGH,
            "impact": Impact.HIGH,
            "details": (
                "Deploy mSCP compliance baselines via Jamf configuration profiles. "
                "Create Extension Attribute to report compliance status. "
                "The Jamf collector will parse mSCP compliance results."
            ),
        },
    ],
    "detection_rules": [
        {
            "action": "Enable Datadog detection rules",
            "platform": "datadog",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Review and enable Datadog out-of-box detection rules. "
                "Configure custom detection rules for organization-specific threats. "
                "The Datadog collector will gather rule configuration as evidence."
            ),
        },
    ],
    "monitoring_coverage": [
        {
            "action": "Configure comprehensive monitoring",
            "platform": "datadog",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Create monitors for critical infrastructure and applications. "
                "Enable APM, infrastructure, and log monitoring. "
                "The Datadog collector will verify monitoring coverage."
            ),
        },
    ],
    "access_policies": [
        {
            "action": "Document and configure access control policies",
            "platform": "aws",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Review and document IAM policies and role definitions. "
                "Implement least privilege access principles. "
                "Enable AWS Config rules to monitor policy compliance."
            ),
        },
        {
            "action": "Configure Snowflake role-based access control",
            "platform": "snowflake",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Define and document Snowflake roles and privileges. "
                "Enable the Snowflake collector to gather role configuration. "
                "Implement role hierarchy aligned with business needs."
            ),
        },
    ],
    "audit_logging": [
        {
            "action": "Enable comprehensive audit logging",
            "platform": "aws",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "Enable CloudTrail with multi-region and management events. "
                "Enable S3 access logging for sensitive buckets. "
                "Configure log retention and integrity validation."
            ),
        },
    ],
    "config_compliance": [
        {
            "action": "Enable AWS Config rules",
            "platform": "aws",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Enable AWS Config in all regions. "
                "Deploy conformance packs for security baselines. "
                "The AWS collector will gather compliance rule results."
            ),
        },
    ],
    "data_protection": [
        {
            "action": "Implement data protection controls",
            "platform": "aws",
            "effort": Effort.HIGH,
            "impact": Impact.HIGH,
            "details": (
                "Enable S3 bucket versioning and encryption. "
                "Configure S3 Object Lock for critical data. "
                "Implement cross-region replication for disaster recovery."
            ),
        },
    ],
    "security_policies": [
        {
            "action": "Document and configure security policies",
            "platform": "okta",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Review and document Okta sign-on and password policies. "
                "Enable the Okta collector to gather policy configuration. "
                "Ensure policies align with organizational security requirements."
            ),
        },
    ],
    "identity_federation": [
        {
            "action": "Configure SSO and federation",
            "platform": "okta",
            "effort": Effort.MEDIUM,
            "impact": Impact.HIGH,
            "details": (
                "Configure Okta as identity provider for all applications. "
                "Enable SCIM provisioning where supported. "
                "Document federation configuration for audit evidence."
            ),
        },
        {
            "action": "Enable Snowflake SSO integration",
            "platform": "snowflake",
            "effort": Effort.MEDIUM,
            "impact": Impact.MEDIUM,
            "details": (
                "Configure Snowflake SAML or OAuth integration with IdP. "
                "Enable the Snowflake collector to verify SSO configuration. "
                "Document federation setup for compliance evidence."
            ),
        },
    ],
    "software_inventory": [
        {
            "action": "Enable application inventory collection",
            "platform": "jamf",
            "effort": Effort.LOW,
            "impact": Impact.MEDIUM,
            "details": (
                "Enable application inventory in Jamf Pro. "
                "The Jamf collector will gather installed applications per device. "
                "Configure prohibited application detection if needed."
            ),
        },
    ],
    "authentication_logs": [
        {
            "action": "Enable authentication logging",
            "platform": "snowflake",
            "effort": Effort.LOW,
            "impact": Impact.MEDIUM,
            "details": (
                "The Snowflake collector queries LOGIN_HISTORY by default. "
                "Ensure ACCOUNT_USAGE views are accessible. "
                "Configure collection schedule for regular evidence gathering."
            ),
        },
    ],
    "data_access_logs": [
        {
            "action": "Enable data access history",
            "platform": "snowflake",
            "effort": Effort.LOW,
            "impact": Impact.HIGH,
            "details": (
                "The Snowflake collector queries ACCESS_HISTORY by default. "
                "Provides evidence of who accessed what data and when. "
                "Ensure warehouse has sufficient credits for queries."
            ),
        },
    ],
}


class GapAnalyzer:
    """
    Analyzer for identifying and prioritizing compliance gaps.

    Analyzes maturity results to identify controls without sufficient
    evidence, prioritizes gaps based on risk and function importance,
    and generates actionable recommendations for closing gaps.

    Example:
        analyzer = GapAnalyzer()

        # Analyze gaps from maturity breakdown
        analysis = analyzer.analyze_gaps(maturity_breakdown)

        # Get critical gaps requiring immediate attention
        critical = analyzer.get_critical_gaps()

        # Get quick wins (low effort, high impact)
        quick_wins = analyzer.get_quick_wins()

        # Get recommendations for a specific gap
        recommendations = analyzer.generate_recommendations(gap)

    Attributes:
        config: GapAnalyzerConfig with analysis settings.
    """

    def __init__(self, config: GapAnalyzerConfig | None = None) -> None:
        """
        Initialize the gap analyzer.

        Args:
            config: GapAnalyzerConfig with analysis settings.
                Defaults to standard settings.
        """
        self.config = config or GapAnalyzerConfig()
        self._last_analysis: GapAnalysis | None = None

    def analyze_gaps(
        self,
        maturity_breakdown: MaturityBreakdown,
        target_maturity: int | None = None,
    ) -> GapAnalysis:
        """
        Perform complete gap analysis on maturity results.

        Args:
            maturity_breakdown: MaturityBreakdown from MaturityCalculator.
            target_maturity: Target maturity level (overrides config).

        Returns:
            GapAnalysis with all identified gaps and recommendations.
        """
        target = target_maturity or self.config.target_maturity
        all_gaps: list[Gap] = []
        gaps_by_function: dict[str, list[Gap]] = {}
        gaps_by_priority: dict[str, int] = {p.value: 0 for p in Priority}
        gaps_by_type: dict[str, int] = {t.value: 0 for t in GapType}

        # Initialize function groupings
        for function in get_all_functions():
            gaps_by_function[function.id] = []

        # Analyze each subcategory
        for control_id, score in maturity_breakdown.by_subcategory.items():
            gap = self._analyze_control(control_id, score, target)
            if gap:
                all_gaps.append(gap)
                gaps_by_function[gap.function_id].append(gap)
                gaps_by_priority[gap.priority.value] += 1
                gaps_by_type[gap.gap_type.value] += 1

        # Sort gaps by priority
        priority_order = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
        }
        all_gaps.sort(key=lambda g: priority_order[g.priority])

        # Generate recommendations for all gaps
        all_recommendations: list[Recommendation] = []
        for gap in all_gaps:
            gap.recommendations = self.generate_recommendations(gap)
            all_recommendations.extend(gap.recommendations)

        # Identify quick wins (low effort gaps)
        quick_wins = [
            g for g in all_gaps
            if any(
                r.effort == Effort.LOW and r.impact in (Impact.HIGH, Impact.MEDIUM)
                for r in g.recommendations
            )
        ]

        # Identify critical gaps
        critical_gaps = [g for g in all_gaps if g.priority == Priority.CRITICAL]

        # Get top recommendations (deduplicated, prioritized)
        top_recommendations = self._prioritize_recommendations(all_recommendations)[:10]

        # Calculate statistics
        total_controls = len(maturity_breakdown.by_subcategory)
        controls_with_gaps = len(all_gaps)
        gap_percentage = (
            (controls_with_gaps / total_controls * 100) if total_controls > 0 else 0.0
        )

        analysis = GapAnalysis(
            timestamp=datetime.now(UTC),
            total_controls=total_controls,
            controls_with_gaps=controls_with_gaps,
            gap_percentage=gap_percentage,
            gaps_by_priority=gaps_by_priority,
            gaps_by_function=gaps_by_function,
            gaps_by_type=gaps_by_type,
            all_gaps=all_gaps,
            top_recommendations=top_recommendations,
            quick_wins=quick_wins,
            critical_gaps=critical_gaps,
        )

        self._last_analysis = analysis
        logger.info(
            "Gap analysis complete: %d gaps identified (%.1f%% of controls)",
            controls_with_gaps,
            gap_percentage,
        )

        return analysis

    def _analyze_control(
        self,
        control_id: str,
        score: MaturityScore,
        target_maturity: int,
    ) -> Gap | None:
        """
        Analyze a single control for gaps.

        Args:
            control_id: NIST subcategory ID.
            score: MaturityScore for this control.
            target_maturity: Target maturity level.

        Returns:
            Gap if one is identified, None otherwise.
        """
        # No gap if at or above target
        if score.level >= target_maturity:
            return None

        subcategory = get_subcategory(control_id)
        if not subcategory:
            return None

        # Determine function and category
        parts = control_id.split(".")
        function_id = parts[0] if parts else ""
        category_id = f"{parts[0]}.{parts[1].split('-')[0]}" if len(parts) > 1 else ""

        # Determine gap type
        gap_type = self._determine_gap_type(score)

        # Determine priority
        priority = self._determine_priority(
            score.level, gap_type, function_id, target_maturity
        )

        # Calculate evidence age
        evidence_age_days = None
        if score.last_evidence_date:
            age = datetime.now(UTC) - score.last_evidence_date
            evidence_age_days = age.days

        # Build explanation
        explanation = self._build_explanation(
            score, subcategory.name, gap_type, target_maturity
        )

        # Identify missing evidence types from control definition
        missing_evidence_types = []
        if subcategory.evidence_types:
            # If we have no evidence, all types are missing
            if score.evidence_count == 0:
                missing_evidence_types = list(subcategory.evidence_types)

        return Gap(
            control_id=control_id,
            control_name=subcategory.name,
            function_id=function_id,
            category_id=category_id,
            current_maturity=score.level,
            target_maturity=target_maturity,
            gap_type=gap_type,
            priority=priority,
            explanation=explanation,
            evidence_age_days=evidence_age_days,
            missing_evidence_types=missing_evidence_types,
        )

    def _determine_gap_type(self, score: MaturityScore) -> GapType:
        """Determine the type of gap based on score characteristics."""
        if score.evidence_count == 0:
            return GapType.NO_EVIDENCE

        # Check for stale evidence
        if score.last_evidence_date:
            age = datetime.now(UTC) - score.last_evidence_date
            if age.days > self.config.stale_threshold_days:
                return GapType.STALE_EVIDENCE

        # Check for partial evidence (confidence < 1.0 suggests incomplete)
        if score.confidence < 0.8:
            return GapType.PARTIAL_EVIDENCE

        # Otherwise it's a maturity gap
        return GapType.LOW_MATURITY

    def _determine_priority(
        self,
        current_level: int,
        gap_type: GapType,
        function_id: str,
        target_maturity: int,
    ) -> Priority:
        """Determine gap priority based on severity and function."""
        is_critical_function = function_id in self.config.critical_functions

        # Level 0 in critical functions is always critical
        if current_level == 0 and is_critical_function:
            return Priority.CRITICAL

        # Level 0 in any function is high priority
        if current_level == 0:
            return Priority.HIGH

        # Level 1 in critical functions is high priority
        if current_level == 1 and is_critical_function:
            return Priority.HIGH

        # Stale evidence in critical functions is high priority
        if gap_type == GapType.STALE_EVIDENCE and is_critical_function:
            return Priority.HIGH

        # Level 1 or stale evidence is medium priority
        if current_level == 1 or gap_type == GapType.STALE_EVIDENCE:
            return Priority.MEDIUM

        # Everything else is low priority
        return Priority.LOW

    def _build_explanation(
        self,
        score: MaturityScore,
        control_name: str,
        gap_type: GapType,
        target_maturity: int,
    ) -> str:
        """Build human-readable explanation of the gap."""
        parts = [f"Control '{control_name}' is at maturity level {score.level}, "]
        parts.append(f"below target level {target_maturity}. ")

        if gap_type == GapType.NO_EVIDENCE:
            parts.append(
                "No evidence has been collected for this control. "
                "This may require configuring a collector or uploading manual evidence."
            )
        elif gap_type == GapType.STALE_EVIDENCE:
            if score.last_evidence_date:
                age = datetime.now(UTC) - score.last_evidence_date
                parts.append(
                    f"Evidence is {age.days} days old and considered stale. "
                    "Run evidence collection to refresh."
                )
        elif gap_type == GapType.PARTIAL_EVIDENCE:
            parts.append(
                "Only partial evidence is available. "
                "Additional evidence types may need to be collected."
            )
        else:
            parts.append(
                "Evidence exists but does not demonstrate sufficient maturity. "
                "Consider strengthening controls or improving documentation."
            )

        return "".join(parts)

    def generate_recommendations(self, gap: Gap) -> list[Recommendation]:
        """
        Generate actionable recommendations for closing a gap.

        Args:
            gap: Gap to generate recommendations for.

        Returns:
            List of Recommendations prioritized by impact and effort.
        """
        recommendations: list[Recommendation] = []

        # Get recommendations based on missing evidence types
        for evidence_type in gap.missing_evidence_types:
            if evidence_type in RECOMMENDATION_TEMPLATES:
                for template in RECOMMENDATION_TEMPLATES[evidence_type]:
                    rec = Recommendation(
                        gap_id=gap.control_id,
                        action=template["action"],
                        platform=template["platform"],
                        effort=template["effort"],
                        impact=template["impact"],
                        details=template["details"],
                    )
                    recommendations.append(rec)

        # If no specific recommendations, provide generic ones
        if not recommendations:
            if gap.gap_type == GapType.NO_EVIDENCE:
                recommendations.append(
                    Recommendation(
                        gap_id=gap.control_id,
                        action="Configure evidence collection for this control",
                        platform=None,
                        effort=Effort.MEDIUM,
                        impact=Impact.HIGH,
                        details=(
                            f"Review control {gap.control_id} requirements and identify "
                            "which platform collectors can provide relevant evidence. "
                            "If no automated collection is possible, prepare manual evidence."
                        ),
                    )
                )
            elif gap.gap_type == GapType.STALE_EVIDENCE:
                recommendations.append(
                    Recommendation(
                        gap_id=gap.control_id,
                        action="Run evidence collection to refresh stale data",
                        platform=None,
                        effort=Effort.LOW,
                        impact=Impact.MEDIUM,
                        details=(
                            "Execute 'nisify collect' to gather fresh evidence. "
                            "Consider increasing collection frequency to prevent staleness."
                        ),
                    )
                )
            elif gap.gap_type == GapType.PARTIAL_EVIDENCE:
                recommendations.append(
                    Recommendation(
                        gap_id=gap.control_id,
                        action="Collect additional evidence types",
                        platform=None,
                        effort=Effort.MEDIUM,
                        impact=Impact.MEDIUM,
                        details=(
                            f"Control {gap.control_id} has partial evidence. "
                            "Review required evidence types and configure additional collectors "
                            "or prepare manual evidence to achieve full coverage."
                        ),
                    )
                )
            else:
                recommendations.append(
                    Recommendation(
                        gap_id=gap.control_id,
                        action="Strengthen control implementation",
                        platform=None,
                        effort=Effort.HIGH,
                        impact=Impact.HIGH,
                        details=(
                            f"Control {gap.control_id} has evidence but low maturity. "
                            "Review control implementation and consider process improvements, "
                            "automation, or enhanced documentation to demonstrate higher maturity."
                        ),
                    )
                )

        # Sort by impact (high first) then by effort (low first)
        impact_order = {Impact.HIGH: 0, Impact.MEDIUM: 1, Impact.LOW: 2}
        effort_order = {Effort.LOW: 0, Effort.MEDIUM: 1, Effort.HIGH: 2}
        recommendations.sort(
            key=lambda r: (impact_order[r.impact], effort_order[r.effort])
        )

        return recommendations

    def _prioritize_recommendations(
        self,
        recommendations: list[Recommendation],
    ) -> list[Recommendation]:
        """Deduplicate and prioritize recommendations."""
        # Deduplicate by action text
        seen_actions: set[str] = set()
        unique_recs: list[Recommendation] = []

        for rec in recommendations:
            if rec.action not in seen_actions:
                seen_actions.add(rec.action)
                unique_recs.append(rec)

        # Sort by impact then effort
        impact_order = {Impact.HIGH: 0, Impact.MEDIUM: 1, Impact.LOW: 2}
        effort_order = {Effort.LOW: 0, Effort.MEDIUM: 1, Effort.HIGH: 2}
        unique_recs.sort(
            key=lambda r: (impact_order[r.impact], effort_order[r.effort])
        )

        return unique_recs

    def get_critical_gaps(self) -> list[Gap]:
        """
        Get gaps requiring immediate attention.

        Returns:
            List of critical priority gaps.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.critical_gaps

    def get_quick_wins(self) -> list[Gap]:
        """
        Get gaps that are easy to close with high impact.

        Returns:
            List of quick win gaps.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.quick_wins

    def get_gaps_by_function(self, function_id: str) -> list[Gap]:
        """
        Get all gaps for a specific NIST function.

        Args:
            function_id: NIST function ID (e.g., "PR").

        Returns:
            List of gaps in that function.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.gaps_by_function.get(function_id, [])

    def get_gaps_by_priority(self, priority: Priority) -> list[Gap]:
        """
        Get all gaps with a specific priority.

        Args:
            priority: Priority level to filter by.

        Returns:
            List of gaps with that priority.
        """
        if not self._last_analysis:
            return []
        return [g for g in self._last_analysis.all_gaps if g.priority == priority]
