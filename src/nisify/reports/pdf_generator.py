"""
PDF report generation for compliance documentation.

This module generates professional, board-ready PDF reports suitable
for executive presentations, auditor review, and compliance documentation.

Report Structure:
    - Cover page with organization name and date
    - Executive summary (1 page)
    - Maturity detail by function
    - Gap analysis with recommendations
    - Evidence appendix

Design Requirements:
    - Monochrome color scheme (black, white, grays)
    - Clean, professional typography
    - No emojis or decorative elements
    - Charts in grayscale

Requires weasyprint optional dependency for PDF generation.
Falls back to HTML-only output if weasyprint is not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nisify.analysis.gap_analyzer import GapAnalysis
from nisify.analysis.trend_tracker import TrendAnalysis
from nisify.nist.maturity_calculator import MaturityBreakdown
from nisify.reports.executive_summary import (
    FUNCTION_DESCRIPTIONS,
    MATURITY_DESCRIPTIONS,
    ExecutiveSummaryGenerator,
    SummaryConfig,
)

logger = logging.getLogger(__name__)

# Check for weasyprint availability
try:
    from weasyprint import CSS, HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logger.debug("weasyprint not installed - PDF generation unavailable")


# CSS styles for the report (monochrome, professional)
REPORT_CSS = """
@page {
    size: letter;
    margin: 1in;
    @top-right {
        content: counter(page);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 10pt;
        color: #666666;
    }
}

@page cover {
    margin: 0;
    @top-right { content: none; }
}

* {
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #000000;
    background: #ffffff;
}

/* Cover Page */
.cover {
    page: cover;
    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    padding: 2in;
}

.cover h1 {
    font-size: 36pt;
    font-weight: 300;
    margin-bottom: 0.5em;
    color: #000000;
}

.cover .subtitle {
    font-size: 18pt;
    color: #333333;
    margin-bottom: 2em;
}

.cover .organization {
    font-size: 24pt;
    font-weight: 600;
    margin-bottom: 0.5em;
}

.cover .date {
    font-size: 14pt;
    color: #666666;
}

.cover .logo {
    max-width: 200px;
    margin-bottom: 2em;
}

/* Page Break */
.page-break {
    page-break-after: always;
}

/* Section Headers */
h1 {
    font-size: 24pt;
    font-weight: 600;
    color: #000000;
    border-bottom: 2px solid #000000;
    padding-bottom: 0.25em;
    margin-top: 0;
    margin-bottom: 1em;
}

h2 {
    font-size: 16pt;
    font-weight: 600;
    color: #333333;
    margin-top: 1.5em;
    margin-bottom: 0.5em;
}

h3 {
    font-size: 13pt;
    font-weight: 600;
    color: #333333;
    margin-top: 1em;
    margin-bottom: 0.5em;
}

/* Executive Summary */
.executive-summary {
    background: #f5f5f5;
    padding: 1.5em;
    border-left: 4px solid #333333;
    margin-bottom: 1.5em;
}

.overall-score {
    text-align: center;
    padding: 2em;
    margin-bottom: 1em;
}

.overall-score .level {
    font-size: 72pt;
    font-weight: 700;
    color: #000000;
}

.overall-score .label {
    font-size: 14pt;
    color: #666666;
}

.overall-score .score {
    font-size: 18pt;
    color: #333333;
}

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
}

th, td {
    padding: 0.75em;
    text-align: left;
    border-bottom: 1px solid #cccccc;
}

th {
    background: #f0f0f0;
    font-weight: 600;
    color: #333333;
}

tr:hover {
    background: #fafafa;
}

/* Maturity Bars */
.maturity-bar {
    background: #e0e0e0;
    border-radius: 4px;
    height: 20px;
    width: 100%;
    position: relative;
}

.maturity-bar .fill {
    background: #333333;
    height: 100%;
    border-radius: 4px;
}

.maturity-bar .label {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 10pt;
    font-weight: 600;
}

/* Gap Priority Badges */
.priority-badge {
    display: inline-block;
    padding: 0.25em 0.5em;
    font-size: 9pt;
    font-weight: 600;
    border-radius: 3px;
}

.priority-critical {
    background: #000000;
    color: #ffffff;
}

.priority-high {
    background: #333333;
    color: #ffffff;
}

.priority-medium {
    background: #999999;
    color: #ffffff;
}

.priority-low {
    background: #cccccc;
    color: #000000;
}

/* Gap Cards */
.gap-card {
    border: 1px solid #cccccc;
    padding: 1em;
    margin-bottom: 1em;
    page-break-inside: avoid;
}

.gap-card .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5em;
}

.gap-card .control-id {
    font-weight: 600;
    font-size: 12pt;
}

.gap-card .explanation {
    color: #333333;
    margin-bottom: 0.5em;
}

.gap-card .recommendations {
    background: #f5f5f5;
    padding: 0.75em;
    font-size: 10pt;
}

/* Statistics Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1em;
    margin: 1em 0;
}

.stat-box {
    background: #f5f5f5;
    padding: 1em;
    text-align: center;
}

.stat-box .value {
    font-size: 28pt;
    font-weight: 700;
    color: #000000;
}

.stat-box .label {
    font-size: 10pt;
    color: #666666;
}

/* Evidence Appendix */
.evidence-list {
    font-size: 10pt;
}

.evidence-item {
    padding: 0.5em 0;
    border-bottom: 1px solid #eeeeee;
}

.evidence-item .platform {
    font-weight: 600;
}

.evidence-item .timestamp {
    color: #666666;
}

/* Footer */
.footer {
    margin-top: 2em;
    padding-top: 1em;
    border-top: 1px solid #cccccc;
    font-size: 9pt;
    color: #666666;
    text-align: center;
}

/* Print-specific */
@media print {
    body {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }
}
"""


@dataclass
class ReportConfig:
    """
    Configuration for PDF report generation.

    Attributes:
        organization: Organization name for cover page.
        logo_path: Optional path to logo image.
        include_evidence_appendix: Whether to include evidence details.
        include_all_gaps: Whether to include all gaps or just critical/high.
        include_trends: Whether to include trend analysis.
        max_gaps_per_function: Maximum gaps to show per function.
        report_date: Date for the report.
        footer_text: Custom footer text.
    """

    organization: str = "Organization"
    logo_path: Path | None = None
    include_evidence_appendix: bool = True
    include_all_gaps: bool = False
    include_trends: bool = True
    max_gaps_per_function: int = 5
    report_date: datetime | None = None
    footer_text: str = "Generated by Nisify - NIST CSF 2.0 Compliance Tool"


@dataclass
class ReportResult:
    """
    Result of a report generation operation.

    Attributes:
        success: Whether generation succeeded.
        pdf_path: Path to PDF file (if generated).
        html_path: Path to HTML file.
        size_bytes: Size of generated file.
        page_count: Estimated page count.
        error: Error message if failed.
    """

    success: bool
    pdf_path: Path | None
    html_path: Path | None
    size_bytes: int
    page_count: int
    error: str | None = None


class PdfReportGenerator:
    """
    Generator for PDF compliance reports.

    Creates professional, board-ready PDF reports with executive summary,
    maturity scores, gap analysis, and evidence appendix. Uses weasyprint
    for PDF generation (optional dependency).

    Example:
        generator = PdfReportGenerator(config)

        # Generate full report
        result = generator.generate_report(
            maturity=breakdown,
            gaps=gap_analysis,
            output_dir=Path("./reports"),
        )

        # Generate HTML only (no weasyprint required)
        html = generator.generate_html(breakdown, gap_analysis)

    Attributes:
        config: ReportConfig with generation settings.
    """

    def __init__(self, config: ReportConfig | None = None) -> None:
        """
        Initialize the PDF generator.

        Args:
            config: ReportConfig with generation settings.
        """
        self.config = config or ReportConfig()
        self._summary_generator = ExecutiveSummaryGenerator(
            SummaryConfig(
                organization=self.config.organization,
                include_recommendations=True,
                include_trends=self.config.include_trends,
                report_date=self.config.report_date,
            )
        )

    @property
    def pdf_available(self) -> bool:
        """Check if PDF generation is available."""
        return WEASYPRINT_AVAILABLE

    def generate_report(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None = None,
        evidence_summary: list[dict[str, Any]] | None = None,
        output_dir: Path | None = None,
    ) -> ReportResult:
        """
        Generate PDF report.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            trends: Optional TrendAnalysis for historical context.
            evidence_summary: Optional evidence summary for appendix.
            output_dir: Directory to write report files.

        Returns:
            ReportResult with generation details.
        """
        if output_dir is None:
            output_dir = Path(".")
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate HTML content
        html_content = self.generate_html(maturity, gaps, trends, evidence_summary)

        # Generate timestamp for filename
        report_date = self.config.report_date or datetime.now(UTC)
        timestamp = report_date.strftime("%Y%m%d_%H%M%S")

        # Save HTML
        html_path = output_dir / f"{timestamp}_compliance_report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Generate PDF if weasyprint available
        pdf_path = None
        if WEASYPRINT_AVAILABLE:
            try:
                pdf_path = output_dir / f"{timestamp}_compliance_report.pdf"
                html_doc = HTML(string=html_content)
                css = CSS(string=REPORT_CSS)
                html_doc.write_pdf(pdf_path, stylesheets=[css])
                logger.info("Generated PDF report: %s", pdf_path)
            except Exception as e:
                logger.error("Failed to generate PDF: %s", e)
                return ReportResult(
                    success=False,
                    pdf_path=None,
                    html_path=html_path,
                    size_bytes=html_path.stat().st_size,
                    page_count=0,
                    error=f"PDF generation failed: {e}",
                )
        else:
            logger.warning(
                "weasyprint not installed - PDF generation skipped. "
                "Install with: pip install weasyprint"
            )

        # Calculate size and estimate pages
        if pdf_path and pdf_path.exists():
            size_bytes = pdf_path.stat().st_size
            # Rough estimate: ~50KB per page
            page_count = max(1, size_bytes // 50000)
        else:
            size_bytes = html_path.stat().st_size
            page_count = 0

        return ReportResult(
            success=True,
            pdf_path=pdf_path,
            html_path=html_path,
            size_bytes=size_bytes,
            page_count=page_count,
        )

    def generate_html(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None = None,
        evidence_summary: list[dict[str, Any]] | None = None,
    ) -> str:
        """
        Generate HTML report content.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            trends: Optional TrendAnalysis for historical context.
            evidence_summary: Optional evidence summary for appendix.

        Returns:
            HTML content string.
        """
        report_date = self.config.report_date or datetime.now(UTC)
        date_str = report_date.strftime("%B %d, %Y")

        sections = []

        # HTML header
        sections.append(self._html_header())

        # Cover page
        sections.append(self._generate_cover(date_str))

        # Executive summary
        sections.append(self._generate_executive_section(maturity, gaps, trends))

        # Maturity by function
        sections.append(self._generate_maturity_section(maturity))

        # Gap analysis
        sections.append(self._generate_gaps_section(gaps))

        # Trends (if available)
        if self.config.include_trends and trends:
            sections.append(self._generate_trends_section(trends))

        # Evidence appendix
        if self.config.include_evidence_appendix and evidence_summary:
            sections.append(self._generate_evidence_section(evidence_summary))

        # Footer
        sections.append(self._generate_footer())

        # HTML footer
        sections.append("</body></html>")

        return "\n".join(sections)

    def _html_header(self) -> str:
        """Generate HTML document header."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIST CSF 2.0 Compliance Report - {self.config.organization}</title>
    <style>{REPORT_CSS}</style>
</head>
<body>"""

    def _generate_cover(self, date_str: str) -> str:
        """Generate cover page HTML."""
        logo_html = ""
        if self.config.logo_path and self.config.logo_path.exists():
            logo_html = f'<img src="{self.config.logo_path}" class="logo" alt="Logo">'

        return f"""
<div class="cover">
    {logo_html}
    <h1>NIST CSF 2.0</h1>
    <div class="subtitle">Compliance Assessment Report</div>
    <div class="organization">{self.config.organization}</div>
    <div class="date">{date_str}</div>
</div>
<div class="page-break"></div>"""

    def _generate_executive_section(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        trends: TrendAnalysis | None,
    ) -> str:
        """Generate executive summary section."""
        overall = maturity.overall
        rating = self._summary_generator.get_posture_rating(maturity)
        level_desc = MATURITY_DESCRIPTIONS.get(overall.level, "Unknown")

        # Get key findings
        findings_html = ""
        findings = [
            f"Overall maturity: Level {overall.level} ({overall.score:.2f}/4.0)",
            f"Evidence items collected: {overall.evidence_count}",
            f"Controls with gaps: {gaps.controls_with_gaps} ({gaps.gap_percentage:.1f}%)",
            f"Critical gaps: {gaps.gaps_by_priority.get('critical', 0)}",
        ]
        for finding in findings:
            findings_html += f"<li>{finding}</li>"

        return f"""
<h1>Executive Summary</h1>

<div class="overall-score">
    <div class="level">{overall.level}</div>
    <div class="label">Maturity Level</div>
    <div class="score">{overall.score:.2f} / 4.0 - {rating}</div>
</div>

<div class="executive-summary">
    <p><strong>{level_desc}</strong></p>
    <p>{self._summary_generator._generate_overview(maturity, gaps)}</p>
</div>

<h2>Key Metrics</h2>

<div class="stats-grid">
    <div class="stat-box">
        <div class="value">{overall.level}</div>
        <div class="label">Maturity Level</div>
    </div>
    <div class="stat-box">
        <div class="value">{gaps.controls_with_gaps}</div>
        <div class="label">Controls with Gaps</div>
    </div>
    <div class="stat-box">
        <div class="value">{gaps.gaps_by_priority.get('critical', 0)}</div>
        <div class="label">Critical Gaps</div>
    </div>
</div>

<h2>Key Findings</h2>
<ul>
{findings_html}
</ul>

<div class="page-break"></div>"""

    def _generate_maturity_section(self, maturity: MaturityBreakdown) -> str:
        """Generate maturity scores section."""
        rows = ""
        for func_id, func_score in maturity.by_function.items():
            func_desc = FUNCTION_DESCRIPTIONS.get(func_id, func_id)
            func_name = func_desc.split(" - ")[0]
            func_detail = func_desc.split(" - ")[1] if " - " in func_desc else ""
            level_desc = MATURITY_DESCRIPTIONS.get(func_score.level, "").split(" - ")[0]
            bar_width = (func_score.score / 4.0) * 100

            rows += f"""
<tr>
    <td><strong>{func_name}</strong><br><small>{func_detail}</small></td>
    <td>{func_score.level}</td>
    <td>{func_score.score:.2f}</td>
    <td>
        <div class="maturity-bar">
            <div class="fill" style="width: {bar_width}%;"></div>
        </div>
    </td>
    <td>{level_desc}</td>
</tr>"""

        return f"""
<h1>Maturity Scores by Function</h1>

<table>
    <thead>
        <tr>
            <th>Function</th>
            <th>Level</th>
            <th>Score</th>
            <th>Progress</th>
            <th>Assessment</th>
        </tr>
    </thead>
    <tbody>
        {rows}
    </tbody>
</table>

<div class="page-break"></div>"""

    def _generate_gaps_section(self, gaps: GapAnalysis) -> str:
        """Generate gap analysis section."""
        # Summary stats
        summary = f"""
<h1>Gap Analysis</h1>

<div class="stats-grid">
    <div class="stat-box">
        <div class="value">{gaps.total_controls}</div>
        <div class="label">Total Controls</div>
    </div>
    <div class="stat-box">
        <div class="value">{gaps.controls_with_gaps}</div>
        <div class="label">With Gaps</div>
    </div>
    <div class="stat-box">
        <div class="value">{gaps.gap_percentage:.1f}%</div>
        <div class="label">Gap Rate</div>
    </div>
</div>

<h2>Gap Distribution</h2>
<table>
    <thead>
        <tr>
            <th>Priority</th>
            <th>Count</th>
        </tr>
    </thead>
    <tbody>
        <tr><td>Critical</td><td>{gaps.gaps_by_priority.get('critical', 0)}</td></tr>
        <tr><td>High</td><td>{gaps.gaps_by_priority.get('high', 0)}</td></tr>
        <tr><td>Medium</td><td>{gaps.gaps_by_priority.get('medium', 0)}</td></tr>
        <tr><td>Low</td><td>{gaps.gaps_by_priority.get('low', 0)}</td></tr>
    </tbody>
</table>
"""

        # Critical and high gaps
        priority_gaps = [
            g for g in gaps.all_gaps
            if g.priority.value in ("critical", "high")
        ]

        if not self.config.include_all_gaps:
            priority_gaps = priority_gaps[:10]  # Limit to top 10

        gaps_html = ""
        for gap in priority_gaps:
            priority_class = f"priority-{gap.priority.value}"
            rec_html = ""
            if gap.recommendations:
                rec = gap.recommendations[0]
                rec_html = f'<div class="recommendations"><strong>Recommendation:</strong> {rec.action}</div>'

            gaps_html += f"""
<div class="gap-card">
    <div class="header">
        <span class="control-id">{gap.control_id} - {gap.control_name}</span>
        <span class="priority-badge {priority_class}">{gap.priority.value.upper()}</span>
    </div>
    <div class="explanation">{gap.explanation}</div>
    {rec_html}
</div>"""

        return f"""
{summary}

<h2>Priority Gaps</h2>
{gaps_html}

<div class="page-break"></div>"""

    def _generate_trends_section(self, trends: TrendAnalysis) -> str:
        """Generate trends section."""
        overall = trends.overall_trend
        stats = trends.statistics

        direction_text = overall.direction.value.capitalize()
        delta_str = ""
        if overall.score_delta:
            sign = "+" if overall.score_delta > 0 else ""
            delta_str = f" ({sign}{overall.score_delta:.2f})"

        return f"""
<h1>Trend Analysis</h1>

<div class="executive-summary">
    <p>Over the past {trends.period_days} days, overall compliance posture has been
    <strong>{direction_text}</strong>{delta_str}.</p>
</div>

<div class="stats-grid">
    <div class="stat-box">
        <div class="value">{stats.get('improving_count', 0)}</div>
        <div class="label">Improving</div>
    </div>
    <div class="stat-box">
        <div class="value">{stats.get('stable_count', 0)}</div>
        <div class="label">Stable</div>
    </div>
    <div class="stat-box">
        <div class="value">{stats.get('regressing_count', 0)}</div>
        <div class="label">Regressing</div>
    </div>
</div>

<div class="page-break"></div>"""

    def _generate_evidence_section(
        self,
        evidence_summary: list[dict[str, Any]],
    ) -> str:
        """Generate evidence appendix section."""
        # Group by platform
        by_platform: dict[str, list[dict[str, Any]]] = {}
        for item in evidence_summary:
            platform = item.get("platform", "unknown")
            if platform not in by_platform:
                by_platform[platform] = []
            by_platform[platform].append(item)

        platform_sections = ""
        for platform, items in by_platform.items():
            items_html = ""
            for item in items[:20]:  # Limit per platform
                ev_type = item.get("evidence_type", "unknown")
                collected = item.get("collected_at", "unknown")
                items_html += f"""
<div class="evidence-item">
    <span class="platform">{ev_type}</span>
    <span class="timestamp"> - {collected}</span>
</div>"""

            platform_sections += f"""
<h3>{platform.upper()}</h3>
<div class="evidence-list">
{items_html}
</div>"""

        return f"""
<h1>Evidence Appendix</h1>

<p>Summary of evidence collected from configured platforms.</p>

{platform_sections}
"""

    def _generate_footer(self) -> str:
        """Generate report footer."""
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""
<div class="footer">
    {self.config.footer_text}<br>
    Report generated: {timestamp}
</div>"""

    def get_report_metadata(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
    ) -> dict[str, Any]:
        """
        Get metadata about the report.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.

        Returns:
            Dictionary with report metadata.
        """
        return {
            "organization": self.config.organization,
            "report_date": (
                self.config.report_date or datetime.now(UTC)
            ).isoformat(),
            "overall_maturity": maturity.overall.level,
            "overall_score": maturity.overall.score,
            "total_gaps": gaps.controls_with_gaps,
            "critical_gaps": gaps.gaps_by_priority.get("critical", 0),
            "pdf_available": WEASYPRINT_AVAILABLE,
            "generator_version": "0.1.0",
        }
