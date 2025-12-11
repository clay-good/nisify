"""
Report generation for compliance documentation.

This module generates professional reports suitable for board presentations,
auditor review, and programmatic consumption.

Supported Formats:
    - PDF: Board-ready reports with executive summary, maturity scores,
           gap analysis, and evidence appendix. Requires weasyprint.
    - JSON: Machine-readable exports with full data and schemas.
    - HTML: Browser-viewable reports (generated alongside PDF).
    - Text: Plain text summaries for emails and quick reference.
    - Markdown: Documentation-friendly format.

Example:
    from nisify.reports import (
        PdfReportGenerator,
        JsonExporter,
        ExecutiveSummaryGenerator,
    )

    # Generate PDF report
    pdf_gen = PdfReportGenerator(ReportConfig(organization="Acme Corp"))
    result = pdf_gen.generate_report(maturity, gaps, output_dir=Path("./reports"))

    # Export JSON data
    json_exp = JsonExporter(version="0.1.0")
    result = json_exp.export_full(maturity, gaps, output_dir=Path("./exports"))

    # Generate executive summary
    summary_gen = ExecutiveSummaryGenerator()
    summary = summary_gen.generate_summary(maturity, gaps)
    email = summary_gen.generate_email_body(maturity, gaps)
"""

from nisify.reports.executive_summary import (
    ExecutiveSummaryGenerator,
    SummaryConfig,
)
from nisify.reports.json_exporter import (
    ExportMetadata,
    ExportResult,
    JsonExporter,
)
from nisify.reports.pdf_generator import (
    WEASYPRINT_AVAILABLE,
    PdfReportGenerator,
    ReportConfig,
    ReportResult,
)

__all__ = [
    # JSON Exporter
    "JsonExporter",
    "ExportMetadata",
    "ExportResult",
    # Executive Summary
    "ExecutiveSummaryGenerator",
    "SummaryConfig",
    # PDF Generator
    "PdfReportGenerator",
    "ReportConfig",
    "ReportResult",
    "WEASYPRINT_AVAILABLE",
]
