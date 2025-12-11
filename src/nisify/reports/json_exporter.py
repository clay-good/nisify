"""
JSON export functionality for compliance data.

This module exports maturity scores, gap analysis, and evidence in
machine-readable JSON format. All exports include metadata for
traceability and validation.

Export Types:
    - full: Complete export with all data
    - maturity: Maturity scores and explanations only
    - evidence: Raw evidence with metadata
    - gaps: Gap analysis and recommendations only

All exports are validated against JSON schemas and include timestamps
for audit purposes.
"""

from __future__ import annotations

import gzip
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nisify.analysis.gap_analyzer import GapAnalysis
from nisify.analysis.trend_tracker import TrendAnalysis
from nisify.nist.maturity_calculator import MaturityBreakdown

logger = logging.getLogger(__name__)


# JSON Schema definitions for export validation
MATURITY_EXPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Nisify Maturity Export",
    "type": "object",
    "required": ["metadata", "overall", "by_function"],
    "properties": {
        "metadata": {
            "type": "object",
            "required": ["export_type", "timestamp", "version"],
        },
        "overall": {"type": "object"},
        "by_function": {"type": "object"},
        "by_category": {"type": "object"},
        "by_subcategory": {"type": "object"},
        "statistics": {"type": "object"},
    },
}

GAPS_EXPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Nisify Gap Analysis Export",
    "type": "object",
    "required": ["metadata", "summary", "gaps"],
    "properties": {
        "metadata": {"type": "object"},
        "summary": {"type": "object"},
        "gaps": {"type": "array"},
        "recommendations": {"type": "array"},
    },
}

EVIDENCE_EXPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Nisify Evidence Export",
    "type": "object",
    "required": ["metadata", "evidence_items"],
    "properties": {
        "metadata": {"type": "object"},
        "evidence_items": {"type": "array"},
        "collection_runs": {"type": "array"},
    },
}

FULL_EXPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Nisify Full Export",
    "type": "object",
    "required": ["metadata", "maturity", "gaps"],
    "properties": {
        "metadata": {"type": "object"},
        "maturity": {"type": "object"},
        "gaps": {"type": "object"},
        "evidence": {"type": "object"},
        "trends": {"type": "object"},
    },
}


@dataclass
class ExportMetadata:
    """
    Metadata included in all exports.

    Attributes:
        export_type: Type of export (full, maturity, evidence, gaps).
        timestamp: When the export was created.
        version: Nisify version that created the export.
        organization: Organization name (from config).
        period_start: Start of data period (if applicable).
        period_end: End of data period (if applicable).
    """

    export_type: str
    timestamp: datetime
    version: str
    organization: str | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "export_type": self.export_type,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "organization": self.organization,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "format_version": "1.0",
        }


@dataclass
class ExportResult:
    """
    Result of an export operation.

    Attributes:
        success: Whether the export completed successfully.
        path: Path to the exported file.
        size_bytes: Size of the exported file in bytes.
        record_count: Number of records exported.
        export_type: Type of export performed.
        compressed: Whether the file is compressed.
        error: Error message if export failed.
    """

    success: bool
    path: Path | None
    size_bytes: int
    record_count: int
    export_type: str
    compressed: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "path": str(self.path) if self.path else None,
            "size_bytes": self.size_bytes,
            "record_count": self.record_count,
            "export_type": self.export_type,
            "compressed": self.compressed,
            "error": self.error,
        }


class JsonExporter:
    """
    Exporter for JSON format compliance data.

    Exports maturity scores, gap analysis, evidence, and complete
    data sets in machine-readable JSON format. Supports compression
    and schema validation.

    Example:
        exporter = JsonExporter(version="0.1.0", organization="Acme Corp")

        # Export maturity scores
        result = exporter.export_maturity(breakdown, Path("./exports"))

        # Export gap analysis
        result = exporter.export_gaps(gap_analysis, Path("./exports"))

        # Export everything
        result = exporter.export_full(
            maturity=breakdown,
            gaps=gap_analysis,
            evidence=evidence_items,
            trends=trend_analysis,
            output_dir=Path("./exports"),
        )

    Attributes:
        version: Nisify version string.
        organization: Organization name for metadata.
    """

    def __init__(
        self,
        version: str = "0.1.0",
        organization: str | None = None,
    ) -> None:
        """
        Initialize the JSON exporter.

        Args:
            version: Nisify version string for metadata.
            organization: Organization name for metadata.
        """
        self.version = version
        self.organization = organization

    def export_maturity(
        self,
        breakdown: MaturityBreakdown,
        output_dir: Path,
        compress: bool = False,
    ) -> ExportResult:
        """
        Export maturity scores to JSON.

        Args:
            breakdown: MaturityBreakdown from calculator.
            output_dir: Directory to write export file.
            compress: Whether to gzip compress the output.

        Returns:
            ExportResult with export details.
        """
        try:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            metadata = ExportMetadata(
                export_type="maturity",
                timestamp=datetime.now(UTC),
                version=self.version,
                organization=self.organization,
            )

            export_data = {
                "metadata": metadata.to_dict(),
                "overall": breakdown.overall.to_dict(),
                "by_function": {
                    k: v.to_dict() for k, v in breakdown.by_function.items()
                },
                "by_category": {
                    k: v.to_dict() for k, v in breakdown.by_category.items()
                },
                "by_subcategory": {
                    k: v.to_dict() for k, v in breakdown.by_subcategory.items()
                },
                "statistics": breakdown.statistics,
                "schema": MATURITY_EXPORT_SCHEMA,
            }

            filename = self._generate_filename("maturity", compress)
            filepath = output_dir / filename

            size_bytes = self._write_json(export_data, filepath, compress)

            record_count = (
                len(breakdown.by_subcategory)
                + len(breakdown.by_category)
                + len(breakdown.by_function)
                + 1  # overall
            )

            logger.info("Exported maturity data to %s (%d bytes)", filepath, size_bytes)

            return ExportResult(
                success=True,
                path=filepath,
                size_bytes=size_bytes,
                record_count=record_count,
                export_type="maturity",
                compressed=compress,
            )

        except Exception as e:
            logger.error("Failed to export maturity data: %s", e)
            return ExportResult(
                success=False,
                path=None,
                size_bytes=0,
                record_count=0,
                export_type="maturity",
                compressed=compress,
                error=str(e),
            )

    def export_gaps(
        self,
        gap_analysis: GapAnalysis,
        output_dir: Path,
        compress: bool = False,
    ) -> ExportResult:
        """
        Export gap analysis to JSON.

        Args:
            gap_analysis: GapAnalysis from analyzer.
            output_dir: Directory to write export file.
            compress: Whether to gzip compress the output.

        Returns:
            ExportResult with export details.
        """
        try:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            metadata = ExportMetadata(
                export_type="gaps",
                timestamp=datetime.now(UTC),
                version=self.version,
                organization=self.organization,
            )

            export_data = {
                "metadata": metadata.to_dict(),
                "summary": {
                    "total_controls": gap_analysis.total_controls,
                    "controls_with_gaps": gap_analysis.controls_with_gaps,
                    "gap_percentage": gap_analysis.gap_percentage,
                    "gaps_by_priority": gap_analysis.gaps_by_priority,
                    "gaps_by_type": gap_analysis.gaps_by_type,
                },
                "gaps": [g.to_dict() for g in gap_analysis.all_gaps],
                "critical_gaps": [g.to_dict() for g in gap_analysis.critical_gaps],
                "quick_wins": [g.to_dict() for g in gap_analysis.quick_wins],
                "recommendations": [
                    r.to_dict() for r in gap_analysis.top_recommendations
                ],
                "gaps_by_function": {
                    k: [g.to_dict() for g in v]
                    for k, v in gap_analysis.gaps_by_function.items()
                },
                "schema": GAPS_EXPORT_SCHEMA,
            }

            filename = self._generate_filename("gaps", compress)
            filepath = output_dir / filename

            size_bytes = self._write_json(export_data, filepath, compress)

            logger.info("Exported gap analysis to %s (%d bytes)", filepath, size_bytes)

            return ExportResult(
                success=True,
                path=filepath,
                size_bytes=size_bytes,
                record_count=len(gap_analysis.all_gaps),
                export_type="gaps",
                compressed=compress,
            )

        except Exception as e:
            logger.error("Failed to export gap analysis: %s", e)
            return ExportResult(
                success=False,
                path=None,
                size_bytes=0,
                record_count=0,
                export_type="gaps",
                compressed=compress,
                error=str(e),
            )

    def export_evidence(
        self,
        evidence_items: list[dict[str, Any]],
        collection_runs: list[dict[str, Any]] | None = None,
        output_dir: Path | None = None,
        compress: bool = False,
    ) -> ExportResult:
        """
        Export evidence items to JSON.

        Args:
            evidence_items: List of evidence dictionaries.
            collection_runs: Optional list of collection run metadata.
            output_dir: Directory to write export file.
            compress: Whether to gzip compress the output.

        Returns:
            ExportResult with export details.
        """
        try:
            if output_dir is None:
                output_dir = Path(".")
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Determine period from evidence
            period_start = None
            period_end = None
            if evidence_items:
                dates = []
                for item in evidence_items:
                    if "collected_at" in item:
                        try:
                            dt = datetime.fromisoformat(item["collected_at"])
                            dates.append(dt)
                        except (ValueError, TypeError):
                            pass
                if dates:
                    period_start = min(dates)
                    period_end = max(dates)

            metadata = ExportMetadata(
                export_type="evidence",
                timestamp=datetime.now(UTC),
                version=self.version,
                organization=self.organization,
                period_start=period_start,
                period_end=period_end,
            )

            # Group evidence by platform
            by_platform: dict[str, list[dict[str, Any]]] = {}
            for item in evidence_items:
                platform = item.get("platform", "unknown")
                if platform not in by_platform:
                    by_platform[platform] = []
                by_platform[platform].append(item)

            export_data = {
                "metadata": metadata.to_dict(),
                "evidence_items": evidence_items,
                "by_platform": by_platform,
                "collection_runs": collection_runs or [],
                "statistics": {
                    "total_items": len(evidence_items),
                    "platforms": list(by_platform.keys()),
                    "items_by_platform": {k: len(v) for k, v in by_platform.items()},
                },
                "schema": EVIDENCE_EXPORT_SCHEMA,
            }

            filename = self._generate_filename("evidence", compress)
            filepath = output_dir / filename

            size_bytes = self._write_json(export_data, filepath, compress)

            logger.info("Exported evidence to %s (%d bytes)", filepath, size_bytes)

            return ExportResult(
                success=True,
                path=filepath,
                size_bytes=size_bytes,
                record_count=len(evidence_items),
                export_type="evidence",
                compressed=compress,
            )

        except Exception as e:
            logger.error("Failed to export evidence: %s", e)
            return ExportResult(
                success=False,
                path=None,
                size_bytes=0,
                record_count=0,
                export_type="evidence",
                compressed=compress,
                error=str(e),
            )

    def export_full(
        self,
        maturity: MaturityBreakdown,
        gaps: GapAnalysis,
        evidence: list[dict[str, Any]] | None = None,
        trends: TrendAnalysis | None = None,
        output_dir: Path | None = None,
        compress: bool = False,
    ) -> ExportResult:
        """
        Export complete compliance data to JSON.

        Args:
            maturity: MaturityBreakdown from calculator.
            gaps: GapAnalysis from analyzer.
            evidence: Optional list of evidence dictionaries.
            trends: Optional TrendAnalysis from tracker.
            output_dir: Directory to write export file.
            compress: Whether to gzip compress the output.

        Returns:
            ExportResult with export details.
        """
        try:
            if output_dir is None:
                output_dir = Path(".")
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            metadata = ExportMetadata(
                export_type="full",
                timestamp=datetime.now(UTC),
                version=self.version,
                organization=self.organization,
            )

            export_data: dict[str, Any] = {
                "metadata": metadata.to_dict(),
                "maturity": {
                    "overall": maturity.overall.to_dict(),
                    "by_function": {
                        k: v.to_dict() for k, v in maturity.by_function.items()
                    },
                    "by_category": {
                        k: v.to_dict() for k, v in maturity.by_category.items()
                    },
                    "by_subcategory": {
                        k: v.to_dict() for k, v in maturity.by_subcategory.items()
                    },
                    "statistics": maturity.statistics,
                },
                "gaps": {
                    "summary": {
                        "total_controls": gaps.total_controls,
                        "controls_with_gaps": gaps.controls_with_gaps,
                        "gap_percentage": gaps.gap_percentage,
                        "gaps_by_priority": gaps.gaps_by_priority,
                        "gaps_by_type": gaps.gaps_by_type,
                    },
                    "all_gaps": [g.to_dict() for g in gaps.all_gaps],
                    "critical_gaps": [g.to_dict() for g in gaps.critical_gaps],
                    "quick_wins": [g.to_dict() for g in gaps.quick_wins],
                    "top_recommendations": [
                        r.to_dict() for r in gaps.top_recommendations
                    ],
                },
                "schema": FULL_EXPORT_SCHEMA,
            }

            # Add evidence if provided
            if evidence:
                by_platform: dict[str, list[dict[str, Any]]] = {}
                for item in evidence:
                    platform = item.get("platform", "unknown")
                    if platform not in by_platform:
                        by_platform[platform] = []
                    by_platform[platform].append(item)

                export_data["evidence"] = {
                    "items": evidence,
                    "by_platform": by_platform,
                    "statistics": {
                        "total_items": len(evidence),
                        "platforms": list(by_platform.keys()),
                    },
                }

            # Add trends if provided
            if trends:
                export_data["trends"] = trends.to_dict()

            filename = self._generate_filename("full", compress)
            filepath = output_dir / filename

            size_bytes = self._write_json(export_data, filepath, compress)

            record_count = (
                len(maturity.by_subcategory)
                + len(gaps.all_gaps)
                + (len(evidence) if evidence else 0)
            )

            logger.info("Exported full data to %s (%d bytes)", filepath, size_bytes)

            return ExportResult(
                success=True,
                path=filepath,
                size_bytes=size_bytes,
                record_count=record_count,
                export_type="full",
                compressed=compress,
            )

        except Exception as e:
            logger.error("Failed to export full data: %s", e)
            return ExportResult(
                success=False,
                path=None,
                size_bytes=0,
                record_count=0,
                export_type="full",
                compressed=compress,
                error=str(e),
            )

    def _generate_filename(self, export_type: str, compress: bool) -> str:
        """Generate filename with timestamp."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        extension = ".json.gz" if compress else ".json"
        return f"{timestamp}_{export_type}_export{extension}"

    def _write_json(
        self,
        data: dict[str, Any],
        filepath: Path,
        compress: bool,
    ) -> int:
        """
        Write JSON data to file.

        Args:
            data: Data to write.
            filepath: Path to output file.
            compress: Whether to gzip compress.

        Returns:
            Size of written file in bytes.
        """
        json_content = json.dumps(data, indent=2, default=str)

        if compress:
            with gzip.open(filepath, "wt", encoding="utf-8") as f:
                f.write(json_content)
        else:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_content)

        return filepath.stat().st_size

    def get_schema(self, export_type: str) -> dict[str, Any]:
        """
        Get JSON schema for an export type.

        Args:
            export_type: Type of export (full, maturity, evidence, gaps).

        Returns:
            JSON schema dictionary.
        """
        schemas = {
            "maturity": MATURITY_EXPORT_SCHEMA,
            "gaps": GAPS_EXPORT_SCHEMA,
            "evidence": EVIDENCE_EXPORT_SCHEMA,
            "full": FULL_EXPORT_SCHEMA,
        }
        return schemas.get(export_type, {})

    def export_schema(self, export_type: str, output_path: Path) -> bool:
        """
        Export JSON schema to file.

        Args:
            export_type: Type of export.
            output_path: Path to write schema file.

        Returns:
            True if successful.
        """
        try:
            schema = self.get_schema(export_type)
            if not schema:
                return False

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(schema, f, indent=2)

            return True
        except Exception as e:
            logger.error("Failed to export schema: %s", e)
            return False
