"""
Dashboard HTTP server for Nisify compliance visualization.

This module provides a simple HTTP server using Python's built-in http.server
module. No external frameworks (Flask, Django, FastAPI) are used to minimize
dependencies and attack surface.

Features:
    - Local-only binding by default (127.0.0.1)
    - Static file serving for CSS and JavaScript
    - HTML template rendering
    - JSON API endpoints for data
    - Optional password protection

Security:
    - Binds to localhost only by default
    - No external resource loading (fully offline)
    - CORS disabled
    - All data is read-only
"""

from __future__ import annotations

import html
import json
import logging
import os
import socket
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from nisify.analysis.gap_analyzer import GapAnalysis
from nisify.analysis.trend_tracker import TrendAnalysis
from nisify.nist.maturity_calculator import MaturityBreakdown
from nisify.dashboard.routes import RouteContext, get_route_handler

logger = logging.getLogger(__name__)

# Default host and port
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

# Content types
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
}


class DashboardData:
    """
    Container for dashboard data.

    Holds the current maturity breakdown, gap analysis, and trend data
    for serving via the dashboard API.

    Attributes:
        maturity: Current maturity breakdown.
        gaps: Current gap analysis.
        trends: Current trend analysis.
        evidence_store: Reference to evidence store for evidence browsing.
        last_updated: When data was last refreshed.
    """

    def __init__(self) -> None:
        """Initialize empty dashboard data."""
        self.maturity: MaturityBreakdown | None = None
        self.gaps: GapAnalysis | None = None
        self.trends: TrendAnalysis | None = None
        self.evidence_store: Any = None
        self.last_updated: datetime | None = None
        self.organization_name: str = "Organization"

    def update(
        self,
        maturity: MaturityBreakdown | None = None,
        gaps: GapAnalysis | None = None,
        trends: TrendAnalysis | None = None,
        evidence_store: Any = None,
        organization_name: str | None = None,
    ) -> None:
        """
        Update dashboard data.

        Args:
            maturity: New maturity breakdown.
            gaps: New gap analysis.
            trends: New trend analysis.
            evidence_store: Reference to evidence store.
            organization_name: Organization name for display.
        """
        if maturity is not None:
            self.maturity = maturity
        if gaps is not None:
            self.gaps = gaps
        if trends is not None:
            self.trends = trends
        if evidence_store is not None:
            self.evidence_store = evidence_store
        if organization_name is not None:
            self.organization_name = organization_name
        self.last_updated = datetime.now(UTC)

    def to_summary(self) -> dict[str, Any]:
        """Get summary data for dashboard overview."""
        summary: dict[str, Any] = {
            "organization": self.organization_name,
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
            "has_data": self.maturity is not None,
        }

        if self.maturity:
            summary["overall_score"] = round(self.maturity.overall.score, 2)
            summary["overall_level"] = self.maturity.overall.level
            summary["evidence_count"] = self.maturity.overall.evidence_count
            summary["statistics"] = self.maturity.statistics

        if self.gaps:
            summary["gap_count"] = self.gaps.controls_with_gaps
            summary["gap_percentage"] = round(self.gaps.gap_percentage, 1)
            summary["critical_gaps"] = len(self.gaps.critical_gaps)
            summary["quick_wins"] = len(self.gaps.quick_wins)

        if self.trends:
            summary["trend_direction"] = self.trends.overall_trend.direction.value
            summary["trend_delta"] = self.trends.overall_trend.score_delta

        return summary


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the dashboard.

    Routes requests to appropriate handlers for pages and API endpoints.
    Serves static files and renders HTML templates.
    """

    # Class-level reference to dashboard data
    dashboard_data: DashboardData = DashboardData()

    # Class-level reference to static/template directories
    static_dir: Path = Path(__file__).parent / "static"
    template_dir: Path = Path(__file__).parent / "templates"

    # Route table
    routes: dict[str, Callable[..., None]] = {}

    def log_message(self, format: str, *args: Any) -> None:
        """Log HTTP requests to logger instead of stderr."""
        logger.debug("Dashboard request: %s", format % args)

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Try routes first
        if path in self.routes:
            self.routes[path](self, query)
            return

        # Static files
        if path.startswith("/static/"):
            self._serve_static(path[8:])  # Remove /static/ prefix
            return

        # Page routes
        if path == "/" or path == "/index":
            self._serve_template("index.html")
        elif path == "/dashboard":
            self._serve_template("dashboard.html")
        elif path == "/gaps":
            self._serve_template("gaps.html")
        elif path == "/evidence":
            self._serve_template("evidence.html")
        elif path == "/trends":
            self._serve_template("trends.html")
        # API routes - check route handlers from routes module first
        elif path.startswith("/api/"):
            handler = get_route_handler(path)
            if handler:
                self._serve_api_route(handler, query)
            else:
                self._send_404()
        else:
            self._send_404()

    def _serve_static(self, filename: str) -> None:
        """Serve a static file."""
        # Prevent directory traversal
        safe_filename = os.path.basename(filename)
        file_path = self.static_dir / safe_filename

        if not file_path.exists() or not file_path.is_file():
            self._send_404()
            return

        # Determine content type
        ext = file_path.suffix.lower()
        content_type = CONTENT_TYPES.get(ext, "application/octet-stream")

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logger.error("Error serving static file %s: %s", filename, e)
            self._send_500()

    def _serve_template(self, template_name: str) -> None:
        """Serve an HTML template."""
        template_path = self.template_dir / template_name

        if not template_path.exists():
            self._send_404()
            return

        try:
            with open(template_path, encoding="utf-8") as f:
                content = f.read()

            # Simple template variable substitution
            content = self._render_template(content)

            encoded = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except Exception as e:
            logger.error("Error serving template %s: %s", template_name, e)
            self._send_500()

    def _render_template(self, content: str) -> str:
        """
        Render template with variable substitution.

        Supports simple {{variable}} syntax for basic substitutions.
        All values are HTML-escaped to prevent XSS attacks.
        """
        data = self.dashboard_data

        # All values are HTML-escaped for security
        replacements = {
            "{{organization}}": html.escape(data.organization_name),
            "{{last_updated}}": html.escape(
                data.last_updated.strftime("%Y-%m-%d %H:%M UTC")
                if data.last_updated
                else "Never"
            ),
            "{{overall_score}}": html.escape(
                f"{data.maturity.overall.score:.2f}"
                if data.maturity
                else "N/A"
            ),
            "{{overall_level}}": html.escape(
                str(data.maturity.overall.level)
                if data.maturity
                else "N/A"
            ),
            "{{evidence_count}}": html.escape(
                str(data.maturity.overall.evidence_count)
                if data.maturity
                else "0"
            ),
            "{{gap_count}}": html.escape(
                str(data.gaps.controls_with_gaps)
                if data.gaps
                else "0"
            ),
            "{{critical_gaps}}": html.escape(
                str(len(data.gaps.critical_gaps))
                if data.gaps
                else "0"
            ),
        }

        for key, value in replacements.items():
            content = content.replace(key, value)

        return content

    def _serve_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        """Serve JSON response."""
        try:
            content = json.dumps(data, indent=2, default=str)
            encoded = content.encode("utf-8")

            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except Exception as e:
            logger.error("Error serving JSON: %s", e)
            self._send_500()

    def _serve_api_route(
        self,
        handler: Any,
        query: dict[str, list[str]],
    ) -> None:
        """
        Serve an API route using a route handler from routes module.

        Args:
            handler: Route handler function.
            query: Query parameters.
        """
        # Build route context with current dashboard data
        context = RouteContext(
            maturity=self.dashboard_data.maturity,
            gaps=self.dashboard_data.gaps,
            trends=self.dashboard_data.trends,
            evidence_store=self.dashboard_data.evidence_store,
            organization_name=self.dashboard_data.organization_name,
            last_updated=self.dashboard_data.last_updated,
        )

        try:
            result = handler(context, query)

            # Check for error status in response
            status = HTTPStatus.OK
            if "status" in result:
                status_code = result.pop("status", 200)
                if status_code == 400:
                    status = HTTPStatus.BAD_REQUEST
                elif status_code == 404:
                    status = HTTPStatus.NOT_FOUND
                elif status_code == 500:
                    status = HTTPStatus.INTERNAL_SERVER_ERROR

            self._serve_json(result, status)
        except Exception as e:
            logger.error("Error in API handler: %s", e)
            self._serve_json(
                {"error": str(e)},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _serve_api_summary(self) -> None:
        """Serve dashboard summary API."""
        summary = self.dashboard_data.to_summary()
        self._serve_json(summary)

    def _serve_api_maturity(self) -> None:
        """Serve maturity data API."""
        if not self.dashboard_data.maturity:
            self._serve_json(
                {"error": "No maturity data available"},
                HTTPStatus.NOT_FOUND,
            )
            return

        self._serve_json(self.dashboard_data.maturity.to_dict())

    def _serve_api_gaps(self) -> None:
        """Serve gap analysis API."""
        if not self.dashboard_data.gaps:
            self._serve_json(
                {"error": "No gap analysis available"},
                HTTPStatus.NOT_FOUND,
            )
            return

        self._serve_json(self.dashboard_data.gaps.to_dict())

    def _serve_api_evidence(self, query: dict[str, list[str]]) -> None:
        """Serve evidence listing API."""
        store = self.dashboard_data.evidence_store

        if not store:
            self._serve_json(
                {"error": "No evidence store configured"},
                HTTPStatus.NOT_FOUND,
            )
            return

        # Get query parameters
        platform = query.get("platform", [None])[0]
        evidence_type = query.get("type", [None])[0]
        limit = int(query.get("limit", ["100"])[0])

        try:
            # Get evidence statistics
            stats = store.get_statistics()

            # Get recent evidence
            evidence_list = []
            if hasattr(store, "get_all_evidence"):
                all_evidence = store.get_all_evidence(limit=limit)
                for ev in all_evidence:
                    if platform and ev.get("platform") != platform:
                        continue
                    if evidence_type and ev.get("evidence_type") != evidence_type:
                        continue
                    evidence_list.append(ev)

            response = {
                "statistics": stats,
                "evidence": evidence_list[:limit],
                "total": len(evidence_list),
            }
            self._serve_json(response)
        except Exception as e:
            logger.error("Error fetching evidence: %s", e)
            self._serve_json(
                {"error": str(e)},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _serve_api_trends(self) -> None:
        """Serve trend data API."""
        if not self.dashboard_data.trends:
            self._serve_json(
                {"error": "No trend data available"},
                HTTPStatus.NOT_FOUND,
            )
            return

        self._serve_json(self.dashboard_data.trends.to_dict())

    def _serve_api_functions(self) -> None:
        """Serve function scores API."""
        if not self.dashboard_data.maturity:
            self._serve_json(
                {"error": "No maturity data available"},
                HTTPStatus.NOT_FOUND,
            )
            return

        functions = {}
        for func_id, score in self.dashboard_data.maturity.by_function.items():
            functions[func_id] = score.to_dict()

        self._serve_json({"functions": functions})

    def _serve_api_health(self) -> None:
        """Serve health check API."""
        health = {
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "has_maturity_data": self.dashboard_data.maturity is not None,
            "has_gap_data": self.dashboard_data.gaps is not None,
            "has_trend_data": self.dashboard_data.trends is not None,
        }
        self._serve_json(health)

    def _send_404(self) -> None:
        """Send 404 Not Found response."""
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        content = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested resource was not found.</p>
<p><a href="/">Return to Dashboard</a></p>
</body>
</html>"""
        self.wfile.write(content.encode("utf-8"))

    def _send_500(self) -> None:
        """Send 500 Internal Server Error response."""
        self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        content = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<h1>500 Internal Server Error</h1>
<p>An internal error occurred.</p>
<p><a href="/">Return to Dashboard</a></p>
</body>
</html>"""
        self.wfile.write(content.encode("utf-8"))


class DashboardServer:
    """
    Dashboard HTTP server manager.

    Provides methods for starting, stopping, and managing the dashboard
    HTTP server. Runs the server in a background thread.

    Example:
        server = DashboardServer()

        # Update data
        server.update_data(maturity=breakdown, gaps=analysis)

        # Start server
        server.start(host="127.0.0.1", port=8080)

        # Check status
        if server.is_running():
            print(f"Dashboard at http://{server.host}:{server.port}")

        # Stop server
        server.stop()

    Attributes:
        host: Host address to bind to.
        port: Port number to bind to.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
    ) -> None:
        """
        Initialize the dashboard server.

        Args:
            host: Host address to bind to. Defaults to localhost.
            port: Port number to bind to. Defaults to 8080.
        """
        self.host = host
        self.port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._data = DashboardData()

        # Set data reference on handler class
        DashboardRequestHandler.dashboard_data = self._data

    def update_data(
        self,
        maturity: MaturityBreakdown | None = None,
        gaps: GapAnalysis | None = None,
        trends: TrendAnalysis | None = None,
        evidence_store: Any = None,
        organization_name: str | None = None,
    ) -> None:
        """
        Update dashboard data.

        Args:
            maturity: New maturity breakdown.
            gaps: New gap analysis.
            trends: New trend analysis.
            evidence_store: Reference to evidence store.
            organization_name: Organization name for display.
        """
        self._data.update(
            maturity=maturity,
            gaps=gaps,
            trends=trends,
            evidence_store=evidence_store,
            organization_name=organization_name,
        )

    def start(
        self,
        host: str | None = None,
        port: int | None = None,
        blocking: bool = False,
    ) -> bool:
        """
        Start the dashboard server.

        Args:
            host: Host address to bind to (overrides instance setting).
            port: Port number to bind to (overrides instance setting).
            blocking: If True, blocks until server is stopped.

        Returns:
            True if server started successfully, False otherwise.
        """
        if self._running:
            logger.warning("Dashboard server is already running")
            return True

        if host:
            self.host = host
        if port:
            self.port = port

        try:
            self._server = HTTPServer(
                (self.host, self.port),
                DashboardRequestHandler,
            )
            self._running = True

            logger.info(
                "Dashboard server starting at http://%s:%d",
                self.host,
                self.port,
            )

            if blocking:
                self._run_server()
            else:
                self._thread = threading.Thread(
                    target=self._run_server,
                    daemon=True,
                )
                self._thread.start()

            return True

        except OSError as e:
            logger.error("Failed to start dashboard server: %s", e)
            self._running = False
            return False

    def _run_server(self) -> None:
        """Run the server loop."""
        if self._server:
            try:
                self._server.serve_forever()
            except Exception as e:
                logger.error("Dashboard server error: %s", e)
            finally:
                self._running = False

    def stop(self) -> None:
        """Stop the dashboard server."""
        if not self._running:
            return

        logger.info("Stopping dashboard server")

        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

        self._running = False

    def is_running(self) -> bool:
        """
        Check if server is running.

        Returns:
            True if server is running, False otherwise.
        """
        return self._running

    def get_url(self) -> str:
        """
        Get the dashboard URL.

        Returns:
            URL string for the dashboard.
        """
        return f"http://{self.host}:{self.port}"

    def get_status(self) -> dict[str, Any]:
        """
        Get server status information.

        Returns:
            Dictionary with server status.
        """
        return {
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "url": self.get_url() if self._running else None,
            "has_data": self._data.maturity is not None,
            "last_updated": (
                self._data.last_updated.isoformat()
                if self._data.last_updated
                else None
            ),
        }


def find_available_port(start_port: int = DEFAULT_PORT, max_attempts: int = 10) -> int:
    """
    Find an available port starting from the given port.

    Args:
        start_port: Port number to start searching from.
        max_attempts: Maximum number of ports to try.

    Returns:
        An available port number.

    Raises:
        RuntimeError: If no available port is found.
    """
    for i in range(max_attempts):
        port = start_port + i
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((DEFAULT_HOST, port))
                return port
        except OSError:
            continue

    raise RuntimeError(
        f"No available port found in range {start_port}-{start_port + max_attempts - 1}"
    )
