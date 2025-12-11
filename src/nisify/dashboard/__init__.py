"""
Local web dashboard for compliance visualization.

A read-only web interface served locally using Python's built-in
http.server module. No external frameworks or CDN dependencies.

Features:
    - Overall maturity score display
    - Function-level score visualization
    - Gap analysis browser
    - Evidence explorer
    - Historical trend charts

Security:
    - Binds to localhost only by default
    - No external resource loading (fully offline)
    - CORS disabled
    - All data is read-only

Example:
    from nisify.dashboard import DashboardServer

    # Create server
    server = DashboardServer(host="127.0.0.1", port=8080)

    # Update data
    server.update_data(
        maturity=maturity_breakdown,
        gaps=gap_analysis,
        trends=trend_analysis,
        organization_name="Acme Corp"
    )

    # Start server (non-blocking)
    server.start()

    # Check status
    print(f"Dashboard: {server.get_url()}")

    # Stop server
    server.stop()
"""

from nisify.dashboard.routes import (
    API_ROUTES,
    RouteContext,
    get_route_handler,
    handle_api_categories,
    handle_api_controls,
    handle_api_evidence,
    handle_api_functions,
    handle_api_gaps,
    handle_api_health,
    handle_api_maturity,
    handle_api_subcategories,
    handle_api_summary,
    handle_api_trends,
    list_routes,
)
from nisify.dashboard.server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DashboardData,
    DashboardRequestHandler,
    DashboardServer,
    find_available_port,
)

__all__ = [
    # Server
    "DashboardServer",
    "DashboardData",
    "DashboardRequestHandler",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "find_available_port",
    # Routes
    "RouteContext",
    "API_ROUTES",
    "get_route_handler",
    "list_routes",
    # Route handlers
    "handle_api_summary",
    "handle_api_maturity",
    "handle_api_gaps",
    "handle_api_evidence",
    "handle_api_trends",
    "handle_api_functions",
    "handle_api_categories",
    "handle_api_subcategories",
    "handle_api_health",
    "handle_api_controls",
]
