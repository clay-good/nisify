"""
Notion collector for Nisify.

Collects security evidence from Notion including users, workspaces,
audit logs, and page access. All API calls are read-only.

Required Notion Permissions:
    - Read user information (for user directory)
    - Read content (for page inventory)

Authentication:
    Credentials are retrieved from the credential store with keys:
    - notion_api_token: Internal integration token (create at https://www.notion.so/my-integrations)

    Note: The integration must be added to workspaces/pages you want to access.

Rate Limiting:
    Notion API has rate limits (3 requests/second). This collector:
    - Uses conservative delays between requests
    - Implements exponential backoff on 429 responses
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import requests

from nisify.collectors.base import (
    AuthenticationError,
    BaseCollector,
    CollectionResult,
    CollectorConnectionError,
    CollectorRegistry,
    Evidence,
    RateLimitError,
)

if TYPE_CHECKING:
    from nisify.config.credentials import CredentialStore
    from nisify.config.settings import Settings


@CollectorRegistry.register
class NotionCollector(BaseCollector):
    """
    Notion evidence collector.

    Collects security-relevant evidence from Notion:
        - User directory (user_inventory)
        - Workspace databases (data_inventory)
        - Page access permissions (access_control)
        - Audit log (audit_logs) - Enterprise only

    Evidence Types Collected:
        - user_inventory: All users in the workspace
        - data_inventory: Databases and pages with sharing settings
        - access_control: Page/database permissions
        - audit_logs: Activity audit log (Enterprise feature)

    Example:
        collector = NotionCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "notion"
    default_rate_limit_delay = 0.35  # Stay under 3 req/sec

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Notion collector.

        Args:
            config: Settings object containing Notion configuration.
            credential_store: Credential store for retrieving Notion credentials.
        """
        super().__init__(config, credential_store)
        self._base_url = "https://api.notion.com/v1"
        self._session: requests.Session | None = None

    def _get_session(self) -> requests.Session:
        """
        Get or create a requests session with authentication.

        Returns:
            Configured requests.Session.

        Raises:
            AuthenticationError: If credentials are missing.
        """
        if self._session is not None:
            return self._session

        # Get credentials
        api_token = self.get_credential("notion_api_token")

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Notion-Version": "2022-06-28",
            }
        )

        return self._session

    def _api_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        """
        Make an API request to Notion.

        Args:
            method: HTTP method.
            endpoint: API endpoint path.
            params: Query parameters.
            json_data: JSON body for POST requests.

        Returns:
            Tuple of (response JSON, response headers).

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limit is exceeded.
            CollectorConnectionError: If connection fails.
        """
        session = self._get_session()
        url = f"{self._base_url}{endpoint}"

        start_time = time.time()
        self._rate_limit()

        try:
            response = session.request(
                method, url, params=params, json=json_data, timeout=30
            )
            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Notion rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else 1,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Notion authentication failed. Check your integration token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Notion permission denied. Ensure integration has access to the workspace.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}, dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Notion: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Notion request timed out: {e}",
                platform=self.platform,
            )

    def _paginate_post(
        self,
        endpoint: str,
        body: dict[str, Any] | None = None,
        results_key: str = "results",
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Notion API endpoint using POST.

        Notion uses start_cursor for pagination with POST requests.

        Args:
            endpoint: API endpoint path.
            body: Request body.
            results_key: Key in response containing results array.
            limit: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        body = body or {}
        body.setdefault("page_size", 100)

        start_cursor = None

        while True:
            if start_cursor:
                body["start_cursor"] = start_cursor

            data, _ = self._api_request("POST", endpoint, json_data=body)

            items = data.get(results_key, [])
            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page
            if not data.get("has_more"):
                break
            start_cursor = data.get("next_cursor")
            if not start_cursor:
                break

        return all_items

    def _paginate_get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "results",
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Notion API endpoint using GET.

        Args:
            endpoint: API endpoint path.
            params: Query parameters.
            results_key: Key in response containing results array.
            limit: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        params.setdefault("page_size", 100)

        start_cursor = None

        while True:
            if start_cursor:
                params["start_cursor"] = start_cursor

            data, _ = self._api_request("GET", endpoint, params=params)

            items = data.get(results_key, [])
            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page
            if not data.get("has_more"):
                break
            start_cursor = data.get("next_cursor")
            if not start_cursor:
                break

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Notion permission strings.
        """
        return [
            "Read user information",
            "Read content",
            "Integration added to workspace",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Notion.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/users/me")
            self.logger.info(
                f"Notion connection successful. Bot: {data.get('name')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Notion connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Notion.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        collectors = [
            ("user_inventory", self._collect_users),
            ("data_inventory", self._collect_databases),
            ("access_control", self._collect_permissions),
            ("audit_logs", self._collect_audit_logs),
        ]

        for evidence_type, collector_func in collectors:
            try:
                self.logger.info(f"Collecting {evidence_type}...")
                items = collector_func()
                evidence_items.extend(items)
                collected_types.append(evidence_type)
                self.logger.info(f"Collected {len(items)} items for {evidence_type}")
            except AuthenticationError:
                raise
            except Exception as e:
                self.logger.error(f"Failed to collect {evidence_type}: {e}")
                errors.append(f"{evidence_type}: {str(e)}")
                failed_types.append(evidence_type)

        duration = time.time() - start_time

        if len(errors) == 0:
            success = True
            partial = False
        elif len(collected_types) > 0:
            success = True
            partial = True
        else:
            success = False
            partial = False

        return CollectionResult(
            platform=self.platform,
            timestamp=datetime.now(UTC),
            success=success,
            evidence_items=evidence_items,
            errors=errors,
            duration_seconds=duration,
            partial=partial,
        )

    def _collect_users(self) -> list[Evidence]:
        """
        Collect user directory information.

        Returns:
            List of Evidence items with user inventory.
        """
        users = self._paginate_get("/users", results_key="results")

        user_data = []
        for user in users:
            user_type = user.get("type")
            if user_type == "person":
                person = user.get("person", {})
                user_data.append(
                    {
                        "id": user.get("id"),
                        "type": user_type,
                        "name": user.get("name"),
                        "email": person.get("email"),
                        "avatar_url": user.get("avatar_url"),
                    }
                )
            elif user_type == "bot":
                bot = user.get("bot", {})
                user_data.append(
                    {
                        "id": user.get("id"),
                        "type": user_type,
                        "name": user.get("name"),
                        "bot_owner_type": bot.get("owner", {}).get("type"),
                    }
                )

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": len(user_data),
                    "person_count": sum(1 for u in user_data if u.get("type") == "person"),
                    "bot_count": sum(1 for u in user_data if u.get("type") == "bot"),
                },
                "user_inventory",
                {"source": "notion_users"},
            )
        ]

    def _collect_databases(self) -> list[Evidence]:
        """
        Collect database inventory.

        Returns:
            List of Evidence items with data inventory.
        """
        # Search for all databases
        databases = self._paginate_post(
            "/search",
            {"filter": {"value": "database", "property": "object"}},
            limit=500,
        )

        db_data = []
        for db in databases:
            # Get database properties
            props = db.get("properties", {})
            title = ""
            for prop in db.get("title", []):
                if prop.get("type") == "text":
                    title += prop.get("text", {}).get("content", "")

            db_data.append(
                {
                    "id": db.get("id"),
                    "title": title,
                    "created_time": db.get("created_time"),
                    "last_edited_time": db.get("last_edited_time"),
                    "created_by": db.get("created_by", {}).get("id"),
                    "last_edited_by": db.get("last_edited_by", {}).get("id"),
                    "is_inline": db.get("is_inline"),
                    "property_count": len(props),
                    "property_names": list(props.keys())[:20],
                    "url": db.get("url"),
                    "public_url": db.get("public_url"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "databases": db_data,
                    "total_databases": len(db_data),
                    "publicly_shared": sum(1 for d in db_data if d.get("public_url")),
                },
                "data_inventory",
                {"source": "notion_databases"},
            )
        ]

    def _collect_permissions(self) -> list[Evidence]:
        """
        Collect page and database permissions.

        Returns:
            List of Evidence items with access control data.
        """
        # Search for pages and databases to analyze permissions
        all_items = self._paginate_post("/search", {}, limit=200)

        permission_data = []
        for item in all_items:
            item_type = item.get("object")
            item_id = item.get("id")

            # Get title
            title = ""
            if item_type == "page":
                props = item.get("properties", {})
                title_prop = props.get("title") or props.get("Name")
                if title_prop:
                    for t in title_prop.get("title", []):
                        title += t.get("plain_text", "")
            elif item_type == "database":
                for t in item.get("title", []):
                    title += t.get("plain_text", "")

            # Check sharing status
            is_public = item.get("public_url") is not None

            permission_data.append(
                {
                    "id": item_id,
                    "type": item_type,
                    "title": title[:100],  # Truncate long titles
                    "is_public": is_public,
                    "url": item.get("url"),
                    "created_time": item.get("created_time"),
                    "last_edited_time": item.get("last_edited_time"),
                    "parent_type": item.get("parent", {}).get("type"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "items": permission_data,
                    "total_items": len(permission_data),
                    "public_items": sum(1 for p in permission_data if p.get("is_public")),
                    "pages": sum(1 for p in permission_data if p.get("type") == "page"),
                    "databases": sum(1 for p in permission_data if p.get("type") == "database"),
                },
                "access_control",
                {"source": "notion_permissions"},
            )
        ]

    def _collect_audit_logs(self) -> list[Evidence]:
        """
        Collect audit logs (Enterprise feature).

        Note: This requires Notion Enterprise plan.

        Returns:
            List of Evidence items with audit logs.
        """
        # Audit logs are only available on Enterprise
        # Try to access them, fail gracefully if not available

        audit_data = []
        try:
            # The audit log endpoint requires Enterprise
            # This will likely fail on lower tiers
            data, _ = self._api_request(
                "POST",
                "/audit_log/query",
                json_data={
                    "start_time": (datetime.now(UTC) - timedelta(days=30)).isoformat(),
                    "page_size": 100,
                },
            )
            events = data.get("results", [])

            for event in events:
                audit_data.append(
                    {
                        "id": event.get("id"),
                        "timestamp": event.get("timestamp"),
                        "actor": event.get("actor", {}).get("person", {}).get("email"),
                        "action": event.get("action"),
                        "entity_type": event.get("entity", {}).get("type"),
                        "entity_id": event.get("entity", {}).get("id"),
                        "ip_address": event.get("ip_address"),
                    }
                )
        except Exception as e:
            self.logger.info(f"Audit logs not available (requires Enterprise): {e}")
            # Return empty but valid evidence
            return [
                self.normalize_evidence(
                    {
                        "events": [],
                        "total_events": 0,
                        "note": "Audit logs require Notion Enterprise plan",
                    },
                    "audit_logs",
                    {"source": "notion_audit_log"},
                )
            ]

        # Action breakdown
        action_counts: dict[str, int] = {}
        for event in audit_data:
            action = event.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": audit_data,
                    "total_events": len(audit_data),
                    "action_counts": action_counts,
                    "date_range_days": 30,
                },
                "audit_logs",
                {"source": "notion_audit_log"},
            )
        ]
