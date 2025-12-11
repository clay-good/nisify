"""
Zendesk collector for Nisify.

Collects security evidence from Zendesk including users, audit logs,
security settings, and ticket data for compliance tracking. All API calls are read-only.

Required Zendesk Permissions:
    - Admin access (for audit logs and security settings)
    - Agent access (for tickets and users)

Authentication:
    Credentials are retrieved from the credential store with keys:
    - zendesk_subdomain: Your Zendesk subdomain (e.g., "your-company" for your-company.zendesk.com)
    - zendesk_email: Admin/agent email address
    - zendesk_api_token: API token (Admin > Channels > API)

Rate Limiting:
    Zendesk enforces rate limits (400 requests/min for most plans). This collector:
    - Checks Retry-After headers
    - Uses exponential backoff on 429 responses
"""

from __future__ import annotations

import base64
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
class ZendeskCollector(BaseCollector):
    """
    Zendesk evidence collector.

    Collects security-relevant evidence from Zendesk:
        - User directory (user_inventory)
        - Audit logs (audit_logs)
        - Security settings (security_config)
        - Support tickets (incident_tracking)
        - Groups and roles (access_control)

    Evidence Types Collected:
        - user_inventory: All agents and admins with access information
        - audit_logs: Account audit events (last 30 days)
        - security_config: Security and authentication settings
        - incident_tracking: Security/compliance-tagged tickets
        - access_control: Groups, roles, and permissions

    Example:
        collector = ZendeskCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "zendesk"
    default_rate_limit_delay = 0.15

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Zendesk collector.

        Args:
            config: Settings object containing Zendesk configuration.
            credential_store: Credential store for retrieving Zendesk credentials.
        """
        super().__init__(config, credential_store)
        self._base_url: str | None = None
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
        subdomain = self.get_credential("zendesk_subdomain")
        email = self.get_credential("zendesk_email")
        api_token = self.get_credential("zendesk_api_token")

        # Normalize subdomain
        subdomain = subdomain.strip()
        if ".zendesk.com" in subdomain:
            subdomain = subdomain.split(".")[0]

        self._base_url = f"https://{subdomain}.zendesk.com"

        # Create basic auth header (email/token format)
        auth_string = f"{email}/token:{api_token}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Basic {auth_bytes}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        return self._session

    def _api_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        """
        Make an API request to Zendesk.

        Args:
            method: HTTP method.
            endpoint: API endpoint path.
            params: Query parameters.

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
            response = session.request(method, url, params=params, timeout=30)
            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Zendesk rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else 60,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Zendesk authentication failed. Check email and API token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Zendesk permission denied. Check account permissions.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}, dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Zendesk: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Zendesk request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Zendesk API endpoint.

        Zendesk uses next_page URL for pagination.

        Args:
            endpoint: API endpoint path.
            params: Initial query parameters.
            results_key: Key in response containing results array.
            limit: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        params.setdefault("per_page", 100)

        next_url: str | None = endpoint

        while next_url:
            if next_url.startswith("http"):
                # Full URL from next_page
                session = self._get_session()
                response = session.get(next_url, timeout=30)
                response.raise_for_status()
                data = response.json()
                headers = dict(response.headers)
            else:
                data, headers = self._api_request("GET", next_url, params if next_url == endpoint else None)

            # Find results in response
            if results_key and results_key in data:
                items = data[results_key]
            else:
                # Try to find the main array (users, tickets, etc.)
                for key in ["users", "tickets", "audit_logs", "groups", "organizations", "results"]:
                    if key in data:
                        items = data[key]
                        break
                else:
                    items = []

            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page
            next_url = data.get("next_page")

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Zendesk permission strings.
        """
        return [
            "Admin (for audit logs)",
            "Agent (for tickets and users)",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Zendesk.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/api/v2/users/me.json")
            user = data.get("user", {})
            self.logger.info(
                f"Zendesk connection successful. User: {user.get('name')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Zendesk connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Zendesk.

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
            ("audit_logs", self._collect_audit_logs),
            ("security_config", self._collect_security_settings),
            ("incident_tracking", self._collect_tickets),
            ("access_control", self._collect_groups_and_roles),
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
        # Get all users (agents and admins)
        users = self._paginate("/api/v2/users.json", {"role[]": ["admin", "agent"]})

        user_data = []
        for user in users:
            user_data.append(
                {
                    "id": user.get("id"),
                    "name": user.get("name"),
                    "email": user.get("email"),
                    "role": user.get("role"),
                    "role_type": user.get("role_type"),
                    "active": user.get("active"),
                    "verified": user.get("verified"),
                    "suspended": user.get("suspended"),
                    "two_factor_auth_enabled": user.get("two_factor_auth_enabled"),
                    "created_at": user.get("created_at"),
                    "updated_at": user.get("updated_at"),
                    "last_login_at": user.get("last_login_at"),
                    "default_group_id": user.get("default_group_id"),
                    "custom_role_id": user.get("custom_role_id"),
                }
            )

        # Calculate stats
        total_users = len(user_data)
        two_fa_enabled = sum(1 for u in user_data if u.get("two_factor_auth_enabled"))

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": total_users,
                    "admins": sum(1 for u in user_data if u.get("role") == "admin"),
                    "agents": sum(1 for u in user_data if u.get("role") == "agent"),
                    "two_factor_enabled": two_fa_enabled,
                    "two_factor_disabled": total_users - two_fa_enabled,
                    "suspended_users": sum(1 for u in user_data if u.get("suspended")),
                },
                "user_inventory",
                {"source": "zendesk_users"},
            )
        ]

    def _collect_audit_logs(self) -> list[Evidence]:
        """
        Collect audit logs (requires admin).

        Returns:
            List of Evidence items with audit logs.
        """
        # Get audit logs from last 30 days
        since = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

        audit_logs = []
        try:
            # Audit logs endpoint
            logs = self._paginate(
                "/api/v2/audit_logs.json",
                {"filter[created_at][]": since},
                results_key="audit_logs",
                limit=1000,
            )
            audit_logs.extend(logs)
        except Exception as e:
            self.logger.warning(f"Could not fetch audit logs: {e}")

        event_data = []
        for log in audit_logs:
            event_data.append(
                {
                    "id": log.get("id"),
                    "action": log.get("action"),
                    "action_label": log.get("action_label"),
                    "actor_id": log.get("actor_id"),
                    "actor_name": log.get("actor_name"),
                    "source_id": log.get("source_id"),
                    "source_type": log.get("source_type"),
                    "source_label": log.get("source_label"),
                    "ip_address": log.get("ip_address"),
                    "created_at": log.get("created_at"),
                    "change_description": log.get("change_description"),
                }
            )

        # Action breakdown
        action_counts: dict[str, int] = {}
        for event in event_data:
            action = event.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": event_data,
                    "total_events": len(event_data),
                    "action_counts": action_counts,
                    "date_range_days": 30,
                },
                "audit_logs",
                {"source": "zendesk_audit_logs"},
            )
        ]

    def _collect_security_settings(self) -> list[Evidence]:
        """
        Collect security and authentication settings.

        Returns:
            List of Evidence items with security configuration.
        """
        security_data: dict[str, Any] = {
            "account_settings": {},
            "authentication": {},
        }

        # Get account settings
        try:
            data, _ = self._api_request("GET", "/api/v2/account/settings.json")
            settings = data.get("settings", {})

            security_data["account_settings"] = {
                "active_features": settings.get("active_features", {}),
                "agents_can_delete_tickets": settings.get("agents", {}).get("can_delete_tickets"),
                "agents_can_edit_profile": settings.get("agents", {}).get("can_edit_profile"),
            }

            # Security-specific settings
            security = settings.get("security", {})
            security_data["authentication"] = {
                "require_two_factor_auth": security.get("require_two_factor_auth"),
                "password_requirements": security.get("password_requirements"),
                "sso_enabled": settings.get("sso", {}).get("enabled"),
                "sso_method": settings.get("sso", {}).get("method"),
            }
        except Exception as e:
            self.logger.warning(f"Failed to get account settings: {e}")

        return [
            self.normalize_evidence(
                {
                    "account_settings": security_data["account_settings"],
                    "authentication": security_data["authentication"],
                },
                "security_config",
                {"source": "zendesk_settings"},
            )
        ]

    def _collect_tickets(self) -> list[Evidence]:
        """
        Collect security/compliance-related tickets.

        Returns:
            List of Evidence items with incident tracking data.
        """
        # Search for security-related tickets
        search_queries = [
            "tags:security",
            "tags:compliance",
            "tags:incident",
            "tags:data-breach",
            "tags:privacy",
        ]

        all_tickets = []
        seen_ids = set()

        for query in search_queries:
            try:
                data, _ = self._api_request(
                    "GET",
                    "/api/v2/search.json",
                    {"query": f"type:ticket {query}", "sort_by": "created_at", "sort_order": "desc"},
                )
                tickets = data.get("results", [])
                for ticket in tickets:
                    if ticket.get("id") not in seen_ids:
                        seen_ids.add(ticket.get("id"))
                        all_tickets.append(ticket)
            except Exception as e:
                self.logger.warning(f"Failed to search tickets with query '{query}': {e}")

        ticket_data = []
        for ticket in all_tickets[:200]:  # Limit to 200 tickets
            ticket_data.append(
                {
                    "id": ticket.get("id"),
                    "subject": ticket.get("subject"),
                    "status": ticket.get("status"),
                    "priority": ticket.get("priority"),
                    "type": ticket.get("type"),
                    "created_at": ticket.get("created_at"),
                    "updated_at": ticket.get("updated_at"),
                    "requester_id": ticket.get("requester_id"),
                    "assignee_id": ticket.get("assignee_id"),
                    "group_id": ticket.get("group_id"),
                    "tags": ticket.get("tags", []),
                    "satisfaction_rating": ticket.get("satisfaction_rating"),
                }
            )

        # Status breakdown
        status_counts: dict[str, int] = {}
        for ticket in ticket_data:
            status = ticket.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "tickets": ticket_data,
                    "total_tickets": len(ticket_data),
                    "status_counts": status_counts,
                    "open_tickets": sum(1 for t in ticket_data if t.get("status") in ["new", "open", "pending"]),
                },
                "incident_tracking",
                {"source": "zendesk_tickets"},
            )
        ]

    def _collect_groups_and_roles(self) -> list[Evidence]:
        """
        Collect groups, custom roles, and permissions.

        Returns:
            List of Evidence items with access control data.
        """
        access_data: dict[str, Any] = {
            "groups": [],
            "custom_roles": [],
        }

        # Get groups
        try:
            groups = self._paginate("/api/v2/groups.json", results_key="groups")
            for group in groups:
                access_data["groups"].append(
                    {
                        "id": group.get("id"),
                        "name": group.get("name"),
                        "description": group.get("description"),
                        "default": group.get("default"),
                        "deleted": group.get("deleted"),
                        "created_at": group.get("created_at"),
                        "updated_at": group.get("updated_at"),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get groups: {e}")

        # Get custom roles
        try:
            data, _ = self._api_request("GET", "/api/v2/custom_roles.json")
            roles = data.get("custom_roles", [])
            for role in roles:
                access_data["custom_roles"].append(
                    {
                        "id": role.get("id"),
                        "name": role.get("name"),
                        "description": role.get("description"),
                        "role_type": role.get("role_type"),
                        "created_at": role.get("created_at"),
                        "updated_at": role.get("updated_at"),
                        "configuration": role.get("configuration"),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get custom roles: {e}")

        return [
            self.normalize_evidence(
                {
                    "groups": access_data["groups"],
                    "custom_roles": access_data["custom_roles"],
                    "total_groups": len(access_data["groups"]),
                    "total_custom_roles": len(access_data["custom_roles"]),
                },
                "access_control",
                {"source": "zendesk_groups_roles"},
            )
        ]
