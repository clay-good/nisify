"""
SpotDraft collector for Nisify.

Collects security evidence from SpotDraft including contracts, users,
templates, and audit logs. All API calls are read-only.

Required SpotDraft Permissions:
    - API access (contact SpotDraft for API enablement)
    - Read access to contracts and users

Authentication:
    Credentials are retrieved from the credential store with keys:
    - spotdraft_api_key: API key from SpotDraft settings
    - spotdraft_api_secret: API secret (if required)
    - spotdraft_subdomain: Your SpotDraft subdomain (e.g., "company" for company.spotdraft.com)

Rate Limiting:
    SpotDraft API has rate limits. This collector:
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
class SpotDraftCollector(BaseCollector):
    """
    SpotDraft evidence collector.

    Collects security-relevant evidence from SpotDraft:
        - User directory (user_inventory)
        - Contract inventory (contract_inventory)
        - Contract templates (template_inventory)
        - Audit/activity logs (audit_logs)

    Evidence Types Collected:
        - user_inventory: All users with roles and permissions
        - contract_inventory: Contracts with metadata and status
        - template_inventory: Contract templates
        - audit_logs: User activity and contract events

    Example:
        collector = SpotDraftCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "spotdraft"
    default_rate_limit_delay = 0.2

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the SpotDraft collector.

        Args:
            config: Settings object containing SpotDraft configuration.
            credential_store: Credential store for retrieving SpotDraft credentials.
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
        api_key = self.get_credential("spotdraft_api_key")

        # Try to get subdomain (optional)
        try:
            subdomain = self.get_credential("spotdraft_subdomain")
            self._base_url = f"https://{subdomain}.spotdraft.com/api/v1"
        except Exception:
            # Default to main API endpoint
            self._base_url = "https://api.spotdraft.com/v1"

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
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
        Make an API request to SpotDraft.

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
                    "SpotDraft rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else 60,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "SpotDraft authentication failed. Check your API key.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "SpotDraft permission denied. Check API key permissions.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}, dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to SpotDraft: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"SpotDraft request timed out: {e}",
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
        Paginate through a SpotDraft API endpoint.

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
        params.setdefault("page_size", 100)
        page = 1

        while True:
            params["page"] = page
            data, _ = self._api_request("GET", endpoint, params)

            # Find results
            if results_key and results_key in data:
                items = data[results_key]
            elif isinstance(data, list):
                items = data
            else:
                # Try common keys
                for key in ["data", "results", "items", "contracts", "users", "templates"]:
                    if key in data:
                        items = data[key]
                        break
                else:
                    items = []

            if not items:
                break

            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for more pages
            total = data.get("total") or data.get("total_count")
            if total and len(all_items) >= total:
                break

            if len(items) < params.get("page_size", 100):
                break

            page += 1

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of SpotDraft permission strings.
        """
        return [
            "API access enabled",
            "Read access to contracts",
            "Read access to users",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to SpotDraft.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            # Try to get current user or organization info
            data, _ = self._api_request("GET", "/me")
            self.logger.info(
                f"SpotDraft connection successful. User: {data.get('email', data.get('name', 'Unknown'))}"
            )
            return True
        except Exception as e:
            self.logger.error(f"SpotDraft connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from SpotDraft.

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
            ("contract_inventory", self._collect_contracts),
            ("template_inventory", self._collect_templates),
            ("audit_logs", self._collect_activity),
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
        users = self._paginate("/users", results_key="users")

        user_data = []
        for user in users:
            user_data.append(
                {
                    "id": user.get("id"),
                    "email": user.get("email"),
                    "name": user.get("name"),
                    "role": user.get("role"),
                    "status": user.get("status"),
                    "created_at": user.get("created_at"),
                    "last_login": user.get("last_login"),
                    "is_admin": user.get("is_admin"),
                    "department": user.get("department"),
                    "teams": user.get("teams", []),
                }
            )

        # Role breakdown
        role_counts: dict[str, int] = {}
        for user in user_data:
            role = user.get("role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": len(user_data),
                    "role_counts": role_counts,
                    "admin_count": sum(1 for u in user_data if u.get("is_admin")),
                },
                "user_inventory",
                {"source": "spotdraft_users"},
            )
        ]

    def _collect_contracts(self) -> list[Evidence]:
        """
        Collect contract inventory.

        Returns:
            List of Evidence items with contract inventory.
        """
        contracts = self._paginate("/contracts", results_key="contracts", limit=500)

        contract_data = []
        for contract in contracts:
            contract_data.append(
                {
                    "id": contract.get("id"),
                    "title": contract.get("title"),
                    "status": contract.get("status"),
                    "type": contract.get("type") or contract.get("contract_type"),
                    "created_at": contract.get("created_at"),
                    "updated_at": contract.get("updated_at"),
                    "effective_date": contract.get("effective_date"),
                    "expiration_date": contract.get("expiration_date"),
                    "owner_id": contract.get("owner_id") or contract.get("owner", {}).get("id"),
                    "owner_email": contract.get("owner", {}).get("email"),
                    "counterparty": contract.get("counterparty"),
                    "value": contract.get("value"),
                    "currency": contract.get("currency"),
                }
            )

        # Status breakdown
        status_counts: dict[str, int] = {}
        for contract in contract_data:
            status = contract.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        # Check for expiring contracts
        now = datetime.now(UTC)
        expiring_soon = []
        for contract in contract_data:
            exp_date = contract.get("expiration_date")
            if exp_date:
                try:
                    exp = datetime.fromisoformat(exp_date.replace("Z", "+00:00"))
                    if now < exp < now + timedelta(days=90):
                        expiring_soon.append(contract)
                except Exception:
                    pass

        return [
            self.normalize_evidence(
                {
                    "contracts": contract_data,
                    "total_contracts": len(contract_data),
                    "status_counts": status_counts,
                    "expiring_within_90_days": len(expiring_soon),
                },
                "contract_inventory",
                {"source": "spotdraft_contracts"},
            )
        ]

    def _collect_templates(self) -> list[Evidence]:
        """
        Collect contract templates.

        Returns:
            List of Evidence items with template inventory.
        """
        templates = self._paginate("/templates", results_key="templates")

        template_data = []
        for template in templates:
            template_data.append(
                {
                    "id": template.get("id"),
                    "name": template.get("name"),
                    "description": template.get("description"),
                    "status": template.get("status"),
                    "category": template.get("category"),
                    "created_at": template.get("created_at"),
                    "updated_at": template.get("updated_at"),
                    "created_by": template.get("created_by"),
                    "version": template.get("version"),
                    "usage_count": template.get("usage_count"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "templates": template_data,
                    "total_templates": len(template_data),
                    "active_templates": sum(1 for t in template_data if t.get("status") == "active"),
                },
                "template_inventory",
                {"source": "spotdraft_templates"},
            )
        ]

    def _collect_activity(self) -> list[Evidence]:
        """
        Collect activity/audit logs.

        Returns:
            List of Evidence items with audit logs.
        """
        # Get activity from last 30 days
        since = (datetime.now(UTC) - timedelta(days=30)).isoformat()

        activities = self._paginate(
            "/activity",
            {"since": since},
            results_key="activities",
            limit=1000,
        )

        activity_data = []
        for activity in activities:
            activity_data.append(
                {
                    "id": activity.get("id"),
                    "action": activity.get("action"),
                    "actor_id": activity.get("actor_id") or activity.get("user_id"),
                    "actor_email": activity.get("actor_email") or activity.get("user", {}).get("email"),
                    "resource_type": activity.get("resource_type"),
                    "resource_id": activity.get("resource_id"),
                    "resource_name": activity.get("resource_name"),
                    "timestamp": activity.get("timestamp") or activity.get("created_at"),
                    "ip_address": activity.get("ip_address"),
                    "details": activity.get("details"),
                }
            )

        # Action breakdown
        action_counts: dict[str, int] = {}
        for activity in activity_data:
            action = activity.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "activities": activity_data,
                    "total_activities": len(activity_data),
                    "action_counts": action_counts,
                    "date_range_days": 30,
                },
                "audit_logs",
                {"source": "spotdraft_activity"},
            )
        ]
