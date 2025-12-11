"""
Okta collector for Nisify.

Collects security evidence from Okta including users, MFA status, system logs,
security policies, and application assignments. All API calls are read-only.

Required Okta Permissions:
    - okta.users.read
    - okta.logs.read
    - okta.policies.read
    - okta.apps.read

Authentication:
    Credentials are retrieved from the credential store with keys:
    - okta_domain: Your Okta domain (e.g., "your-org.okta.com")
    - okta_api_token: API token with read permissions

    API tokens are created in the Okta Admin Console under:
    Security > API > Tokens

Rate Limiting:
    Okta enforces rate limits per API endpoint. This collector:
    - Checks X-Rate-Limit-Remaining headers
    - Respects X-Rate-Limit-Reset when limits are hit
    - Uses exponential backoff on 429 responses
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

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
class OktaCollector(BaseCollector):
    """
    Okta evidence collector.

    Collects security-relevant evidence from Okta:
        - User directory (user_inventory)
        - MFA enrollment status (mfa_status)
        - System log events (access_logs)
        - Security policies (security_policies)
        - Application assignments (access_assignments)

    Evidence Types Collected:
        - user_inventory: All active users with profile information
        - mfa_status: MFA enrollment status and factor types per user
        - access_logs: Authentication events from the system log (last 30 days)
        - security_policies: Password, sign-on, and MFA policies
        - access_assignments: User-to-application access mappings

    Example:
        collector = OktaCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "okta"
    default_rate_limit_delay = 0.1

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Okta collector.

        Args:
            config: Settings object containing Okta configuration.
            credential_store: Credential store for retrieving Okta credentials.
        """
        super().__init__(config, credential_store)
        self._domain: str | None = None
        self._api_token: str | None = None
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
        self._domain = self.get_credential("okta_domain")
        self._api_token = self.get_credential("okta_api_token")

        # Normalize domain
        domain = self._domain.strip()
        if domain.startswith("https://"):
            domain = domain[8:]
        if domain.startswith("http://"):
            domain = domain[7:]
        if domain.endswith("/"):
            domain = domain[:-1]

        self._base_url = f"https://{domain}"

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"SSWS {self._api_token}",
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
        Make an API request to Okta.

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
        if self._base_url is None:
            raise AuthenticationError("Not connected", platform=self.platform)
        url = urljoin(self._base_url + "/", endpoint.lstrip("/"))

        start_time = time.time()
        self._rate_limit()

        try:
            response = session.request(method, url, params=params, timeout=30)
            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            # Check for rate limiting
            remaining = response.headers.get("X-Rate-Limit-Remaining")
            if remaining and int(remaining) < 10:
                self.logger.warning(f"Rate limit low: {remaining} requests remaining")

            if response.status_code == 429:
                reset_time = response.headers.get("X-Rate-Limit-Reset")
                retry_after = None
                if reset_time:
                    retry_after = max(0, int(reset_time) - time.time())
                raise RateLimitError(
                    "Okta rate limit exceeded",
                    platform=self.platform,
                    retry_after=retry_after,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Okta authentication failed. Check your API token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Okta permission denied. Check API token scopes.",
                    platform=self.platform,
                )

            response.raise_for_status()
            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Okta: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Okta request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through an Okta API endpoint.

        Okta uses Link headers for pagination with rel="next".

        Args:
            endpoint: API endpoint path.
            params: Initial query parameters.
            limit: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        params.setdefault("limit", 200)  # Max per page

        next_url: str | None = endpoint

        while next_url:
            data, headers = self._api_request("GET", next_url, params if next_url == endpoint else None)

            if isinstance(data, list):
                all_items.extend(data)
            else:
                # Some endpoints return objects with embedded lists
                break

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page in Link header
            link_header = headers.get("Link", "")
            next_url = None
            for link in link_header.split(","):
                if 'rel="next"' in link:
                    # Extract URL from <url>
                    url_part = link.split(";")[0].strip()
                    if url_part.startswith("<") and url_part.endswith(">"):
                        next_url = url_part[1:-1]
                        # Convert to relative path
                        parsed = urlparse(next_url)
                        next_url = parsed.path
                        if parsed.query:
                            next_url += "?" + parsed.query
                    break

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Okta permission strings.
        """
        return [
            "okta.users.read",
            "okta.logs.read",
            "okta.policies.read",
            "okta.apps.read",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Okta.

        Attempts to fetch the current user to verify credentials.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/api/v1/users/me")
            self.logger.info(
                f"Okta connection successful. User: {data.get('profile', {}).get('email')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Okta connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Okta.

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
            ("mfa_status", self._collect_mfa_status),
            ("access_logs", self._collect_system_logs),
            ("security_policies", self._collect_policies),
            ("access_assignments", self._collect_app_assignments),
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
        users = self._paginate("/api/v1/users", {"filter": 'status eq "ACTIVE"'})

        user_data = []
        for user in users:
            profile = user.get("profile", {})
            user_data.append(
                {
                    "id": user.get("id"),
                    "status": user.get("status"),
                    "created": user.get("created"),
                    "activated": user.get("activated"),
                    "last_login": user.get("lastLogin"),
                    "last_updated": user.get("lastUpdated"),
                    "email": profile.get("email"),
                    "login": profile.get("login"),
                    "first_name": profile.get("firstName"),
                    "last_name": profile.get("lastName"),
                    "user_type": profile.get("userType"),
                    "department": profile.get("department"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": len(user_data),
                },
                "user_inventory",
                {"source": "okta_directory"},
            )
        ]

    def _collect_mfa_status(self) -> list[Evidence]:
        """
        Collect MFA enrollment status for all users.

        Returns:
            List of Evidence items with MFA status.
        """
        users = self._paginate("/api/v1/users", {"filter": 'status eq "ACTIVE"'})

        mfa_data = []
        for user in users:
            user_id = user.get("id")

            # Get enrolled factors for this user
            try:
                factors, _ = self._api_request("GET", f"/api/v1/users/{user_id}/factors")
            except Exception as e:
                self.logger.warning(f"Failed to get factors for user {user_id}: {e}")
                factors = []

            enrolled_factors = [
                {
                    "id": f.get("id"),
                    "factor_type": f.get("factorType"),
                    "provider": f.get("provider"),
                    "status": f.get("status"),
                    "created": f.get("created"),
                    "last_updated": f.get("lastUpdated"),
                }
                for f in factors
                if f.get("status") == "ACTIVE"
            ]

            mfa_data.append(
                {
                    "user_id": user_id,
                    "email": user.get("profile", {}).get("email"),
                    "mfa_enabled": len(enrolled_factors) > 0,
                    "factor_count": len(enrolled_factors),
                    "factors": enrolled_factors,
                }
            )

        # Calculate summary
        total_users = len(mfa_data)
        mfa_enabled = sum(1 for u in mfa_data if u["mfa_enabled"])

        return [
            self.normalize_evidence(
                {
                    "users": mfa_data,
                    "total_users": total_users,
                    "mfa_enabled_count": mfa_enabled,
                    "mfa_disabled_count": total_users - mfa_enabled,
                    "mfa_coverage_percent": (
                        (mfa_enabled / total_users * 100) if total_users > 0 else 0
                    ),
                },
                "mfa_status",
                {"source": "okta_factors"},
            )
        ]

    def _collect_system_logs(self) -> list[Evidence]:
        """
        Collect system log events (authentication events, admin actions).

        Returns:
            List of Evidence items with access logs.
        """
        # Get logs from the last 30 days
        since = (datetime.now(UTC) - timedelta(days=30)).isoformat()

        # Filter for security-relevant events
        event_types = [
            "user.session.start",
            "user.session.end",
            "user.authentication.sso",
            "user.authentication.auth_via_mfa",
            "user.authentication.auth_via_IDP",
            "user.mfa.factor.activate",
            "user.mfa.factor.deactivate",
            "user.account.lock",
            "user.account.unlock",
            "user.lifecycle.create",
            "user.lifecycle.deactivate",
            "user.lifecycle.suspend",
            "policy.lifecycle.create",
            "policy.lifecycle.update",
            "application.lifecycle.create",
            "application.user_membership.add",
            "application.user_membership.remove",
        ]

        all_events = []
        for event_type in event_types:
            try:
                events = self._paginate(
                    "/api/v1/logs",
                    {
                        "since": since,
                        "filter": f'eventType eq "{event_type}"',
                        "limit": 1000,
                    },
                    limit=1000,
                )
                all_events.extend(events)
            except Exception as e:
                self.logger.warning(f"Failed to get logs for {event_type}: {e}")

        # Normalize events
        log_data = []
        for event in all_events:
            actor = event.get("actor", {})
            target = event.get("target", [{}])[0] if event.get("target") else {}
            client = event.get("client", {})

            log_data.append(
                {
                    "uuid": event.get("uuid"),
                    "event_type": event.get("eventType"),
                    "display_message": event.get("displayMessage"),
                    "severity": event.get("severity"),
                    "outcome": event.get("outcome", {}).get("result"),
                    "outcome_reason": event.get("outcome", {}).get("reason"),
                    "published": event.get("published"),
                    "actor_id": actor.get("id"),
                    "actor_type": actor.get("type"),
                    "actor_display_name": actor.get("displayName"),
                    "target_id": target.get("id"),
                    "target_type": target.get("type"),
                    "target_display_name": target.get("displayName"),
                    "client_ip": client.get("ipAddress"),
                    "client_user_agent": client.get("userAgent", {}).get("rawUserAgent"),
                    "client_zone": client.get("zone"),
                }
            )

        # Calculate summary by event type
        event_counts: dict[str, int] = {}
        for event in log_data:
            et = event.get("event_type", "unknown")
            event_counts[et] = event_counts.get(et, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": log_data,
                    "total_events": len(log_data),
                    "event_type_counts": event_counts,
                    "date_range_days": 30,
                },
                "access_logs",
                {"source": "okta_system_log"},
            )
        ]

    def _collect_policies(self) -> list[Evidence]:
        """
        Collect security policies (password, sign-on, MFA).

        Returns:
            List of Evidence items with security policies.
        """
        policies_data: dict[str, Any] = {
            "password_policies": [],
            "sign_on_policies": [],
            "mfa_policies": [],
        }

        # Get password policies
        try:
            password_policies = self._paginate("/api/v1/policies?type=PASSWORD")
            for policy in password_policies:
                settings = policy.get("settings", {}).get("password", {})
                policies_data["password_policies"].append(
                    {
                        "id": policy.get("id"),
                        "name": policy.get("name"),
                        "status": policy.get("status"),
                        "priority": policy.get("priority"),
                        "min_length": settings.get("complexity", {}).get("minLength"),
                        "min_lowercase": settings.get("complexity", {}).get("minLowerCase"),
                        "min_uppercase": settings.get("complexity", {}).get("minUpperCase"),
                        "min_number": settings.get("complexity", {}).get("minNumber"),
                        "min_symbol": settings.get("complexity", {}).get("minSymbol"),
                        "exclude_username": settings.get("complexity", {}).get(
                            "excludeUsername"
                        ),
                        "max_age_days": settings.get("age", {}).get("maxAgeDays"),
                        "expire_warn_days": settings.get("age", {}).get("expireWarnDays"),
                        "history_count": settings.get("age", {}).get("historyCount"),
                        "lockout_attempts": settings.get("lockout", {}).get(
                            "maxAttempts"
                        ),
                        "lockout_duration_minutes": settings.get("lockout", {}).get(
                            "autoUnlockMinutes"
                        ),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get password policies: {e}")

        # Get sign-on policies
        try:
            sign_on_policies = self._paginate("/api/v1/policies?type=OKTA_SIGN_ON")
            for policy in sign_on_policies:
                policies_data["sign_on_policies"].append(
                    {
                        "id": policy.get("id"),
                        "name": policy.get("name"),
                        "status": policy.get("status"),
                        "priority": policy.get("priority"),
                        "description": policy.get("description"),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get sign-on policies: {e}")

        # Get MFA policies
        try:
            mfa_policies = self._paginate("/api/v1/policies?type=MFA_ENROLL")
            for policy in mfa_policies:
                settings = policy.get("settings", {})
                factors = settings.get("factors", {})
                policies_data["mfa_policies"].append(
                    {
                        "id": policy.get("id"),
                        "name": policy.get("name"),
                        "status": policy.get("status"),
                        "priority": policy.get("priority"),
                        "factors_configured": list(factors.keys()) if factors else [],
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get MFA policies: {e}")

        return [
            self.normalize_evidence(
                {
                    "password_policies": policies_data["password_policies"],
                    "sign_on_policies": policies_data["sign_on_policies"],
                    "mfa_policies": policies_data["mfa_policies"],
                    "total_password_policies": len(policies_data["password_policies"]),
                    "total_sign_on_policies": len(policies_data["sign_on_policies"]),
                    "total_mfa_policies": len(policies_data["mfa_policies"]),
                },
                "security_policies",
                {"source": "okta_policies"},
            )
        ]

    def _collect_app_assignments(self) -> list[Evidence]:
        """
        Collect application assignments (which users have access to which apps).

        Returns:
            List of Evidence items with access assignments.
        """
        # Get all applications
        apps = self._paginate("/api/v1/apps", {"filter": 'status eq "ACTIVE"'})

        app_assignments = []
        for app in apps:
            app_id = app.get("id")
            app_name = app.get("label") or app.get("name")

            # Get users assigned to this app
            try:
                users = self._paginate(f"/api/v1/apps/{app_id}/users", limit=500)
                user_count = len(users)
                user_ids = [u.get("id") for u in users[:100]]  # Limit stored IDs
            except Exception as e:
                self.logger.warning(f"Failed to get users for app {app_name}: {e}")
                user_count = -1
                user_ids = []

            # Get groups assigned to this app
            try:
                groups = self._paginate(f"/api/v1/apps/{app_id}/groups", limit=100)
                group_count = len(groups)
                group_names = [g.get("profile", {}).get("name") for g in groups[:20]]
            except Exception as e:
                self.logger.warning(f"Failed to get groups for app {app_name}: {e}")
                group_count = -1
                group_names = []

            app_assignments.append(
                {
                    "app_id": app_id,
                    "app_name": app_name,
                    "app_status": app.get("status"),
                    "sign_on_mode": app.get("signOnMode"),
                    "created": app.get("created"),
                    "assigned_user_count": user_count,
                    "assigned_group_count": group_count,
                    "sample_user_ids": user_ids,
                    "sample_group_names": group_names,
                }
            )

        return [
            self.normalize_evidence(
                {
                    "applications": app_assignments,
                    "total_applications": len(app_assignments),
                },
                "access_assignments",
                {"source": "okta_applications"},
            )
        ]
