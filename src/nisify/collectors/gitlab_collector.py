"""
GitLab collector for Nisify.

Collects security evidence from GitLab including projects, users, audit events,
merge request approvals, protected branches, and access tokens. All API calls are read-only.

Required GitLab Permissions:
    - api (full API access) or read_api (read-only)
    - read_user (for user information)
    - read_repository (for project/branch info)

Authentication:
    Credentials are retrieved from the credential store with keys:
    - gitlab_url: GitLab instance URL (e.g., "https://gitlab.com" or self-hosted)
    - gitlab_token: Personal access token or group/project access token

Rate Limiting:
    GitLab.com enforces rate limits. This collector:
    - Checks RateLimit-Remaining headers
    - Respects RateLimit-Reset when limits are hit
    - Uses exponential backoff on 429 responses
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

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
class GitLabCollector(BaseCollector):
    """
    GitLab evidence collector.

    Collects security-relevant evidence from GitLab:
        - Project inventory (project_inventory)
        - User directory (user_inventory)
        - Audit events (audit_logs)
        - Merge request settings (change_management)
        - Protected branches (branch_protection)
        - Access tokens (access_tokens)

    Evidence Types Collected:
        - project_inventory: All accessible projects with security settings
        - user_inventory: Users with access levels and activity
        - audit_logs: Security-relevant audit events (last 30 days)
        - change_management: MR approval rules and settings
        - branch_protection: Protected branch configurations
        - access_tokens: Project and group access tokens

    Example:
        collector = GitLabCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "gitlab"
    default_rate_limit_delay = 0.05

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the GitLab collector.

        Args:
            config: Settings object containing GitLab configuration.
            credential_store: Credential store for retrieving GitLab credentials.
        """
        super().__init__(config, credential_store)
        self._base_url: str | None = None
        self._token: str | None = None
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
        gitlab_url = self.get_credential("gitlab_url")
        self._token = self.get_credential("gitlab_token")

        # Normalize URL
        url = gitlab_url.strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        if url.endswith("/"):
            url = url[:-1]
        self._base_url = url

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "PRIVATE-TOKEN": self._token,
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
        Make an API request to GitLab.

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
            remaining = response.headers.get("RateLimit-Remaining")
            if remaining and int(remaining) < 10:
                self.logger.warning(f"Rate limit low: {remaining} requests remaining")

            if response.status_code == 429:
                reset_time = response.headers.get("RateLimit-Reset")
                retry_after = None
                if reset_time:
                    retry_after = max(0, int(reset_time) - time.time())
                raise RateLimitError(
                    "GitLab rate limit exceeded",
                    platform=self.platform,
                    retry_after=retry_after,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "GitLab authentication failed. Check your access token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "GitLab permission denied. Check token scopes.",
                    platform=self.platform,
                )

            response.raise_for_status()

            # Handle empty responses
            if response.status_code == 204 or not response.content:
                return [], dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to GitLab: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"GitLab request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a GitLab API endpoint.

        GitLab uses X-Next-Page header for pagination.

        Args:
            endpoint: API endpoint path.
            params: Initial query parameters.
            limit: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        params.setdefault("per_page", 100)
        page = 1

        while True:
            params["page"] = page
            data, headers = self._api_request("GET", endpoint, params)

            if isinstance(data, list):
                all_items.extend(data)
            else:
                break

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page
            next_page = headers.get("X-Next-Page")
            if not next_page:
                break
            page = int(next_page)

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of GitLab permission strings.
        """
        return [
            "api or read_api",
            "read_user",
            "read_repository",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to GitLab.

        Attempts to fetch current user to verify credentials.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/api/v4/user")
            self.logger.info(
                f"GitLab connection successful. User: {data.get('username')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"GitLab connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from GitLab.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        collectors = [
            ("project_inventory", self._collect_projects),
            ("user_inventory", self._collect_users),
            ("audit_logs", self._collect_audit_events),
            ("change_management", self._collect_merge_request_settings),
            ("branch_protection", self._collect_protected_branches),
            ("access_tokens", self._collect_access_tokens),
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

    def _collect_projects(self) -> list[Evidence]:
        """
        Collect project inventory with security settings.

        Returns:
            List of Evidence items with project inventory.
        """
        projects = self._paginate(
            "/api/v4/projects",
            {"membership": "true", "with_security_reports": "true"},
        )

        project_data = []
        for project in projects:
            project_data.append(
                {
                    "id": project.get("id"),
                    "name": project.get("name"),
                    "path_with_namespace": project.get("path_with_namespace"),
                    "visibility": project.get("visibility"),
                    "created_at": project.get("created_at"),
                    "last_activity_at": project.get("last_activity_at"),
                    "default_branch": project.get("default_branch"),
                    "archived": project.get("archived"),
                    "issues_enabled": project.get("issues_enabled"),
                    "merge_requests_enabled": project.get("merge_requests_enabled"),
                    "wiki_enabled": project.get("wiki_enabled"),
                    "snippets_enabled": project.get("snippets_enabled"),
                    "container_registry_enabled": project.get("container_registry_enabled"),
                    "only_allow_merge_if_pipeline_succeeds": project.get(
                        "only_allow_merge_if_pipeline_succeeds"
                    ),
                    "only_allow_merge_if_all_discussions_resolved": project.get(
                        "only_allow_merge_if_all_discussions_are_resolved"
                    ),
                    "remove_source_branch_after_merge": project.get(
                        "remove_source_branch_after_merge"
                    ),
                    "request_access_enabled": project.get("request_access_enabled"),
                    "approvals_before_merge": project.get("approvals_before_merge"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "projects": project_data,
                    "total_projects": len(project_data),
                    "visibility_breakdown": {
                        "public": sum(1 for p in project_data if p["visibility"] == "public"),
                        "internal": sum(1 for p in project_data if p["visibility"] == "internal"),
                        "private": sum(1 for p in project_data if p["visibility"] == "private"),
                    },
                },
                "project_inventory",
                {"source": "gitlab_projects"},
            )
        ]

    def _collect_users(self) -> list[Evidence]:
        """
        Collect user directory information.

        Returns:
            List of Evidence items with user inventory.
        """
        users = self._paginate("/api/v4/users", {"active": "true"})

        user_data = []
        for user in users:
            user_data.append(
                {
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "name": user.get("name"),
                    "state": user.get("state"),
                    "email": user.get("email"),
                    "is_admin": user.get("is_admin"),
                    "two_factor_enabled": user.get("two_factor_enabled"),
                    "created_at": user.get("created_at"),
                    "last_sign_in_at": user.get("last_sign_in_at"),
                    "last_activity_on": user.get("last_activity_on"),
                    "external": user.get("external"),
                    "bot": user.get("bot"),
                }
            )

        # Calculate 2FA stats
        total_users = len(user_data)
        two_fa_enabled = sum(1 for u in user_data if u.get("two_factor_enabled"))

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": total_users,
                    "two_factor_enabled_count": two_fa_enabled,
                    "two_factor_disabled_count": total_users - two_fa_enabled,
                    "admin_count": sum(1 for u in user_data if u.get("is_admin")),
                },
                "user_inventory",
                {"source": "gitlab_users"},
            )
        ]

    def _collect_audit_events(self) -> list[Evidence]:
        """
        Collect audit events (requires Premium/Ultimate).

        Returns:
            List of Evidence items with audit logs.
        """
        # Get audit events from the last 30 days
        since = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%d")

        audit_events = []
        try:
            # Try instance-level audit events first (admin only)
            events = self._paginate(
                "/api/v4/audit_events",
                {"created_after": since},
                limit=1000,
            )
            audit_events.extend(events)
        except Exception:
            # Fall back to group-level audit events
            try:
                groups = self._paginate("/api/v4/groups", {"min_access_level": 30})
                for group in groups[:10]:  # Limit to first 10 groups
                    try:
                        events = self._paginate(
                            f"/api/v4/groups/{group['id']}/audit_events",
                            {"created_after": since},
                            limit=200,
                        )
                        audit_events.extend(events)
                    except Exception as e:
                        self.logger.warning(f"Failed to get audit events for group {group['id']}: {e}")
            except Exception as e:
                self.logger.warning(f"Failed to get groups for audit events: {e}")

        # Normalize events
        event_data = []
        for event in audit_events:
            event_data.append(
                {
                    "id": event.get("id"),
                    "author_id": event.get("author_id"),
                    "entity_id": event.get("entity_id"),
                    "entity_type": event.get("entity_type"),
                    "entity_path": event.get("entity_path"),
                    "target_id": event.get("target_id"),
                    "target_type": event.get("target_type"),
                    "target_details": event.get("target_details"),
                    "action": event.get("details", {}).get("custom_message")
                    or event.get("details", {}).get("action"),
                    "ip_address": event.get("details", {}).get("ip_address"),
                    "created_at": event.get("created_at"),
                }
            )

        # Calculate action breakdown
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
                {"source": "gitlab_audit_events"},
            )
        ]

    def _collect_merge_request_settings(self) -> list[Evidence]:
        """
        Collect merge request approval settings per project.

        Returns:
            List of Evidence items with change management settings.
        """
        projects = self._paginate(
            "/api/v4/projects",
            {"membership": "true"},
            limit=100,
        )

        mr_settings = []
        for project in projects:
            project_id = project.get("id")
            project_name = project.get("path_with_namespace")

            settings = {
                "project_id": project_id,
                "project_name": project_name,
                "merge_method": project.get("merge_method"),
                "squash_option": project.get("squash_option"),
                "only_allow_merge_if_pipeline_succeeds": project.get(
                    "only_allow_merge_if_pipeline_succeeds"
                ),
                "only_allow_merge_if_all_discussions_resolved": project.get(
                    "only_allow_merge_if_all_discussions_are_resolved"
                ),
                "remove_source_branch_after_merge": project.get(
                    "remove_source_branch_after_merge"
                ),
                "approvals_before_merge": project.get("approvals_before_merge"),
            }

            # Try to get approval rules (Premium feature)
            try:
                rules, _ = self._api_request(
                    "GET", f"/api/v4/projects/{project_id}/approval_rules"
                )
                settings["approval_rules"] = [
                    {
                        "id": r.get("id"),
                        "name": r.get("name"),
                        "approvals_required": r.get("approvals_required"),
                        "rule_type": r.get("rule_type"),
                    }
                    for r in rules
                ]
            except Exception:
                settings["approval_rules"] = []

            mr_settings.append(settings)

        return [
            self.normalize_evidence(
                {
                    "projects": mr_settings,
                    "total_projects": len(mr_settings),
                    "projects_requiring_approvals": sum(
                        1 for p in mr_settings if (p.get("approvals_before_merge") or 0) > 0
                    ),
                    "projects_requiring_pipeline_success": sum(
                        1 for p in mr_settings if p.get("only_allow_merge_if_pipeline_succeeds")
                    ),
                },
                "change_management",
                {"source": "gitlab_merge_request_settings"},
            )
        ]

    def _collect_protected_branches(self) -> list[Evidence]:
        """
        Collect protected branch configurations.

        Returns:
            List of Evidence items with branch protection settings.
        """
        projects = self._paginate(
            "/api/v4/projects",
            {"membership": "true"},
            limit=100,
        )

        branch_data = []
        for project in projects:
            project_id = project.get("id")
            project_name = project.get("path_with_namespace")

            try:
                branches = self._paginate(
                    f"/api/v4/projects/{project_id}/protected_branches"
                )
                for branch in branches:
                    branch_data.append(
                        {
                            "project_id": project_id,
                            "project_name": project_name,
                            "branch_name": branch.get("name"),
                            "push_access_levels": [
                                {"access_level": level.get("access_level"), "access_level_description": level.get("access_level_description")}
                                for level in branch.get("push_access_levels", [])
                            ],
                            "merge_access_levels": [
                                {"access_level": level.get("access_level"), "access_level_description": level.get("access_level_description")}
                                for level in branch.get("merge_access_levels", [])
                            ],
                            "allow_force_push": branch.get("allow_force_push"),
                            "code_owner_approval_required": branch.get(
                                "code_owner_approval_required"
                            ),
                        }
                    )
            except Exception as e:
                self.logger.warning(f"Failed to get protected branches for {project_name}: {e}")

        return [
            self.normalize_evidence(
                {
                    "protected_branches": branch_data,
                    "total_protected_branches": len(branch_data),
                    "projects_with_protection": len(
                        {b["project_id"] for b in branch_data}
                    ),
                },
                "branch_protection",
                {"source": "gitlab_protected_branches"},
            )
        ]

    def _collect_access_tokens(self) -> list[Evidence]:
        """
        Collect project and group access tokens.

        Returns:
            List of Evidence items with access token information.
        """
        tokens_data = []

        # Get project access tokens
        projects = self._paginate(
            "/api/v4/projects",
            {"membership": "true"},
            limit=50,
        )

        for project in projects:
            project_id = project.get("id")
            project_name = project.get("path_with_namespace")

            try:
                tokens, _ = self._api_request(
                    "GET", f"/api/v4/projects/{project_id}/access_tokens"
                )
                for token in tokens:
                    tokens_data.append(
                        {
                            "type": "project",
                            "entity_id": project_id,
                            "entity_name": project_name,
                            "token_id": token.get("id"),
                            "name": token.get("name"),
                            "active": token.get("active"),
                            "revoked": token.get("revoked"),
                            "created_at": token.get("created_at"),
                            "expires_at": token.get("expires_at"),
                            "scopes": token.get("scopes"),
                            "access_level": token.get("access_level"),
                        }
                    )
            except Exception:
                # May not have permission to view tokens
                pass

        # Get group access tokens
        groups = self._paginate("/api/v4/groups", {"min_access_level": 40}, limit=20)

        for group in groups:
            group_id = group.get("id")
            group_name = group.get("full_path")

            try:
                tokens, _ = self._api_request(
                    "GET", f"/api/v4/groups/{group_id}/access_tokens"
                )
                for token in tokens:
                    tokens_data.append(
                        {
                            "type": "group",
                            "entity_id": group_id,
                            "entity_name": group_name,
                            "token_id": token.get("id"),
                            "name": token.get("name"),
                            "active": token.get("active"),
                            "revoked": token.get("revoked"),
                            "created_at": token.get("created_at"),
                            "expires_at": token.get("expires_at"),
                            "scopes": token.get("scopes"),
                            "access_level": token.get("access_level"),
                        }
                    )
            except Exception:
                # May not have permission to view tokens
                pass

        # Check for expired or soon-to-expire tokens
        now = datetime.now(UTC)
        expiring_soon = []
        for token in tokens_data:
            if token.get("expires_at"):
                try:
                    expires = datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00"))
                    if expires < now + timedelta(days=30):
                        expiring_soon.append(token)
                except Exception:
                    pass

        return [
            self.normalize_evidence(
                {
                    "tokens": tokens_data,
                    "total_tokens": len(tokens_data),
                    "active_tokens": sum(1 for t in tokens_data if t.get("active")),
                    "expiring_within_30_days": len(expiring_soon),
                    "project_tokens": sum(1 for t in tokens_data if t["type"] == "project"),
                    "group_tokens": sum(1 for t in tokens_data if t["type"] == "group"),
                },
                "access_tokens",
                {"source": "gitlab_access_tokens"},
            )
        ]
