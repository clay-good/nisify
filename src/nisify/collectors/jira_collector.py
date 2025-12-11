"""
Jira collector for Nisify.

Collects security evidence from Jira/Atlassian including projects, users,
audit logs, permission schemes, and issue tracking for compliance workflows.
All API calls are read-only.

Required Jira Permissions:
    - Browse Projects
    - Administer Jira (for audit logs and permission schemes)

Authentication:
    Credentials are retrieved from the credential store with keys:
    - jira_url: Jira instance URL (e.g., "https://your-org.atlassian.net")
    - jira_email: User email for authentication
    - jira_api_token: API token (create at https://id.atlassian.com/manage-profile/security/api-tokens)

Rate Limiting:
    Atlassian Cloud enforces rate limits. This collector:
    - Monitors response headers for rate limit status
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
class JiraCollector(BaseCollector):
    """
    Jira evidence collector.

    Collects security-relevant evidence from Jira:
        - Project inventory (project_inventory)
        - User directory (user_inventory)
        - Audit logs (audit_logs)
        - Permission schemes (access_control)
        - Security-related issues (incident_tracking)

    Evidence Types Collected:
        - project_inventory: All accessible projects with configurations
        - user_inventory: Active users with account information
        - audit_logs: Admin audit events (last 30 days)
        - access_control: Permission schemes and project roles
        - incident_tracking: Security/compliance-labeled issues

    Example:
        collector = JiraCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "jira"
    default_rate_limit_delay = 0.1

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Jira collector.

        Args:
            config: Settings object containing Jira configuration.
            credential_store: Credential store for retrieving Jira credentials.
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
        jira_url = self.get_credential("jira_url")
        email = self.get_credential("jira_email")
        api_token = self.get_credential("jira_api_token")

        # Normalize URL
        url = jira_url.strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        if url.endswith("/"):
            url = url[:-1]
        self._base_url = url

        # Create basic auth header
        auth_string = f"{email}:{api_token}"
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
        Make an API request to Jira.

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
                    "Jira rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else None,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Jira authentication failed. Check email and API token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Jira permission denied. Check account permissions.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}, dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Jira: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Jira request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "values",
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Jira API endpoint.

        Jira uses startAt and maxResults for pagination.

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
        params.setdefault("maxResults", 100)
        start_at = 0

        while True:
            params["startAt"] = start_at
            data, _ = self._api_request("GET", endpoint, params)

            items = data.get(results_key, [])
            if not items:
                # Try direct list response
                if isinstance(data, list):
                    items = data
                else:
                    break

            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check if more pages exist
            total = data.get("total", len(items))
            if start_at + len(items) >= total:
                break

            start_at += len(items)

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Jira permission strings.
        """
        return [
            "Browse Projects",
            "Administer Jira (for audit logs)",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Jira.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/rest/api/3/myself")
            self.logger.info(
                f"Jira connection successful. User: {data.get('displayName')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Jira connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Jira.

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
            ("audit_logs", self._collect_audit_logs),
            ("access_control", self._collect_permission_schemes),
            ("incident_tracking", self._collect_security_issues),
            ("improvement_plan", self._collect_improvement_plans),
            ("remediation_tracking", self._collect_remediation_tracking),
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
        Collect project inventory.

        Returns:
            List of Evidence items with project inventory.
        """
        projects = self._paginate("/rest/api/3/project/search")

        project_data = []
        for project in projects:
            project_data.append(
                {
                    "id": project.get("id"),
                    "key": project.get("key"),
                    "name": project.get("name"),
                    "project_type_key": project.get("projectTypeKey"),
                    "style": project.get("style"),
                    "is_private": project.get("isPrivate"),
                    "simplified": project.get("simplified"),
                    "lead_account_id": project.get("lead", {}).get("accountId"),
                    "lead_display_name": project.get("lead", {}).get("displayName"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "projects": project_data,
                    "total_projects": len(project_data),
                    "project_types": list({p.get("project_type_key") for p in project_data}),
                },
                "project_inventory",
                {"source": "jira_projects"},
            )
        ]

    def _collect_users(self) -> list[Evidence]:
        """
        Collect user directory information.

        Returns:
            List of Evidence items with user inventory.
        """
        # Search for all active users
        users = self._paginate(
            "/rest/api/3/users/search",
            results_key="users",
        )

        # If that doesn't work, try user search
        if not users:
            try:
                data, _ = self._api_request(
                    "GET", "/rest/api/3/user/search", {"query": ""}
                )
                users = data if isinstance(data, list) else []
            except Exception:
                users = []

        user_data = []
        for user in users:
            user_data.append(
                {
                    "account_id": user.get("accountId"),
                    "account_type": user.get("accountType"),
                    "display_name": user.get("displayName"),
                    "email": user.get("emailAddress"),
                    "active": user.get("active"),
                    "locale": user.get("locale"),
                    "timezone": user.get("timeZone"),
                }
            )

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": len(user_data),
                    "active_users": sum(1 for u in user_data if u.get("active")),
                    "account_types": list({u.get("account_type") for u in user_data if u.get("account_type")}),
                },
                "user_inventory",
                {"source": "jira_users"},
            )
        ]

    def _collect_audit_logs(self) -> list[Evidence]:
        """
        Collect audit logs (requires admin permissions).

        Returns:
            List of Evidence items with audit logs.
        """
        # Get audit records from last 30 days
        since = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        audit_records = []
        try:
            # Try Atlassian organization audit log
            data, _ = self._api_request(
                "GET",
                "/rest/api/3/auditing/record",
                {"from": since},
            )
            audit_records = data.get("records", [])
        except Exception as e:
            self.logger.warning(f"Could not fetch audit records: {e}")

        event_data = []
        for record in audit_records:
            event_data.append(
                {
                    "id": record.get("id"),
                    "summary": record.get("summary"),
                    "category": record.get("category"),
                    "event_source": record.get("eventSource"),
                    "author_key": record.get("authorKey"),
                    "author_account_id": record.get("authorAccountId"),
                    "remote_address": record.get("remoteAddress"),
                    "created": record.get("created"),
                    "object_item": record.get("objectItem", {}).get("name"),
                    "object_type": record.get("objectItem", {}).get("typeName"),
                    "associated_items": [
                        {"name": item.get("name"), "type": item.get("typeName")}
                        for item in record.get("associatedItems", [])
                    ],
                }
            )

        # Category breakdown
        category_counts: dict[str, int] = {}
        for event in event_data:
            cat = event.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": event_data,
                    "total_events": len(event_data),
                    "category_counts": category_counts,
                    "date_range_days": 30,
                },
                "audit_logs",
                {"source": "jira_audit_records"},
            )
        ]

    def _collect_permission_schemes(self) -> list[Evidence]:
        """
        Collect permission schemes and project roles.

        Returns:
            List of Evidence items with access control information.
        """
        permission_data: dict[str, Any] = {
            "permission_schemes": [],
            "project_roles": [],
        }

        # Get permission schemes
        try:
            data, _ = self._api_request("GET", "/rest/api/3/permissionscheme")
            schemes = data.get("permissionSchemes", [])

            for scheme in schemes:
                scheme_id = scheme.get("id")
                # Get full scheme details
                try:
                    full_scheme, _ = self._api_request(
                        "GET", f"/rest/api/3/permissionscheme/{scheme_id}"
                    )
                    permissions = full_scheme.get("permissions", [])
                except Exception:
                    permissions = []

                permission_data["permission_schemes"].append(
                    {
                        "id": scheme_id,
                        "name": scheme.get("name"),
                        "description": scheme.get("description"),
                        "permission_count": len(permissions),
                        "permissions": [
                            {
                                "permission": p.get("permission"),
                                "holder_type": p.get("holder", {}).get("type"),
                                "holder_value": p.get("holder", {}).get("value"),
                            }
                            for p in permissions[:50]  # Limit stored permissions
                        ],
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get permission schemes: {e}")

        # Get project roles
        try:
            data, _ = self._api_request("GET", "/rest/api/3/role")
            roles = data if isinstance(data, list) else []

            for role in roles:
                permission_data["project_roles"].append(
                    {
                        "id": role.get("id"),
                        "name": role.get("name"),
                        "description": role.get("description"),
                        "scope_type": role.get("scope", {}).get("type"),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get project roles: {e}")

        return [
            self.normalize_evidence(
                {
                    "permission_schemes": permission_data["permission_schemes"],
                    "project_roles": permission_data["project_roles"],
                    "total_schemes": len(permission_data["permission_schemes"]),
                    "total_roles": len(permission_data["project_roles"]),
                },
                "access_control",
                {"source": "jira_permissions"},
            )
        ]

    def _collect_security_issues(self) -> list[Evidence]:
        """
        Collect security and compliance-related issues.

        Returns:
            List of Evidence items with incident tracking data.
        """
        # Search for security/compliance labeled issues
        jql_queries = [
            'labels in ("security", "compliance", "incident", "vulnerability") ORDER BY created DESC',
            'type = "Bug" AND priority in ("Highest", "High") AND status != "Done" ORDER BY created DESC',
        ]

        all_issues = []
        for jql in jql_queries:
            try:
                data, _ = self._api_request(
                    "GET",
                    "/rest/api/3/search",
                    {"jql": jql, "maxResults": 100, "fields": "summary,status,priority,created,updated,assignee,reporter,labels,issuetype"},
                )
                issues = data.get("issues", [])
                all_issues.extend(issues)
            except Exception as e:
                self.logger.warning(f"Failed to search issues with JQL: {e}")

        # Deduplicate by issue key
        seen_keys = set()
        unique_issues = []
        for issue in all_issues:
            key = issue.get("key")
            if key not in seen_keys:
                seen_keys.add(key)
                unique_issues.append(issue)

        issue_data = []
        for issue in unique_issues:
            fields = issue.get("fields", {})
            issue_data.append(
                {
                    "key": issue.get("key"),
                    "id": issue.get("id"),
                    "summary": fields.get("summary"),
                    "status": fields.get("status", {}).get("name"),
                    "status_category": fields.get("status", {}).get("statusCategory", {}).get("name"),
                    "priority": fields.get("priority", {}).get("name"),
                    "issue_type": fields.get("issuetype", {}).get("name"),
                    "created": fields.get("created"),
                    "updated": fields.get("updated"),
                    "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                    "reporter": fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
                    "labels": fields.get("labels", []),
                }
            )

        # Status breakdown
        status_counts: dict[str, int] = {}
        for issue in issue_data:
            status = issue.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "issues": issue_data,
                    "total_issues": len(issue_data),
                    "status_counts": status_counts,
                    "open_issues": sum(1 for i in issue_data if i.get("status_category") != "Done"),
                },
                "incident_tracking",
                {"source": "jira_security_issues"},
            )
        ]

    def _collect_improvement_plans(self) -> list[Evidence]:
        """
        Collect improvement plans and action items from Jira.

        Searches for issues tagged with improvement, action-item, or continuous-improvement
        labels to track organizational improvement initiatives.

        Returns:
            List of Evidence items with improvement plan data.
        """
        # Search for improvement-related issues
        jql_queries = [
            'labels in ("improvement", "action-item", "continuous-improvement", "capa", "corrective-action") ORDER BY created DESC',
            'type in ("Improvement", "Action Item", "Task") AND labels in ("security-improvement", "compliance-improvement") ORDER BY created DESC',
        ]

        all_issues = []
        for jql in jql_queries:
            try:
                data, _ = self._api_request(
                    "GET",
                    "/rest/api/3/search",
                    {
                        "jql": jql,
                        "maxResults": 200,
                        "fields": "summary,status,priority,created,updated,assignee,reporter,labels,issuetype,duedate,description",
                    },
                )
                issues = data.get("issues", [])
                all_issues.extend(issues)
            except Exception as e:
                self.logger.warning(f"Failed to search improvement issues: {e}")

        # Deduplicate by issue key
        seen_keys = set()
        unique_issues = []
        for issue in all_issues:
            key = issue.get("key")
            if key not in seen_keys:
                seen_keys.add(key)
                unique_issues.append(issue)

        improvement_data = []
        for issue in unique_issues:
            fields = issue.get("fields", {})
            description = fields.get("description")
            if isinstance(description, dict):
                # Handle Atlassian Document Format
                description = str(description.get("content", ""))[:500]
            elif description:
                description = description[:500]

            improvement_data.append(
                {
                    "key": issue.get("key"),
                    "id": issue.get("id"),
                    "summary": fields.get("summary"),
                    "description_preview": description,
                    "status": fields.get("status", {}).get("name"),
                    "status_category": fields.get("status", {}).get("statusCategory", {}).get("name"),
                    "priority": fields.get("priority", {}).get("name"),
                    "issue_type": fields.get("issuetype", {}).get("name"),
                    "created": fields.get("created"),
                    "updated": fields.get("updated"),
                    "due_date": fields.get("duedate"),
                    "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                    "reporter": fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
                    "labels": fields.get("labels", []),
                }
            )

        # Calculate status breakdown
        status_counts: dict[str, int] = {}
        for issue in improvement_data:
            status = issue.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        # Check for overdue items
        overdue_count = 0
        today = datetime.now(UTC).date()
        for issue in improvement_data:
            due_date = issue.get("due_date")
            status_cat = issue.get("status_category")
            if due_date and status_cat != "Done":
                try:
                    due = datetime.fromisoformat(due_date).date()
                    if due < today:
                        overdue_count += 1
                except (ValueError, TypeError):
                    pass

        return [
            self.normalize_evidence(
                {
                    "improvements": improvement_data,
                    "total_improvements": len(improvement_data),
                    "status_counts": status_counts,
                    "open_improvements": sum(
                        1 for i in improvement_data if i.get("status_category") != "Done"
                    ),
                    "completed_improvements": sum(
                        1 for i in improvement_data if i.get("status_category") == "Done"
                    ),
                    "overdue_count": overdue_count,
                },
                "improvement_plan",
                {"source": "jira_improvement_issues"},
            )
        ]

    def _collect_remediation_tracking(self) -> list[Evidence]:
        """
        Collect remediation and corrective action tracking from Jira.

        Searches for issues related to vulnerability remediation, audit findings,
        and corrective actions to track remediation progress.

        Returns:
            List of Evidence items with remediation tracking data.
        """
        # Search for remediation-related issues
        jql_queries = [
            'labels in ("remediation", "vulnerability", "audit-finding", "finding", "risk-remediation") ORDER BY priority DESC, created DESC',
            'type in ("Bug", "Task") AND labels in ("security-fix", "compliance-fix", "remediation") ORDER BY priority DESC',
            'summary ~ "remediation" OR summary ~ "finding" OR summary ~ "vulnerability fix" ORDER BY priority DESC',
        ]

        all_issues = []
        for jql in jql_queries:
            try:
                data, _ = self._api_request(
                    "GET",
                    "/rest/api/3/search",
                    {
                        "jql": jql,
                        "maxResults": 200,
                        "fields": "summary,status,priority,created,updated,assignee,reporter,labels,issuetype,duedate,resolution,resolutiondate",
                    },
                )
                issues = data.get("issues", [])
                all_issues.extend(issues)
            except Exception as e:
                self.logger.warning(f"Failed to search remediation issues: {e}")

        # Deduplicate by issue key
        seen_keys = set()
        unique_issues = []
        for issue in all_issues:
            key = issue.get("key")
            if key not in seen_keys:
                seen_keys.add(key)
                unique_issues.append(issue)

        remediation_data = []
        for issue in unique_issues:
            fields = issue.get("fields", {})

            # Calculate days open
            created = fields.get("created")
            resolution_date = fields.get("resolutiondate")
            days_open = None
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if resolution_date:
                        resolved_dt = datetime.fromisoformat(
                            resolution_date.replace("Z", "+00:00")
                        )
                        days_open = (resolved_dt - created_dt).days
                    else:
                        days_open = (datetime.now(UTC) - created_dt).days
                except (ValueError, TypeError):
                    pass

            remediation_data.append(
                {
                    "key": issue.get("key"),
                    "id": issue.get("id"),
                    "summary": fields.get("summary"),
                    "status": fields.get("status", {}).get("name"),
                    "status_category": fields.get("status", {}).get("statusCategory", {}).get("name"),
                    "priority": fields.get("priority", {}).get("name"),
                    "issue_type": fields.get("issuetype", {}).get("name"),
                    "created": created,
                    "updated": fields.get("updated"),
                    "due_date": fields.get("duedate"),
                    "resolution": fields.get("resolution", {}).get("name") if fields.get("resolution") else None,
                    "resolution_date": resolution_date,
                    "days_open": days_open,
                    "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                    "labels": fields.get("labels", []),
                }
            )

        # Calculate summary statistics
        status_counts: dict[str, int] = {}
        priority_counts: dict[str, int] = {}

        for issue in remediation_data:
            status = issue.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            priority = issue.get("priority", "unknown")
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

        # Calculate metrics
        open_items = [i for i in remediation_data if i.get("status_category") != "Done"]
        closed_items = [i for i in remediation_data if i.get("status_category") == "Done"]

        avg_days_to_close = 0
        if closed_items:
            days_values = [i.get("days_open") for i in closed_items if i.get("days_open") is not None]
            if days_values:
                avg_days_to_close = sum(days_values) / len(days_values)

        # Check for overdue items
        overdue_count = 0
        today = datetime.now(UTC).date()
        for issue in open_items:
            due_date = issue.get("due_date")
            if due_date:
                try:
                    due = datetime.fromisoformat(due_date).date()
                    if due < today:
                        overdue_count += 1
                except (ValueError, TypeError):
                    pass

        return [
            self.normalize_evidence(
                {
                    "remediation_items": remediation_data,
                    "total_items": len(remediation_data),
                    "status_counts": status_counts,
                    "priority_counts": priority_counts,
                    "open_count": len(open_items),
                    "closed_count": len(closed_items),
                    "overdue_count": overdue_count,
                    "avg_days_to_close": round(avg_days_to_close, 1),
                    "high_priority_open": sum(
                        1 for i in open_items
                        if i.get("priority") in ("Highest", "High", "Critical")
                    ),
                },
                "remediation_tracking",
                {"source": "jira_remediation_issues"},
            )
        ]
