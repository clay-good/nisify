"""
Datadog collector for Nisify.

Collects security evidence from Datadog including security signals,
detection rules, monitors, audit trail, and log management configuration.
All API calls are read-only.

Required Datadog Permissions:
    - API key with read access
    - Application key with appropriate scopes:
      - security_monitoring_signals_read
      - security_monitoring_rules_read
      - monitors_read
      - events_read
      - logs_read_data

Authentication:
    Credentials are retrieved from the credential store with keys:
    - datadog_api_key: Datadog API key
    - datadog_app_key: Datadog Application key
    - datadog_site: Datadog site (optional, defaults to datadoghq.com)

    Supported sites:
    - datadoghq.com (US1)
    - us3.datadoghq.com (US3)
    - us5.datadoghq.com (US5)
    - datadoghq.eu (EU1)
    - ap1.datadoghq.com (AP1)

Rate Limiting:
    Datadog enforces rate limits per endpoint. This collector:
    - Respects 429 responses and waits for retry
    - Uses exponential backoff on rate limit errors
    - Logs rate limit warnings
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
class DatadogCollector(BaseCollector):
    """
    Datadog evidence collector.

    Collects security-relevant evidence from Datadog:
        - Security signals (security_findings)
        - Detection rules (detection_rules)
        - Monitors (monitoring_coverage)
        - Audit trail (audit_logs)
        - Log configuration (log_retention)

    Evidence Types Collected:
        - security_findings: Security signals from Cloud SIEM
        - detection_rules: Configured detection rules and status
        - monitoring_coverage: All configured monitors
        - audit_logs: Datadog audit trail (who did what in Datadog)
        - log_retention: Log pipeline and retention configuration

    Example:
        collector = DatadogCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "datadog"
    default_rate_limit_delay = 0.2

    # Datadog site to API host mapping
    SITE_HOSTS = {
        "datadoghq.com": "api.datadoghq.com",
        "us3.datadoghq.com": "api.us3.datadoghq.com",
        "us5.datadoghq.com": "api.us5.datadoghq.com",
        "datadoghq.eu": "api.datadoghq.eu",
        "ap1.datadoghq.com": "api.ap1.datadoghq.com",
    }

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Datadog collector.

        Args:
            config: Settings object containing Datadog configuration.
            credential_store: Credential store for retrieving Datadog credentials.
        """
        super().__init__(config, credential_store)
        self._api_key: str | None = None
        self._app_key: str | None = None
        self._base_url: str | None = None
        self._session: requests.Session | None = None

    def _get_session(self) -> requests.Session:
        """
        Get or create a requests session with authentication headers.

        Returns:
            Configured requests.Session.
        """
        if self._session is not None:
            return self._session

        # Get credentials
        self._api_key = self.get_credential("datadog_api_key")
        self._app_key = self.get_credential("datadog_app_key")

        # Determine site and base URL
        try:
            site = self.get_credential("datadog_site")
        except AuthenticationError:
            site = "datadoghq.com"  # Default to US1

        host = self.SITE_HOSTS.get(site)
        if not host:
            # Assume it's a custom host
            host = f"api.{site}" if not site.startswith("api.") else site

        self._base_url = f"https://{host}"

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "DD-API-KEY": self._api_key,
                "DD-APPLICATION-KEY": self._app_key,
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
        json_data: dict[str, Any] | None = None,
    ) -> Any:
        """
        Make an API request to Datadog.

        Args:
            method: HTTP method.
            endpoint: API endpoint path.
            params: Query parameters.
            json_data: JSON body for POST requests.

        Returns:
            Response JSON data.

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
                method,
                url,
                params=params,
                json=json_data,
                timeout=60,
            )
            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("X-RateLimit-Reset")
                raise RateLimitError(
                    "Datadog rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else None,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Datadog authentication failed. Check API and Application keys.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Datadog permission denied. Check Application key scopes.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.text:
                return response.json()
            return {}

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Datadog: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Datadog request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data_key: str = "data",
        max_items: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Datadog API endpoint.

        Args:
            endpoint: API endpoint path.
            params: Initial query parameters.
            data_key: Key in response containing results list.
            max_items: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        page_size = 100
        params["page[limit]"] = page_size

        cursor = None

        while True:
            if cursor:
                params["page[cursor]"] = cursor

            data = self._api_request("GET", endpoint, params)

            items = data.get(data_key, [])
            all_items.extend(items)

            if max_items and len(all_items) >= max_items:
                all_items = all_items[:max_items]
                break

            # Check for next page
            meta = data.get("meta", {})
            page_info = meta.get("page", {})
            cursor = page_info.get("after")

            if not cursor or len(items) < page_size:
                break

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Datadog permission scope strings.
        """
        return [
            "security_monitoring_signals_read",
            "security_monitoring_rules_read",
            "monitors_read",
            "events_read",
            "logs_read_data",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Datadog.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            # Test by validating the API key
            data = self._api_request("GET", "/api/v1/validate")
            if data.get("valid"):
                self.logger.info("Datadog connection successful. API key is valid.")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Datadog connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Datadog.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        collectors = [
            ("security_findings", self._collect_security_signals),
            ("detection_rules", self._collect_detection_rules),
            ("monitoring_coverage", self._collect_monitors),
            ("audit_logs", self._collect_audit_logs),
            ("log_retention", self._collect_log_configuration),
            ("threat_register", self._collect_threat_register),
            ("capacity_monitoring", self._collect_capacity_monitoring),
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

    def _collect_security_signals(self) -> list[Evidence]:
        """
        Collect security signals from Cloud SIEM.

        Returns:
            List of Evidence items with security findings.
        """
        # Get signals from the last 30 days
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=30)

        # Use the security monitoring signals search endpoint
        signals = self._paginate(
            "/api/v2/security_monitoring/signals",
            {
                "filter[from]": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "filter[to]": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sort": "-timestamp",
            },
            max_items=5000,
        )

        # Process signals
        signal_data = []
        for signal in signals:
            attributes = signal.get("attributes", {})
            signal_data.append(
                {
                    "id": signal.get("id"),
                    "timestamp": attributes.get("timestamp"),
                    "status": attributes.get("status"),
                    "severity": attributes.get("severity"),
                    "title": attributes.get("message"),
                    "rule_id": attributes.get("rule", {}).get("id"),
                    "rule_name": attributes.get("rule", {}).get("name"),
                    "tags": attributes.get("tags", []),
                    "triage_state": attributes.get("state"),
                }
            )

        # Calculate summary
        total_signals = len(signal_data)

        # Count by severity
        severity_counts: dict[str, int] = {}
        for s in signal_data:
            severity = s.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count by status
        status_counts: dict[str, int] = {}
        for s in signal_data:
            status = s.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "signals": signal_data,
                    "total_signals": total_signals,
                    "severity_counts": severity_counts,
                    "status_counts": status_counts,
                    "date_range_days": 30,
                },
                "security_findings",
                {"source": "datadog_security_signals"},
            )
        ]

    def _collect_detection_rules(self) -> list[Evidence]:
        """
        Collect security detection rules.

        Returns:
            List of Evidence items with detection rules.
        """
        rules = self._paginate(
            "/api/v2/security_monitoring/rules",
            {},
            max_items=1000,
        )

        rule_data = []
        for rule in rules:
            attributes = rule.get("attributes", {})
            rule_data.append(
                {
                    "id": rule.get("id"),
                    "name": attributes.get("name"),
                    "is_enabled": attributes.get("isEnabled"),
                    "is_default": attributes.get("isDefault"),
                    "type": attributes.get("type"),
                    "severity": attributes.get("options", {}).get("defaultSeverity"),
                    "has_extended_title": attributes.get("hasExtendedTitle"),
                    "tags": attributes.get("tags", []),
                    "created_at": attributes.get("createdAt"),
                    "updated_at": attributes.get("updateAuthorId"),
                }
            )

        # Calculate summary
        total_rules = len(rule_data)
        enabled_count = sum(1 for r in rule_data if r.get("is_enabled"))
        default_rules = sum(1 for r in rule_data if r.get("is_default"))
        custom_rules = total_rules - default_rules

        # Count by type
        type_counts: dict[str, int] = {}
        for r in rule_data:
            rt = r.get("type", "unknown")
            type_counts[rt] = type_counts.get(rt, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "rules": rule_data,
                    "total_rules": total_rules,
                    "enabled_count": enabled_count,
                    "disabled_count": total_rules - enabled_count,
                    "default_rules": default_rules,
                    "custom_rules": custom_rules,
                    "type_counts": type_counts,
                },
                "detection_rules",
                {"source": "datadog_security_rules"},
            )
        ]

    def _collect_monitors(self) -> list[Evidence]:
        """
        Collect all configured monitors.

        Returns:
            List of Evidence items with monitoring coverage.
        """
        # Get all monitors
        monitors = self._api_request("GET", "/api/v1/monitor")

        if not isinstance(monitors, list):
            monitors = []

        monitor_data = []
        for monitor in monitors:
            monitor_data.append(
                {
                    "id": monitor.get("id"),
                    "name": monitor.get("name"),
                    "type": monitor.get("type"),
                    "overall_state": monitor.get("overall_state"),
                    "query": monitor.get("query"),
                    "message": monitor.get("message", "")[:200],  # Truncate
                    "tags": monitor.get("tags", []),
                    "created": monitor.get("created"),
                    "modified": monitor.get("modified"),
                    "priority": monitor.get("priority"),
                    "restricted_roles": monitor.get("restricted_roles"),
                }
            )

        # Calculate summary
        total_monitors = len(monitor_data)

        # Count by state
        state_counts: dict[str, int] = {}
        for m in monitor_data:
            state = m.get("overall_state", "unknown")
            state_counts[state] = state_counts.get(state, 0) + 1

        # Count by type
        type_counts: dict[str, int] = {}
        for m in monitor_data:
            mt = m.get("type", "unknown")
            type_counts[mt] = type_counts.get(mt, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "monitors": monitor_data,
                    "total_monitors": total_monitors,
                    "state_counts": state_counts,
                    "type_counts": type_counts,
                },
                "monitoring_coverage",
                {"source": "datadog_monitors"},
            )
        ]

    def _collect_audit_logs(self) -> list[Evidence]:
        """
        Collect Datadog audit trail.

        Returns:
            List of Evidence items with audit logs.
        """
        # Get audit logs from the last 30 days
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=30)

        try:
            events = self._paginate(
                "/api/v2/audit/events",
                {
                    "filter[from]": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "filter[to]": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sort": "-timestamp",
                },
                max_items=5000,
            )
        except Exception as e:
            self.logger.warning(f"Failed to get audit logs: {e}")
            events = []

        # Process events
        audit_data = []
        for event in events:
            attributes = event.get("attributes", {})
            audit_data.append(
                {
                    "id": event.get("id"),
                    "timestamp": attributes.get("timestamp"),
                    "type": event.get("type"),
                    "service": attributes.get("service"),
                    "action": attributes.get("evt", {}).get("name"),
                    "user_name": attributes.get("usr", {}).get("name"),
                    "user_email": attributes.get("usr", {}).get("email"),
                    "client_ip": attributes.get("network", {}).get("client", {}).get("ip"),
                }
            )

        # Calculate summary
        total_events = len(audit_data)

        # Count by action
        action_counts: dict[str, int] = {}
        for event in audit_data:
            action = event.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        # Count by user
        user_counts: dict[str, int] = {}
        for event in audit_data:
            user = event.get("user_email", "unknown")
            user_counts[user] = user_counts.get(user, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": audit_data,
                    "total_events": total_events,
                    "action_counts": action_counts,
                    "user_counts": user_counts,
                    "date_range_days": 30,
                },
                "audit_logs",
                {"source": "datadog_audit_trail"},
            )
        ]

    def _collect_log_configuration(self) -> list[Evidence]:
        """
        Collect log pipeline and retention configuration.

        Returns:
            List of Evidence items with log retention config.
        """
        config_data: dict[str, Any] = {
            "pipelines": [],
            "indexes": [],
        }

        # Get log pipelines
        try:
            pipelines = self._api_request("GET", "/api/v1/logs/config/pipelines")
            if isinstance(pipelines, list):
                for pipeline in pipelines:
                    config_data["pipelines"].append(
                        {
                            "id": pipeline.get("id"),
                            "name": pipeline.get("name"),
                            "is_enabled": pipeline.get("is_enabled"),
                            "is_read_only": pipeline.get("is_read_only"),
                            "type": pipeline.get("type"),
                            "filter_query": pipeline.get("filter", {}).get("query"),
                            "processor_count": len(pipeline.get("processors", [])),
                        }
                    )
        except Exception as e:
            self.logger.warning(f"Failed to get log pipelines: {e}")

        # Get log indexes (retention settings)
        try:
            indexes = self._api_request("GET", "/api/v1/logs/config/indexes")
            if isinstance(indexes, dict):
                for index in indexes.get("indexes", []):
                    config_data["indexes"].append(
                        {
                            "name": index.get("name"),
                            "retention_days": index.get("num_retention_days"),
                            "daily_limit": index.get("daily_limit"),
                            "is_rate_limited": index.get("is_rate_limited"),
                            "filter_query": index.get("filter", {}).get("query"),
                        }
                    )
        except Exception as e:
            self.logger.warning(f"Failed to get log indexes: {e}")

        # Calculate summary
        total_pipelines = len(config_data["pipelines"])
        enabled_pipelines = sum(
            1 for p in config_data["pipelines"] if p.get("is_enabled")
        )
        total_indexes = len(config_data["indexes"])

        # Get max retention
        max_retention = 0
        for idx in config_data["indexes"]:
            retention = idx.get("retention_days", 0)
            if retention and retention > max_retention:
                max_retention = retention

        return [
            self.normalize_evidence(
                {
                    "pipelines": config_data["pipelines"],
                    "indexes": config_data["indexes"],
                    "total_pipelines": total_pipelines,
                    "enabled_pipelines": enabled_pipelines,
                    "total_indexes": total_indexes,
                    "max_retention_days": max_retention,
                },
                "log_retention",
                {"source": "datadog_logs_config"},
            )
        ]

    def _collect_threat_register(self) -> list[Evidence]:
        """
        Collect threat intelligence and risk data from security signals.

        Maps security signals to a threat register format showing identified
        threats, their severity, status, and remediation state.

        Returns:
            List of Evidence items with threat register data.
        """
        # Get high/critical security signals from last 90 days for threat register
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=90)

        signals = self._paginate(
            "/api/v2/security_monitoring/signals",
            {
                "filter[from]": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "filter[to]": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "filter[query]": "status:(high OR critical)",
                "sort": "-timestamp",
            },
            max_items=1000,
        )

        # Build threat register from security signals
        threat_data = []
        for signal in signals:
            attributes = signal.get("attributes", {})
            rule_info = attributes.get("rule", {})

            # Determine threat status based on signal state
            signal_state = attributes.get("state", "open")
            if signal_state in ["archived", "resolved"]:
                threat_status = "mitigated"
            elif signal_state == "under_review":
                threat_status = "in_progress"
            else:
                threat_status = "identified"

            threat_data.append(
                {
                    "threat_id": signal.get("id"),
                    "threat_name": attributes.get("message") or rule_info.get("name"),
                    "threat_type": rule_info.get("type"),
                    "severity": attributes.get("severity"),
                    "status": threat_status,
                    "first_seen": attributes.get("timestamp"),
                    "last_seen": attributes.get("timestamp"),
                    "source_rule": rule_info.get("name"),
                    "source_rule_id": rule_info.get("id"),
                    "affected_resources": attributes.get("tags", []),
                    "triage_state": signal_state,
                }
            )

        # Calculate threat summary
        total_threats = len(threat_data)
        severity_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}

        for threat in threat_data:
            sev = threat.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            status = threat.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            ttype = threat.get("threat_type", "unknown")
            type_counts[ttype] = type_counts.get(ttype, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "threats": threat_data,
                    "total_threats": total_threats,
                    "severity_counts": severity_counts,
                    "status_counts": status_counts,
                    "type_counts": type_counts,
                    "date_range_days": 90,
                    "open_threats": status_counts.get("identified", 0),
                    "in_progress_threats": status_counts.get("in_progress", 0),
                    "mitigated_threats": status_counts.get("mitigated", 0),
                },
                "threat_register",
                {"source": "datadog_security_signals_threat_analysis"},
            )
        ]

    def _collect_capacity_monitoring(self) -> list[Evidence]:
        """
        Collect capacity and resource monitoring data from infrastructure metrics.

        Gathers information about monitored infrastructure, resource alerts,
        and capacity-related monitors.

        Returns:
            List of Evidence items with capacity monitoring data.
        """
        # Get infrastructure-related monitors (CPU, memory, disk, network)
        capacity_keywords = [
            "cpu",
            "memory",
            "disk",
            "storage",
            "network",
            "capacity",
            "utilization",
            "threshold",
        ]

        monitors = self._api_request("GET", "/api/v1/monitor")
        if not isinstance(monitors, list):
            monitors = []

        capacity_monitors = []
        for monitor in monitors:
            name = monitor.get("name", "").lower()
            query = monitor.get("query", "").lower()
            tags = [t.lower() for t in monitor.get("tags", [])]

            # Check if monitor is capacity-related
            is_capacity = any(
                kw in name or kw in query or any(kw in t for t in tags)
                for kw in capacity_keywords
            )

            if is_capacity:
                capacity_monitors.append(
                    {
                        "id": monitor.get("id"),
                        "name": monitor.get("name"),
                        "type": monitor.get("type"),
                        "overall_state": monitor.get("overall_state"),
                        "query": monitor.get("query"),
                        "thresholds": monitor.get("options", {}).get("thresholds"),
                        "tags": monitor.get("tags", []),
                        "created": monitor.get("created"),
                        "modified": monitor.get("modified"),
                        "message": monitor.get("message", "")[:200],
                    }
                )

        # Get hosts for infrastructure inventory
        try:
            hosts_response = self._api_request(
                "GET", "/api/v1/hosts", {"count": 1000}
            )
            hosts = hosts_response.get("host_list", [])
        except Exception:
            hosts = []

        host_data = []
        for host in hosts[:500]:
            meta = host.get("meta", {})
            host_data.append(
                {
                    "id": host.get("id"),
                    "name": host.get("name"),
                    "is_muted": host.get("is_muted"),
                    "host_tags": host.get("tags_by_source", {}),
                    "platform": meta.get("platform"),
                    "processor": meta.get("processor"),
                    "machine": meta.get("machine"),
                    "agent_version": meta.get("agent_version"),
                    "up": host.get("up"),
                }
            )

        # Calculate summary
        total_capacity_monitors = len(capacity_monitors)
        alerting_count = sum(
            1 for m in capacity_monitors if m.get("overall_state") == "Alert"
        )
        warning_count = sum(
            1 for m in capacity_monitors if m.get("overall_state") == "Warn"
        )

        total_hosts = len(host_data)
        hosts_up = sum(1 for h in host_data if h.get("up"))

        return [
            self.normalize_evidence(
                {
                    "capacity_monitors": capacity_monitors,
                    "total_capacity_monitors": total_capacity_monitors,
                    "alerting_monitors": alerting_count,
                    "warning_monitors": warning_count,
                    "ok_monitors": total_capacity_monitors - alerting_count - warning_count,
                    "infrastructure_hosts": host_data,
                    "total_hosts": total_hosts,
                    "hosts_up": hosts_up,
                    "hosts_down": total_hosts - hosts_up,
                },
                "capacity_monitoring",
                {"source": "datadog_infrastructure_monitoring"},
            )
        ]
