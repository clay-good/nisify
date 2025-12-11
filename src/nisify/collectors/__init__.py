"""
Platform collectors for evidence gathering.

Each collector is responsible for authenticating with a specific platform,
gathering evidence via read-only API calls, and normalizing the results
to a common schema.

Supported platforms:
    - AWS (Security Hub, IAM, CloudTrail, Config)
    - Okta (System Log, Users, Policies)
    - Jamf Pro (Device Compliance, Inventory)
    - Google Workspace (Admin Audit Logs, Directory)
    - Snowflake (ACCOUNT_USAGE views)
    - Datadog (Security Signals, Monitors)
    - GitLab (Projects, Users, Audit Events, MR Settings)
    - Jira (Projects, Users, Audit Logs, Permissions)
    - Zendesk (Users, Audit Logs, Tickets, Security Settings)
    - Zoom (Users, Meetings, Recordings, Security Settings)
    - Notion (Users, Databases, Pages, Permissions)
    - Slab (Users, Posts, Topics, Access Settings)
    - SpotDraft (Users, Contracts, Templates, Activity)

All collectors inherit from BaseCollector and register themselves
with the CollectorRegistry for discovery.
"""

# Import collectors to trigger registration
# These imports are intentionally at module level to ensure
# collectors register themselves when the package is imported
from nisify.collectors.aws_collector import AwsCollector
from nisify.collectors.base import (
    AuthenticationError,
    BaseCollector,
    CollectionResult,
    CollectorConnectionError,
    CollectorError,
    CollectorRegistry,
    ConfigurationError,
    Evidence,
    PartialCollectionError,
    RateLimitError,
)
from nisify.collectors.datadog_collector import DatadogCollector
from nisify.collectors.gitlab_collector import GitLabCollector
from nisify.collectors.google_collector import GoogleCollector
from nisify.collectors.jamf_collector import JamfCollector
from nisify.collectors.jira_collector import JiraCollector
from nisify.collectors.notion_collector import NotionCollector
from nisify.collectors.okta_collector import OktaCollector
from nisify.collectors.slab_collector import SlabCollector
from nisify.collectors.snowflake_collector import SnowflakeCollector
from nisify.collectors.spotdraft_collector import SpotDraftCollector
from nisify.collectors.zendesk_collector import ZendeskCollector
from nisify.collectors.zoom_collector import ZoomCollector

__all__ = [
    # Base classes and types
    "BaseCollector",
    "Evidence",
    "CollectionResult",
    "CollectorRegistry",
    # Error classes
    "CollectorError",
    "AuthenticationError",
    "RateLimitError",
    "CollectorConnectionError",
    "PartialCollectionError",
    "ConfigurationError",
    # Platform collectors
    "AwsCollector",
    "OktaCollector",
    "JamfCollector",
    "GoogleCollector",
    "SnowflakeCollector",
    "DatadogCollector",
    "GitLabCollector",
    "JiraCollector",
    "ZendeskCollector",
    "ZoomCollector",
    "NotionCollector",
    "SlabCollector",
    "SpotDraftCollector",
]
