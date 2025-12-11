"""
Slab collector for Nisify.

Collects security evidence from Slab including users, posts, topics,
and access permissions. All API calls are read-only.

Required Slab Permissions:
    - API access enabled for your organization
    - Read access to users and content

Authentication:
    Credentials are retrieved from the credential store with keys:
    - slab_api_token: API token from Slab settings
    - slab_organization: Organization slug (optional, for URL construction)

    Get your API token from: Settings > Integrations > API

Rate Limiting:
    Slab API has rate limits. This collector:
    - Uses conservative delays between requests
    - Implements exponential backoff on 429 responses
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
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
class SlabCollector(BaseCollector):
    """
    Slab evidence collector.

    Collects security-relevant evidence from Slab:
        - User directory (user_inventory)
        - Posts/documentation (data_inventory)
        - Topics/organization (topic_structure)
        - Access and sharing (access_control)

    Evidence Types Collected:
        - user_inventory: All users in the organization
        - data_inventory: Posts and their metadata
        - topic_structure: Topic hierarchy and organization
        - access_control: Sharing and permission settings

    Example:
        collector = SlabCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "slab"
    default_rate_limit_delay = 0.2

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Slab collector.

        Args:
            config: Settings object containing Slab configuration.
            credential_store: Credential store for retrieving Slab credentials.
        """
        super().__init__(config, credential_store)
        self._base_url = "https://api.slab.com/v1"
        self._graphql_url = "https://api.slab.com/v1/graphql"
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
        api_token = self.get_credential("slab_api_token")

        # Create session with auth headers
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        return self._session

    def _graphql_request(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        """
        Make a GraphQL request to Slab.

        Args:
            query: GraphQL query string.
            variables: Query variables.

        Returns:
            Tuple of (response data, response headers).

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limit is exceeded.
            CollectorConnectionError: If connection fails.
        """
        session = self._get_session()

        start_time = time.time()
        self._rate_limit()

        try:
            response = session.post(
                self._graphql_url,
                json={"query": query, "variables": variables or {}},
                timeout=30,
            )
            duration_ms = (time.time() - start_time) * 1000
            self._log_api_call("POST", "/graphql", response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Slab rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else 60,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Slab authentication failed. Check your API token.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Slab permission denied. Check API token permissions.",
                    platform=self.platform,
                )

            response.raise_for_status()

            data = response.json()
            if "errors" in data:
                error_msg = data["errors"][0].get("message", "Unknown GraphQL error")
                raise CollectorConnectionError(
                    f"Slab GraphQL error: {error_msg}",
                    platform=self.platform,
                )

            return data.get("data", {}), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Slab: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Slab request timed out: {e}",
                platform=self.platform,
            )

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Slab permission strings.
        """
        return [
            "API access enabled",
            "Read access to organization content",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Slab.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            query = """
            query {
                organization {
                    name
                    id
                }
            }
            """
            data, _ = self._graphql_request(query)
            org = data.get("organization", {})
            self.logger.info(
                f"Slab connection successful. Organization: {org.get('name')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Slab connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Slab.

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
            ("data_inventory", self._collect_posts),
            ("topic_structure", self._collect_topics),
            ("access_control", self._collect_access_settings),
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
        query = """
        query {
            organization {
                members {
                    id
                    email
                    name
                    role
                    status
                    createdAt
                    lastActiveAt
                }
            }
        }
        """

        data, _ = self._graphql_request(query)
        members = data.get("organization", {}).get("members", [])

        user_data = []
        for member in members:
            user_data.append(
                {
                    "id": member.get("id"),
                    "email": member.get("email"),
                    "name": member.get("name"),
                    "role": member.get("role"),
                    "status": member.get("status"),
                    "created_at": member.get("createdAt"),
                    "last_active_at": member.get("lastActiveAt"),
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
                    "active_users": sum(1 for u in user_data if u.get("status") == "ACTIVE"),
                },
                "user_inventory",
                {"source": "slab_members"},
            )
        ]

    def _collect_posts(self) -> list[Evidence]:
        """
        Collect posts/documentation.

        Returns:
            List of Evidence items with data inventory.
        """
        query = """
        query($first: Int, $after: String) {
            organization {
                posts(first: $first, after: $after) {
                    edges {
                        node {
                            id
                            title
                            createdAt
                            updatedAt
                            visibility
                            author {
                                id
                                name
                            }
                            topic {
                                id
                                name
                            }
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
        }
        """

        all_posts = []
        after = None
        while True:
            data, _ = self._graphql_request(query, {"first": 100, "after": after})
            posts_data = data.get("organization", {}).get("posts", {})
            edges = posts_data.get("edges", [])

            for edge in edges:
                node = edge.get("node", {})
                all_posts.append(
                    {
                        "id": node.get("id"),
                        "title": node.get("title"),
                        "created_at": node.get("createdAt"),
                        "updated_at": node.get("updatedAt"),
                        "visibility": node.get("visibility"),
                        "author_id": node.get("author", {}).get("id"),
                        "author_name": node.get("author", {}).get("name"),
                        "topic_id": node.get("topic", {}).get("id"),
                        "topic_name": node.get("topic", {}).get("name"),
                    }
                )

            page_info = posts_data.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")

            if len(all_posts) >= 1000:
                break

        # Visibility breakdown
        visibility_counts: dict[str, int] = {}
        for post in all_posts:
            vis = post.get("visibility", "unknown")
            visibility_counts[vis] = visibility_counts.get(vis, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "posts": all_posts,
                    "total_posts": len(all_posts),
                    "visibility_counts": visibility_counts,
                },
                "data_inventory",
                {"source": "slab_posts"},
            )
        ]

    def _collect_topics(self) -> list[Evidence]:
        """
        Collect topic/folder structure.

        Returns:
            List of Evidence items with topic structure.
        """
        query = """
        query {
            organization {
                topics {
                    id
                    name
                    description
                    visibility
                    createdAt
                    postsCount
                    parentTopic {
                        id
                        name
                    }
                }
            }
        }
        """

        data, _ = self._graphql_request(query)
        topics = data.get("organization", {}).get("topics", [])

        topic_data = []
        for topic in topics:
            topic_data.append(
                {
                    "id": topic.get("id"),
                    "name": topic.get("name"),
                    "description": topic.get("description"),
                    "visibility": topic.get("visibility"),
                    "created_at": topic.get("createdAt"),
                    "posts_count": topic.get("postsCount"),
                    "parent_topic_id": topic.get("parentTopic", {}).get("id") if topic.get("parentTopic") else None,
                    "parent_topic_name": topic.get("parentTopic", {}).get("name") if topic.get("parentTopic") else None,
                }
            )

        return [
            self.normalize_evidence(
                {
                    "topics": topic_data,
                    "total_topics": len(topic_data),
                    "root_topics": sum(1 for t in topic_data if not t.get("parent_topic_id")),
                },
                "topic_structure",
                {"source": "slab_topics"},
            )
        ]

    def _collect_access_settings(self) -> list[Evidence]:
        """
        Collect access and sharing settings.

        Returns:
            List of Evidence items with access control data.
        """
        query = """
        query {
            organization {
                id
                name
                settings {
                    defaultPostVisibility
                    defaultTopicVisibility
                    allowPublicSharing
                    requireSso
                }
                domains {
                    domain
                    verified
                }
            }
        }
        """

        data, _ = self._graphql_request(query)
        org = data.get("organization", {})
        settings = org.get("settings", {})
        domains = org.get("domains", [])

        access_data = {
            "organization_id": org.get("id"),
            "organization_name": org.get("name"),
            "default_post_visibility": settings.get("defaultPostVisibility"),
            "default_topic_visibility": settings.get("defaultTopicVisibility"),
            "allow_public_sharing": settings.get("allowPublicSharing"),
            "require_sso": settings.get("requireSso"),
            "domains": [
                {"domain": d.get("domain"), "verified": d.get("verified")}
                for d in domains
            ],
        }

        return [
            self.normalize_evidence(
                {
                    "settings": access_data,
                    "sso_required": access_data.get("require_sso", False),
                    "public_sharing_allowed": access_data.get("allow_public_sharing", False),
                    "verified_domains": sum(1 for d in domains if d.get("verified")),
                },
                "access_control",
                {"source": "slab_settings"},
            )
        ]
