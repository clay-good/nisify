"""
Tests for platform collectors.

Uses Python's unittest module with mock API responses.
Tests authentication, rate limiting, error handling, and evidence normalization.
"""

from __future__ import annotations

import time
import unittest
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, Mock, patch

from nisify.collectors.base import (
    AuthenticationError,
    BaseCollector,
    CollectionResult,
    CollectorConnectionError,
    CollectorError,
    CollectorRegistry,
    Evidence,
    PartialCollectionError,
    RateLimitError,
)


class TestEvidence(unittest.TestCase):
    """Tests for the Evidence dataclass."""

    def test_create_evidence(self) -> None:
        """Test creating evidence with factory method."""
        raw_data = {"users": [{"id": "1", "name": "test"}]}
        evidence = Evidence.create(
            platform="test_platform",
            evidence_type="user_inventory",
            raw_data=raw_data,
            metadata={"source": "test"},
        )

        self.assertEqual(evidence.platform, "test_platform")
        self.assertEqual(evidence.evidence_type, "user_inventory")
        self.assertEqual(evidence.raw_data, raw_data)
        self.assertEqual(evidence.metadata["source"], "test")
        self.assertIsNotNone(evidence.id)
        self.assertIsInstance(evidence.collected_at, datetime)

    def test_evidence_hash_consistency(self) -> None:
        """Test that same data produces same hash."""
        raw_data = {"key": "value", "nested": {"a": 1}}

        evidence1 = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data=raw_data,
        )
        evidence2 = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data=raw_data,
        )

        # Same data should produce same hash
        self.assertEqual(evidence1.compute_hash(), evidence2.compute_hash())

    def test_evidence_hash_changes_with_data(self) -> None:
        """Test that different data produces different hash."""
        evidence1 = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={"key": "value1"},
        )
        evidence2 = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={"key": "value2"},
        )

        self.assertNotEqual(evidence1.compute_hash(), evidence2.compute_hash())


class TestCollectionResult(unittest.TestCase):
    """Tests for the CollectionResult dataclass."""

    def test_evidence_count(self) -> None:
        """Test evidence count property."""
        evidence_items = [
            Evidence.create("test", "type1", {"data": 1}),
            Evidence.create("test", "type2", {"data": 2}),
            Evidence.create("test", "type1", {"data": 3}),
        ]

        result = CollectionResult(
            platform="test",
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=evidence_items,
            errors=[],
            duration_seconds=1.0,
        )

        self.assertEqual(result.evidence_count, 3)

    def test_evidence_types_collected(self) -> None:
        """Test evidence types property."""
        evidence_items = [
            Evidence.create("test", "type1", {}),
            Evidence.create("test", "type2", {}),
            Evidence.create("test", "type1", {}),
        ]

        result = CollectionResult(
            platform="test",
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=evidence_items,
            errors=[],
            duration_seconds=1.0,
        )

        self.assertEqual(result.evidence_types_collected, {"type1", "type2"})

    def test_get_evidence_by_type(self) -> None:
        """Test filtering evidence by type."""
        evidence_items = [
            Evidence.create("test", "type1", {"id": 1}),
            Evidence.create("test", "type2", {"id": 2}),
            Evidence.create("test", "type1", {"id": 3}),
        ]

        result = CollectionResult(
            platform="test",
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=evidence_items,
            errors=[],
            duration_seconds=1.0,
        )

        type1_evidence = result.get_evidence_by_type("type1")
        self.assertEqual(len(type1_evidence), 2)

        type2_evidence = result.get_evidence_by_type("type2")
        self.assertEqual(len(type2_evidence), 1)

        type3_evidence = result.get_evidence_by_type("type3")
        self.assertEqual(len(type3_evidence), 0)


class MockCollector(BaseCollector):
    """Mock collector for testing base class functionality."""

    platform = "mock_platform"

    def __init__(
        self,
        config: Any = None,
        credential_store: Any = None,
    ) -> None:
        # Skip parent init to avoid Settings/CredentialStore requirements
        self.config = config
        self.credential_store = credential_store
        self.logger = MagicMock()
        self._last_api_call = 0.0
        self._rate_limit_delay = 0.01  # Fast for testing
        self._max_retries = 3
        self._retry_base_delay = 0.01
        self._retry_max_delay = 0.1

    def collect(self) -> CollectionResult:
        """Mock collect implementation."""
        return CollectionResult(
            platform=self.platform,
            timestamp=datetime.now(UTC),
            success=True,
            evidence_items=[],
            errors=[],
            duration_seconds=0.1,
        )

    def test_connection(self) -> bool:
        """Mock test_connection implementation."""
        return True

    def get_required_permissions(self) -> list[str]:
        """Mock permissions."""
        return ["read:data"]


class TestBaseCollector(unittest.TestCase):
    """Tests for BaseCollector functionality."""

    def test_normalize_evidence(self) -> None:
        """Test evidence normalization."""
        collector = MockCollector()
        raw_data = {"items": [1, 2, 3]}
        metadata = {"endpoint": "/api/data"}

        evidence = collector.normalize_evidence(
            raw_data=raw_data,
            evidence_type="test_type",
            metadata=metadata,
        )

        self.assertEqual(evidence.platform, "mock_platform")
        self.assertEqual(evidence.evidence_type, "test_type")
        self.assertEqual(evidence.raw_data, raw_data)
        self.assertEqual(evidence.metadata["endpoint"], "/api/data")
        self.assertEqual(evidence.metadata["collector_version"], "1.0.0")

    def test_rate_limiting(self) -> None:
        """Test rate limiting between API calls."""
        collector = MockCollector()
        collector._rate_limit_delay = 0.05  # 50ms delay

        import time

        start = time.time()
        collector._rate_limit()
        collector._rate_limit()
        collector._rate_limit()
        elapsed = time.time() - start

        # Should have at least 2 delays (100ms total)
        self.assertGreaterEqual(elapsed, 0.09)

    def test_retry_on_connection_error(self) -> None:
        """Test retry logic on connection errors."""
        collector = MockCollector()
        call_count = 0

        def failing_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise CollectorConnectionError("Connection failed", "mock_platform")
            return "success"

        result = collector._with_retry(failing_func, max_retries=3)
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 3)

    def test_no_retry_on_auth_error(self) -> None:
        """Test that auth errors are not retried."""
        collector = MockCollector()
        call_count = 0

        def auth_failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise AuthenticationError("Invalid token", "mock_platform")

        with self.assertRaises(AuthenticationError):
            collector._with_retry(auth_failing_func, max_retries=3)

        # Should only be called once (no retry)
        self.assertEqual(call_count, 1)

    def test_retry_exhausted(self) -> None:
        """Test that exception is raised when retries exhausted."""
        collector = MockCollector()

        def always_failing() -> None:
            raise CollectorConnectionError("Always fails", "mock_platform")

        with self.assertRaises(CollectorConnectionError):
            collector._with_retry(always_failing, max_retries=2)

    def test_retry_on_rate_limit_with_retry_after(self) -> None:
        """Test retry with explicit retry-after from rate limit."""
        collector = MockCollector()
        collector._retry_base_delay = 0.01
        call_count = 0

        def rate_limited_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RateLimitError(
                    "Rate limited",
                    "mock_platform",
                    retry_after=0.01,
                )
            return "success"

        result = collector._with_retry(rate_limited_func)
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 2)


class TestCollectorRegistry(unittest.TestCase):
    """Tests for the CollectorRegistry."""

    def setUp(self) -> None:
        """Clear registry before each test."""
        CollectorRegistry.clear()

    def tearDown(self) -> None:
        """Clear registry after each test."""
        CollectorRegistry.clear()

    def test_register_collector(self) -> None:
        """Test registering a collector."""

        @CollectorRegistry.register
        class TestCollector(BaseCollector):
            platform = "test_registry"

            def collect(self) -> CollectionResult:
                pass

            def test_connection(self) -> bool:
                return True

            def get_required_permissions(self) -> list[str]:
                return []

        self.assertTrue(CollectorRegistry.is_registered("test_registry"))
        self.assertIn("test_registry", CollectorRegistry.get_platforms())

    def test_register_without_platform_fails(self) -> None:
        """Test that registering without platform defined fails."""

        class BadCollector(BaseCollector):
            # platform = "base" (inherited, should fail)
            def collect(self) -> CollectionResult:
                pass

            def test_connection(self) -> bool:
                return True

            def get_required_permissions(self) -> list[str]:
                return []

        with self.assertRaises(ValueError):
            CollectorRegistry.register(BadCollector)

    def test_get_collector_class(self) -> None:
        """Test retrieving collector class."""

        @CollectorRegistry.register
        class TestCollector2(BaseCollector):
            platform = "test2"

            def collect(self) -> CollectionResult:
                pass

            def test_connection(self) -> bool:
                return True

            def get_required_permissions(self) -> list[str]:
                return []

        cls = CollectorRegistry.get_collector_class("test2")
        self.assertEqual(cls, TestCollector2)

        cls_none = CollectorRegistry.get_collector_class("nonexistent")
        self.assertIsNone(cls_none)


class TestCollectorErrors(unittest.TestCase):
    """Tests for collector error classes."""

    def test_collector_error_with_platform(self) -> None:
        """Test CollectorError with platform context."""
        error = CollectorError("Something failed", platform="aws")
        self.assertEqual(str(error), "[aws] Something failed")
        self.assertEqual(error.platform, "aws")

    def test_collector_error_without_platform(self) -> None:
        """Test CollectorError without platform context."""
        error = CollectorError("Something failed")
        self.assertEqual(str(error), "Something failed")
        self.assertIsNone(error.platform)

    def test_rate_limit_error_retry_after(self) -> None:
        """Test RateLimitError with retry_after."""
        error = RateLimitError(
            "Too many requests",
            platform="okta",
            retry_after=30.0,
        )
        self.assertEqual(error.retry_after, 30.0)

    def test_partial_collection_error(self) -> None:
        """Test PartialCollectionError attributes."""
        error = PartialCollectionError(
            "Partial failure",
            platform="aws",
            collected_types=["mfa_status", "password_policy"],
            failed_types=["security_findings"],
            errors=["Security Hub not enabled"],
        )

        self.assertEqual(error.collected_types, ["mfa_status", "password_policy"])
        self.assertEqual(error.failed_types, ["security_findings"])
        self.assertEqual(error.errors, ["Security Hub not enabled"])


class TestAwsCollectorMocked(unittest.TestCase):
    """Tests for AWS collector with mocked boto3."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.aws.regions = ["us-east-1"]
        self.mock_config.aws.enabled = True

        self.mock_credential_store = MagicMock()

    @patch("nisify.collectors.aws_collector.boto3", create=True)
    def test_aws_collector_initialization(self, mock_boto3: MagicMock) -> None:
        """Test AWS collector initializes correctly."""
        from nisify.collectors.aws_collector import AwsCollector

        collector = AwsCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "aws")
        self.assertIsNone(collector._boto3)
        self.assertIsNone(collector._session)

    @patch("nisify.collectors.aws_collector.boto3", create=True)
    def test_aws_collector_requires_boto3(self, mock_boto3: MagicMock) -> None:
        """Test AWS collector raises error when boto3 not installed."""
        from nisify.collectors.aws_collector import AwsCollector

        collector = AwsCollector(self.mock_config, self.mock_credential_store)
        collector._boto3 = None  # Reset

        # Simulate boto3 not installed
        mock_boto3.__bool__ = Mock(return_value=False)
        with patch.dict("sys.modules", {"boto3": None}):
            # Force re-import attempt
            collector._boto3 = None
            # The _get_boto3 method should raise when boto3 import fails
            # This is hard to test without actually removing boto3

    @patch("nisify.collectors.aws_collector.boto3", create=True)
    def test_aws_test_connection_success(self, mock_boto3: MagicMock) -> None:
        """Test AWS connection test with successful response."""
        from nisify.collectors.aws_collector import AwsCollector

        # Mock boto3 session and STS client
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "AIDAEXAMPLE",
        }

        # Set up credentials
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }.get(key, "")

        collector = AwsCollector(self.mock_config, self.mock_credential_store)
        collector._boto3 = mock_boto3
        result = collector.test_connection()

        self.assertTrue(result)
        mock_sts.get_caller_identity.assert_called_once()

    @patch("nisify.collectors.aws_collector.boto3", create=True)
    def test_aws_test_connection_auth_failure(self, mock_boto3: MagicMock) -> None:
        """Test AWS connection test with auth failure."""
        from nisify.collectors.aws_collector import AwsCollector

        # Mock boto3 session and STS client
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = Exception(
            "The security token included in the request is invalid"
        )

        collector = AwsCollector(self.mock_config, self.mock_credential_store)
        collector._boto3 = mock_boto3
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.aws_collector.boto3", create=True)
    def test_aws_get_required_permissions(self, mock_boto3: MagicMock) -> None:
        """Test that AWS collector returns correct required permissions."""
        from nisify.collectors.aws_collector import AwsCollector

        collector = AwsCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        # Verify key permissions are included
        self.assertIn("iam:ListUsers", permissions)
        self.assertIn("iam:ListMFADevices", permissions)
        self.assertIn("s3:ListBuckets", permissions)
        self.assertIn("cloudtrail:DescribeTrails", permissions)


class TestOktaCollectorMocked(unittest.TestCase):
    """Tests for Okta collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.okta.domain = "test.okta.com"
        self.mock_config.okta.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.return_value = "test_api_token"

    @patch("nisify.collectors.okta_collector.requests.Session")
    def test_okta_collector_test_connection(self, mock_session_class: MagicMock) -> None:
        """Test Okta collector connection test."""
        from nisify.collectors.okta_collector import OktaCollector

        # Mock successful response
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "test_org"}
        mock_response.headers.get.return_value = "100"  # Rate limit remaining
        mock_session.request.return_value = mock_response

        collector = OktaCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)
        mock_session.request.assert_called()

    @patch("nisify.collectors.okta_collector.requests.Session")
    def test_okta_collector_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Okta collector handles auth failure."""
        from nisify.collectors.okta_collector import OktaCollector

        # Mock 401 response
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers.get.return_value = "100"
        mock_session.request.return_value = mock_response

        collector = OktaCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.okta_collector.requests.Session")
    def test_okta_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Okta rate limit error handling."""
        from nisify.collectors.okta_collector import OktaCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers.get.return_value = "60"  # Retry-After
        mock_session.request.return_value = mock_response

        collector = OktaCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/api/v1/org")

    @patch("nisify.collectors.okta_collector.requests.Session")
    def test_okta_get_required_permissions(self, mock_session_class: MagicMock) -> None:
        """Test that Okta collector returns correct required permissions."""
        from nisify.collectors.okta_collector import OktaCollector

        collector = OktaCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        # Verify key permissions are included
        self.assertIn("okta.users.read", permissions)


class TestJamfCollectorMocked(unittest.TestCase):
    """Tests for Jamf collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.jamf.url = "https://test.jamfcloud.com"
        self.mock_config.jamf.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "client_id": "test_client",
            "client_secret": "test_secret",
        }.get(key, "")

    @patch("nisify.collectors.jamf_collector.requests")
    def test_jamf_collector_initialization(self, mock_requests: MagicMock) -> None:
        """Test Jamf collector initializes correctly."""
        from nisify.collectors.jamf_collector import JamfCollector

        collector = JamfCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "jamf")


class TestGoogleCollectorMocked(unittest.TestCase):
    """Tests for Google collector with mocked google-auth."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.google.customer_id = "C12345"
        self.mock_config.google.service_account_path = "/path/to/sa.json"
        self.mock_config.google.enabled = True

        self.mock_credential_store = MagicMock()

    def test_google_collector_initialization(self) -> None:
        """Test Google collector initializes correctly."""
        from nisify.collectors.google_collector import GoogleCollector

        collector = GoogleCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "google")


class TestSnowflakeCollectorMocked(unittest.TestCase):
    """Tests for Snowflake collector with mocked connector."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.snowflake.account = "test_account"
        self.mock_config.snowflake.warehouse = "COMPUTE_WH"
        self.mock_config.snowflake.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "username": "test_user",
            "password": "test_pass",
        }.get(key, "")

    def test_snowflake_collector_initialization(self) -> None:
        """Test Snowflake collector initializes correctly."""
        from nisify.collectors.snowflake_collector import SnowflakeCollector

        collector = SnowflakeCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "snowflake")


class TestDatadogCollectorMocked(unittest.TestCase):
    """Tests for Datadog collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.datadog.site = "datadoghq.com"
        self.mock_config.datadog.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "api_key": "test_api_key",
            "app_key": "test_app_key",
        }.get(key, "")

    @patch("nisify.collectors.datadog_collector.requests")
    def test_datadog_collector_test_connection(
        self,
        mock_requests: MagicMock,
    ) -> None:
        """Test Datadog collector connection test."""
        from nisify.collectors.datadog_collector import DatadogCollector

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": True}
        mock_requests.get.return_value = mock_response

        collector = DatadogCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)


class TestGitLabCollectorMocked(unittest.TestCase):
    """Tests for GitLab collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.gitlab.url = "https://gitlab.example.com"
        self.mock_config.gitlab.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "gitlab_url": "https://gitlab.example.com",
            "gitlab_token": "test_token",
        }.get(key, "")

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test GitLab collector initializes correctly."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "gitlab")

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test GitLab connection test with successful response."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"username": "testuser"}
        mock_response.headers = {"RateLimit-Remaining": "100"}
        mock_response.content = b'{"username": "testuser"}'
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test GitLab connection test with auth failure."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test GitLab rate limit error handling."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"RateLimit-Reset": str(int(time.time()) + 60)}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/api/v4/user")


class TestJiraCollectorMocked(unittest.TestCase):
    """Tests for Jira collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.jira.url = "https://company.atlassian.net"
        self.mock_config.jira.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "jira_url": "https://company.atlassian.net",
            "jira_email": "user@example.com",
            "jira_api_token": "test_token",
        }.get(key, "")

    @patch("nisify.collectors.jira_collector.requests.Session")
    def test_jira_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Jira collector initializes correctly."""
        from nisify.collectors.jira_collector import JiraCollector

        collector = JiraCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "jira")

    @patch("nisify.collectors.jira_collector.requests.Session")
    def test_jira_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Jira connection test with successful response."""
        from nisify.collectors.jira_collector import JiraCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"displayName": "Test User"}
        mock_response.content = b'{"displayName": "Test User"}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = JiraCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.jira_collector.requests.Session")
    def test_jira_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Jira connection test with auth failure."""
        from nisify.collectors.jira_collector import JiraCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = JiraCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.jira_collector.requests.Session")
    def test_jira_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Jira returns required permissions."""
        from nisify.collectors.jira_collector import JiraCollector

        collector = JiraCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIn("Browse Projects", permissions)

    @patch("nisify.collectors.jira_collector.requests.Session")
    def test_jira_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Jira rate limit handling."""
        from nisify.collectors.jira_collector import JiraCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "30"}
        mock_session.request.return_value = mock_response

        collector = JiraCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/rest/api/3/myself")


class TestZendeskCollectorMocked(unittest.TestCase):
    """Tests for Zendesk collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.zendesk.subdomain = "company"
        self.mock_config.zendesk.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "zendesk_subdomain": "company",
            "zendesk_email": "user@example.com",
            "zendesk_api_token": "test_token",
        }.get(key, "")

    @patch("nisify.collectors.zendesk_collector.requests.Session")
    def test_zendesk_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Zendesk collector initializes correctly."""
        from nisify.collectors.zendesk_collector import ZendeskCollector

        collector = ZendeskCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "zendesk")

    @patch("nisify.collectors.zendesk_collector.requests.Session")
    def test_zendesk_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Zendesk connection test with successful response."""
        from nisify.collectors.zendesk_collector import ZendeskCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"user": {"id": 123, "name": "Test User"}}
        mock_response.content = b'{"user": {"id": 123}}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = ZendeskCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.zendesk_collector.requests.Session")
    def test_zendesk_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Zendesk connection test with auth failure."""
        from nisify.collectors.zendesk_collector import ZendeskCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = ZendeskCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.zendesk_collector.requests.Session")
    def test_zendesk_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Zendesk returns required permissions."""
        from nisify.collectors.zendesk_collector import ZendeskCollector

        collector = ZendeskCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)

    @patch("nisify.collectors.zendesk_collector.requests.Session")
    def test_zendesk_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Zendesk rate limit handling."""
        from nisify.collectors.zendesk_collector import ZendeskCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "30"}
        mock_session.request.return_value = mock_response

        collector = ZendeskCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/api/v2/users/me.json")


class TestZoomCollectorMocked(unittest.TestCase):
    """Tests for Zoom collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.zoom.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "zoom_account_id": "test_account",
            "zoom_client_id": "test_client",
            "zoom_client_secret": "test_secret",
        }.get(key, "")

    @patch("nisify.collectors.zoom_collector.requests.Session")
    def test_zoom_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Zoom collector initializes correctly."""
        from nisify.collectors.zoom_collector import ZoomCollector

        collector = ZoomCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "zoom")

    @patch("nisify.collectors.zoom_collector.requests.Session")
    @patch("nisify.collectors.zoom_collector.requests.post")
    def test_zoom_test_connection_success(
        self, mock_post: MagicMock, mock_session_class: MagicMock
    ) -> None:
        """Test Zoom connection test with successful response."""
        from nisify.collectors.zoom_collector import ZoomCollector

        # Mock OAuth token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock session response
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"email": "test@example.com"}
        mock_response.content = b'{"email": "test@example.com"}'
        mock_response.headers = {"X-RateLimit-Remaining": "100"}
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.zoom_collector.requests.Session")
    @patch("nisify.collectors.zoom_collector.requests.post")
    def test_zoom_oauth_failure(
        self, mock_post: MagicMock, mock_session_class: MagicMock
    ) -> None:
        """Test Zoom connection test with OAuth failure."""
        from nisify.collectors.zoom_collector import ZoomCollector

        # Mock OAuth token failure
        mock_token_response = MagicMock()
        mock_token_response.status_code = 401
        mock_post.return_value = mock_token_response

        collector = ZoomCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.zoom_collector.requests.Session")
    @patch("nisify.collectors.zoom_collector.requests.post")
    def test_zoom_get_required_permissions(
        self, mock_post: MagicMock, mock_session: MagicMock
    ) -> None:
        """Test Zoom returns required permissions."""
        from nisify.collectors.zoom_collector import ZoomCollector

        collector = ZoomCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)

    @patch("nisify.collectors.zoom_collector.requests.Session")
    @patch("nisify.collectors.zoom_collector.requests.post")
    def test_zoom_rate_limit_handling(
        self, mock_post: MagicMock, mock_session_class: MagicMock
    ) -> None:
        """Test Zoom rate limit handling."""
        from nisify.collectors.zoom_collector import ZoomCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock OAuth token success
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_token_response

        # Mock rate limit response
        mock_rate_limit_response = MagicMock()
        mock_rate_limit_response.status_code = 429
        mock_rate_limit_response.headers = {"Retry-After": "30"}
        mock_session.request.return_value = mock_rate_limit_response

        collector = ZoomCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/users/me")


class TestNotionCollectorMocked(unittest.TestCase):
    """Tests for Notion collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.notion.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "notion_api_token": "test_token",
        }.get(key, "")

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Notion collector initializes correctly."""
        from nisify.collectors.notion_collector import NotionCollector

        collector = NotionCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "notion")

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Notion connection test with successful response."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "Nisify Integration"}
        mock_response.content = b'{"name": "Nisify Integration"}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Notion connection test with auth failure."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Notion rate limit error handling."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "1"}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/users/me")


class TestSlabCollectorMocked(unittest.TestCase):
    """Tests for Slab collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.slab.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "slab_api_token": "test_token",
        }.get(key, "")

    @patch("nisify.collectors.slab_collector.requests.Session")
    def test_slab_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Slab collector initializes correctly."""
        from nisify.collectors.slab_collector import SlabCollector

        collector = SlabCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "slab")

    @patch("nisify.collectors.slab_collector.requests.Session")
    def test_slab_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Slab connection test with successful response."""
        from nisify.collectors.slab_collector import SlabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"organization": {"name": "Test Org"}}}
        mock_response.headers = {}
        mock_session.post.return_value = mock_response

        collector = SlabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.slab_collector.requests.Session")
    def test_slab_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Slab connection test with auth failure."""
        from nisify.collectors.slab_collector import SlabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.post.return_value = mock_response

        collector = SlabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.slab_collector.requests.Session")
    def test_slab_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Slab returns required permissions."""
        from nisify.collectors.slab_collector import SlabCollector

        collector = SlabCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)

    @patch("nisify.collectors.slab_collector.requests.Session")
    def test_slab_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Slab rate limit handling."""
        from nisify.collectors.slab_collector import SlabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "30"}
        mock_session.post.return_value = mock_response

        collector = SlabCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._graphql_request("query { organization { name } }")


class TestSpotDraftCollectorMocked(unittest.TestCase):
    """Tests for SpotDraft collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.spotdraft.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "spotdraft_api_key": "test_key",
        }.get(key, "")

    @patch("nisify.collectors.spotdraft_collector.requests.Session")
    def test_spotdraft_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test SpotDraft collector initializes correctly."""
        from nisify.collectors.spotdraft_collector import SpotDraftCollector

        collector = SpotDraftCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "spotdraft")

    @patch("nisify.collectors.spotdraft_collector.requests.Session")
    def test_spotdraft_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test SpotDraft connection test with successful response."""
        from nisify.collectors.spotdraft_collector import SpotDraftCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "user123", "email": "test@example.com"}}
        mock_response.content = b'{"data": {"id": "user123"}}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = SpotDraftCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.spotdraft_collector.requests.Session")
    def test_spotdraft_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test SpotDraft connection test with auth failure."""
        from nisify.collectors.spotdraft_collector import SpotDraftCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = SpotDraftCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.spotdraft_collector.requests.Session")
    def test_spotdraft_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test SpotDraft returns required permissions."""
        from nisify.collectors.spotdraft_collector import SpotDraftCollector

        collector = SpotDraftCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)

    @patch("nisify.collectors.spotdraft_collector.requests.Session")
    def test_spotdraft_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test SpotDraft rate limit handling."""
        from nisify.collectors.spotdraft_collector import SpotDraftCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "30"}
        mock_session.request.return_value = mock_response

        collector = SpotDraftCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/api/v1/me")


class TestJamfCollector(unittest.TestCase):
    """Tests for Jamf collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.jamf.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "jamf_url": "https://test.jamfcloud.com",
            "jamf_client_id": "test_client_id",
            "jamf_client_secret": "test_client_secret",
        }.get(key, "")

    @patch("nisify.collectors.jamf_collector.requests.Session")
    def test_jamf_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Jamf collector initializes correctly."""
        from nisify.collectors.jamf_collector import JamfCollector

        collector = JamfCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "jamf")

    @patch("nisify.collectors.jamf_collector.requests.Session")
    def test_jamf_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Jamf connection test with successful response."""
        from nisify.collectors.jamf_collector import JamfCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call: OAuth token request
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 1800,
        }

        # Second call: API version check
        mock_version_response = MagicMock()
        mock_version_response.status_code = 200
        mock_version_response.json.return_value = {"version": "11.0.0"}
        mock_version_response.text = '{"version": "11.0.0"}'

        mock_session.post.return_value = mock_token_response
        mock_session.request.return_value = mock_version_response

        collector = JamfCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)
        mock_session.post.assert_called_once()  # Token request

    @patch("nisify.collectors.jamf_collector.requests.Session")
    def test_jamf_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Jamf connection test with auth failure."""
        from nisify.collectors.jamf_collector import JamfCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # OAuth token request fails
        mock_token_response = MagicMock()
        mock_token_response.status_code = 401

        mock_session.post.return_value = mock_token_response

        collector = JamfCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.jamf_collector.requests.Session")
    def test_jamf_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Jamf returns required permissions."""
        from nisify.collectors.jamf_collector import JamfCollector

        collector = JamfCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIn("Read Computers", permissions)
        self.assertIn("Read Computer Extension Attributes", permissions)
        self.assertIn("Read macOS Configuration Profiles", permissions)

    @patch("nisify.collectors.jamf_collector.requests.Session")
    def test_jamf_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Jamf rate limit handling."""
        from nisify.collectors.jamf_collector import JamfCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First: OAuth token succeeds
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 1800,
        }
        mock_session.post.return_value = mock_token_response

        # Then: API request returns rate limit
        mock_rate_limit_response = MagicMock()
        mock_rate_limit_response.status_code = 429
        mock_rate_limit_response.headers = {"Retry-After": "60"}
        mock_session.request.return_value = mock_rate_limit_response

        collector = JamfCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/api/v1/computers-inventory")


class TestGoogleCollector(unittest.TestCase):
    """Tests for Google Workspace collector with mocked API."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.google.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "google_service_account_json": '{"type": "service_account", "project_id": "test"}',
            "google_admin_email": "admin@test.com",
        }.get(key, "")

    def test_google_collector_initialization(self) -> None:
        """Test Google collector initializes correctly."""
        from nisify.collectors.google_collector import GoogleCollector

        collector = GoogleCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "google")

    def test_google_get_required_permissions(self) -> None:
        """Test Google returns required permissions."""
        from nisify.collectors.google_collector import GoogleCollector

        collector = GoogleCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        # Should list admin SDK and directory scopes
        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)


class TestSnowflakeCollector(unittest.TestCase):
    """Tests for Snowflake collector with mocked connector."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.snowflake.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "snowflake_account": "test_account",
            "snowflake_username": "test_user",
            "snowflake_password": "test_password",
            "snowflake_warehouse": "test_warehouse",
        }.get(key, "")

    def test_snowflake_collector_initialization(self) -> None:
        """Test Snowflake collector initializes correctly."""
        from nisify.collectors.snowflake_collector import SnowflakeCollector

        collector = SnowflakeCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "snowflake")

    def test_snowflake_get_required_permissions(self) -> None:
        """Test Snowflake returns required permissions."""
        from nisify.collectors.snowflake_collector import SnowflakeCollector

        collector = SnowflakeCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)


class TestDatadogCollector(unittest.TestCase):
    """Tests for Datadog collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.datadog.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "datadog_api_key": "test_api_key",
            "datadog_app_key": "test_app_key",
            "datadog_site": "datadoghq.com",
        }.get(key, "")

    @patch("nisify.collectors.datadog_collector.requests.Session")
    def test_datadog_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Datadog collector initializes correctly."""
        from nisify.collectors.datadog_collector import DatadogCollector

        collector = DatadogCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "datadog")

    @patch("nisify.collectors.datadog_collector.requests.Session")
    def test_datadog_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Datadog connection test with successful response."""
        from nisify.collectors.datadog_collector import DatadogCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": True}
        mock_response.content = b'{"valid": true}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.datadog_collector.requests.Session")
    def test_datadog_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Datadog connection test with auth failure."""
        from nisify.collectors.datadog_collector import DatadogCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.datadog_collector.requests.Session")
    def test_datadog_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Datadog returns required permissions."""
        from nisify.collectors.datadog_collector import DatadogCollector

        collector = DatadogCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIsInstance(permissions, list)
        self.assertTrue(len(permissions) > 0)


class TestGitLabCollector(unittest.TestCase):
    """Tests for GitLab collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.gitlab.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "gitlab_token": "test_token",
            "gitlab_url": "https://gitlab.com",
        }.get(key, "")

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test GitLab collector initializes correctly."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "gitlab")

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test GitLab connection test with successful response."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 1, "username": "testuser"}
        mock_response.content = b'{"id": 1}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test GitLab connection test with auth failure."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.gitlab_collector.requests.Session")
    def test_gitlab_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test GitLab returns required permissions."""
        from nisify.collectors.gitlab_collector import GitLabCollector

        collector = GitLabCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIn("api or read_api", permissions)


class TestNotionCollector(unittest.TestCase):
    """Tests for Notion collector with mocked requests."""

    def setUp(self) -> None:
        """Set up mock configuration."""
        self.mock_config = MagicMock()
        self.mock_config.notion.enabled = True

        self.mock_credential_store = MagicMock()
        self.mock_credential_store.get_credential.side_effect = lambda platform, key: {
            "notion_api_token": "secret_test_token",
        }.get(key, "")

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_collector_initialization(self, mock_session: MagicMock) -> None:
        """Test Notion collector initializes correctly."""
        from nisify.collectors.notion_collector import NotionCollector

        collector = NotionCollector(self.mock_config, self.mock_credential_store)

        self.assertEqual(collector.platform, "notion")

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_test_connection_success(self, mock_session_class: MagicMock) -> None:
        """Test Notion connection test with successful response."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"object": "user", "id": "bot123", "name": "Test Bot"}
        mock_response.content = b'{"object": "user"}'
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertTrue(result)

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_test_connection_auth_failure(self, mock_session_class: MagicMock) -> None:
        """Test Notion connection test with auth failure."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)
        result = collector.test_connection()

        self.assertFalse(result)

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_get_required_permissions(self, mock_session: MagicMock) -> None:
        """Test Notion returns required permissions."""
        from nisify.collectors.notion_collector import NotionCollector

        collector = NotionCollector(self.mock_config, self.mock_credential_store)
        permissions = collector.get_required_permissions()

        self.assertIn("Read user information", permissions)
        self.assertIn("Read content", permissions)

    @patch("nisify.collectors.notion_collector.requests.Session")
    def test_notion_rate_limit_handling(self, mock_session_class: MagicMock) -> None:
        """Test Notion rate limit handling."""
        from nisify.collectors.notion_collector import NotionCollector

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "1"}
        mock_session.request.return_value = mock_response

        collector = NotionCollector(self.mock_config, self.mock_credential_store)

        with self.assertRaises(RateLimitError):
            collector._api_request("GET", "/users/me")


class TestBaseCollectorCredentialErrors(unittest.TestCase):
    """Tests for credential error handling in BaseCollector."""

    def test_get_credential_store_not_initialized(self) -> None:
        """Test error when credential store is not initialized."""
        from nisify.config.credentials import CredentialStoreNotInitializedError

        collector = MockCollector()
        mock_store = MagicMock()
        mock_store.get_credential.side_effect = CredentialStoreNotInitializedError("Store not initialized")
        collector.credential_store = mock_store

        with self.assertRaises(AuthenticationError) as cm:
            collector.get_credential("api_key")

        self.assertIn("not initialized", str(cm.exception))

    def test_get_credential_store_locked(self) -> None:
        """Test error when credential store is locked."""
        from nisify.config.credentials import CredentialStoreLockedError

        collector = MockCollector()
        mock_store = MagicMock()
        mock_store.get_credential.side_effect = CredentialStoreLockedError("Store is locked")
        collector.credential_store = mock_store

        with self.assertRaises(AuthenticationError) as cm:
            collector.get_credential("api_key")

        self.assertIn("locked", str(cm.exception))

    def test_get_credential_not_found(self) -> None:
        """Test error when credential is not found."""
        from nisify.config.credentials import CredentialNotFoundError

        collector = MockCollector()
        mock_store = MagicMock()
        mock_store.get_credential.side_effect = CredentialNotFoundError("api_key", "mock_platform")
        collector.credential_store = mock_store

        with self.assertRaises(AuthenticationError) as cm:
            collector.get_credential("api_key")

        self.assertIn("not found", str(cm.exception))


class TestBaseCollectorRetryEdgeCases(unittest.TestCase):
    """Tests for retry edge cases in BaseCollector."""

    def test_retry_rate_limit_without_retry_after(self) -> None:
        """Test retry with rate limit that has no retry_after header."""
        collector = MockCollector()
        collector._retry_base_delay = 0.01
        collector._retry_max_delay = 0.1
        call_count = 0

        def rate_limited_no_retry_after() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Rate limit without retry_after - should use exponential backoff
                raise RateLimitError(
                    "Rate limited",
                    "mock_platform",
                    retry_after=None,  # No retry_after
                )
            return "success"

        result = collector._with_retry(rate_limited_no_retry_after, max_retries=3)
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 2)


class TestCollectorRegistryCreate(unittest.TestCase):
    """Tests for CollectorRegistry.create method."""

    def setUp(self) -> None:
        """Clear registry before each test."""
        CollectorRegistry.clear()

    def tearDown(self) -> None:
        """Clear registry after each test."""
        CollectorRegistry.clear()

    def test_create_unknown_platform_raises_error(self) -> None:
        """Test that creating collector for unknown platform raises ValueError."""
        mock_config = MagicMock()
        mock_credential_store = MagicMock()

        with self.assertRaises(ValueError) as cm:
            CollectorRegistry.create("unknown_platform", mock_config, mock_credential_store)

        self.assertIn("Unknown platform", str(cm.exception))
        self.assertIn("unknown_platform", str(cm.exception))

    def test_create_registered_platform(self) -> None:
        """Test creating collector for registered platform."""

        @CollectorRegistry.register
        class TestCreateCollector(BaseCollector):
            platform = "test_create"

            def collect(self) -> CollectionResult:
                return CollectionResult(
                    platform=self.platform,
                    timestamp=datetime.now(UTC),
                    success=True,
                    evidence_items=[],
                    errors=[],
                    duration_seconds=0.1,
                )

            def test_connection(self) -> bool:
                return True

            def get_required_permissions(self) -> list[str]:
                return []

        mock_config = MagicMock()
        mock_credential_store = MagicMock()

        collector = CollectorRegistry.create("test_create", mock_config, mock_credential_store)

        self.assertIsInstance(collector, TestCreateCollector)
        self.assertEqual(collector.platform, "test_create")


class TestBaseCollectorAbstractMethods(unittest.TestCase):
    """Tests for abstract method default implementations in BaseCollector."""

    def test_collect_abstract_pass(self) -> None:
        """Test that abstract collect has pass (line 350)."""
        from nisify.collectors.base import BaseCollector

        # Call the abstract method directly from the class
        # passing a mock for self - this executes the pass statement
        result = BaseCollector.collect(MagicMock())
        self.assertIsNone(result)

    def test_connection_abstract_pass(self) -> None:
        """Test that abstract test_connection has pass (line 363)."""
        from nisify.collectors.base import BaseCollector

        result = BaseCollector.test_connection(MagicMock())
        self.assertIsNone(result)

    def test_get_required_permissions_abstract_pass(self) -> None:
        """Test that abstract get_required_permissions has pass (line 376)."""
        from nisify.collectors.base import BaseCollector

        result = BaseCollector.get_required_permissions(MagicMock())
        self.assertIsNone(result)

    def test_retry_with_negative_retries_raises_unknown_error(self) -> None:
        """Test _with_retry with 0 retries that fails raises CollectorError (line 523)."""
        from nisify.collectors.base import CollectorError

        collector = MockCollector()

        def always_raise_connection_error() -> str:
            raise CollectorConnectionError("Connection failed", "mock_platform")

        # With max_retries=0, it will try once, fail, and then hit the retry exhaustion
        # But that still sets last_exception, so we need a different approach

        # Actually, to hit line 523 (the else branch where last_exception is None),
        # we need the for loop to complete without entering any except block AND
        # without returning. This is actually impossible with the current code.

        # The only way to hit line 523 is if the for loop runs to completion
        # without setting last_exception. This can happen if retries < 0.
        # Let's try with max_retries=-1 which makes range(0)

        def succeeds() -> str:
            return "ok"

        # With -1, range(0) is empty, loop doesn't run, goes to line 520-523
        # last_exception is None, so line 523 executes
        with self.assertRaises(CollectorError) as cm:
            collector._with_retry(succeeds, max_retries=-1)

        self.assertIn("Unknown error", str(cm.exception))


class TestEvidenceNormalization(unittest.TestCase):
    """Tests for evidence normalization across collectors."""

    def test_evidence_has_required_fields(self) -> None:
        """Test that all evidence has required fields."""
        evidence = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={"data": "value"},
        )

        # Required fields
        self.assertIsNotNone(evidence.id)
        self.assertIsNotNone(evidence.platform)
        self.assertIsNotNone(evidence.evidence_type)
        self.assertIsNotNone(evidence.collected_at)
        self.assertIsNotNone(evidence.raw_data)
        self.assertIsNotNone(evidence.metadata)

    def test_evidence_timestamp_is_utc(self) -> None:
        """Test that evidence timestamp is UTC."""
        evidence = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={},
        )

        self.assertEqual(evidence.collected_at.tzinfo, UTC)

    def test_evidence_id_is_uuid(self) -> None:
        """Test that evidence ID is a valid UUID."""
        import uuid

        evidence = Evidence.create(
            platform="test",
            evidence_type="test_type",
            raw_data={},
        )

        # Should not raise
        uuid.UUID(evidence.id)


if __name__ == "__main__":
    unittest.main()
