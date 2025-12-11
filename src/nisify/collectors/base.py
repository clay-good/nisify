"""
Base collector interface for evidence gathering.

This module provides the abstract base class for all platform collectors,
along with common data structures and error handling. All collectors inherit
from BaseCollector and implement platform-specific evidence gathering logic.

Design Principles:
    - All API calls are read-only (no write operations)
    - Collectors are independent and can run in isolation
    - Built-in rate limiting and retry logic
    - Evidence is normalized to a common schema
    - Failed collectors do not block other collectors
    - All actions are logged for audit trail
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nisify.config.credentials import CredentialStore
    from nisify.config.settings import Settings


# -----------------------------------------------------------------------------
# Error Classes
# -----------------------------------------------------------------------------


class CollectorError(Exception):
    """Base exception for collector errors."""

    def __init__(self, message: str, platform: str | None = None) -> None:
        self.message = message
        self.platform = platform
        super().__init__(f"[{platform}] {message}" if platform else message)


class AuthenticationError(CollectorError):
    """
    Raised when authentication with a platform fails.

    This includes invalid credentials, expired tokens, and permission denials.
    """

    pass


class RateLimitError(CollectorError):
    """
    Raised when a platform rate limit is exceeded.

    Attributes:
        retry_after: Seconds to wait before retrying (if provided by API).
    """

    def __init__(
        self,
        message: str,
        platform: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, platform)
        self.retry_after = retry_after


class CollectorConnectionError(CollectorError):
    """
    Raised when connection to a platform fails.

    This includes network errors, DNS failures, and timeout errors.
    Note: Named CollectorConnectionError to avoid shadowing built-in ConnectionError.
    """

    pass


class PartialCollectionError(CollectorError):
    """
    Raised when collection partially succeeds.

    Some evidence was collected, but errors occurred for some data types.

    Attributes:
        collected_types: Evidence types that were successfully collected.
        failed_types: Evidence types that failed to collect.
        errors: List of error messages for failed types.
    """

    def __init__(
        self,
        message: str,
        platform: str | None = None,
        collected_types: list[str] | None = None,
        failed_types: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> None:
        super().__init__(message, platform)
        self.collected_types = collected_types or []
        self.failed_types = failed_types or []
        self.errors = errors or []


class ConfigurationError(CollectorError):
    """
    Raised when collector configuration is invalid or missing.
    """

    pass


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------


@dataclass
class Evidence:
    """
    Normalized evidence artifact collected from a platform.

    All evidence from all platforms is normalized to this common structure
    to enable consistent storage, querying, and mapping to NIST controls.

    Attributes:
        id: Unique identifier for this evidence item (UUID).
        platform: Source platform (e.g., "aws", "okta", "jamf").
        evidence_type: Type of evidence matching NIST CSF evidence_types
            (e.g., "mfa_status", "audit_logging", "user_inventory").
        collected_at: UTC timestamp when the evidence was collected.
        raw_data: The raw data from the platform API response.
        metadata: Additional context about the evidence source.
    """

    id: str
    platform: str
    evidence_type: str
    collected_at: datetime
    raw_data: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        platform: str,
        evidence_type: str,
        raw_data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Factory method to create a new Evidence instance with auto-generated ID and timestamp.

        Args:
            platform: Source platform identifier.
            evidence_type: Type of evidence matching NIST CSF types.
            raw_data: Raw data from platform API.
            metadata: Optional additional context.

        Returns:
            New Evidence instance with generated UUID and current UTC timestamp.
        """
        return cls(
            id=str(uuid.uuid4()),
            platform=platform,
            evidence_type=evidence_type,
            collected_at=datetime.now(UTC),
            raw_data=raw_data,
            metadata=metadata or {},
        )

    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of the evidence data for integrity verification.

        Returns:
            Hex-encoded SHA-256 hash of the raw_data.
        """
        import json

        data_str = json.dumps(self.raw_data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()


@dataclass
class CollectionResult:
    """
    Result of a collection run from a single platform.

    Represents the outcome of running a collector, including all gathered
    evidence, any errors encountered, and timing information.

    Attributes:
        platform: The platform that was collected from.
        timestamp: UTC timestamp when collection started.
        success: True if collection completed without fatal errors.
        evidence_items: List of all evidence collected.
        errors: List of error messages for any failures.
        duration_seconds: Total time taken for collection.
        partial: True if some evidence types succeeded while others failed.
    """

    platform: str
    timestamp: datetime
    success: bool
    evidence_items: list[Evidence]
    errors: list[str]
    duration_seconds: float
    partial: bool = False

    @property
    def evidence_count(self) -> int:
        """Return the number of evidence items collected."""
        return len(self.evidence_items)

    @property
    def evidence_types_collected(self) -> set[str]:
        """Return the set of evidence types that were collected."""
        return {e.evidence_type for e in self.evidence_items}

    def get_evidence_by_type(self, evidence_type: str) -> list[Evidence]:
        """
        Get all evidence items of a specific type.

        Args:
            evidence_type: The evidence type to filter by.

        Returns:
            List of Evidence items matching the type.
        """
        return [e for e in self.evidence_items if e.evidence_type == evidence_type]


# -----------------------------------------------------------------------------
# Base Collector
# -----------------------------------------------------------------------------


class BaseCollector(ABC):
    """
    Abstract base class for platform collectors.

    All platform-specific collectors inherit from this class and implement
    the abstract methods for collecting evidence from their respective APIs.

    Features:
        - Built-in rate limiting with configurable delays
        - Automatic retry logic with exponential backoff
        - Comprehensive logging of all API calls
        - Common evidence normalization

    Attributes:
        platform: String identifier for the platform (e.g., "aws", "okta").
        config: Settings object containing platform configuration.
        credential_store: Credential store for retrieving API credentials.
        logger: Logger instance for this collector.

    Rate Limiting:
        Subclasses should call _rate_limit() before each API call.
        The delay is configurable per platform in settings.

    Retry Logic:
        Use _with_retry() wrapper for API calls that should be retried
        on transient failures.

    Example:
        class MyCollector(BaseCollector):
            platform = "my_platform"

            def collect(self) -> CollectionResult:
                start = time.time()
                evidence = []
                errors = []

                try:
                    data = self._with_retry(self._fetch_data)
                    evidence.append(self.normalize_evidence(data, "data_type"))
                except CollectorError as e:
                    errors.append(str(e))

                return CollectionResult(
                    platform=self.platform,
                    timestamp=datetime.now(timezone.utc),
                    success=len(errors) == 0,
                    evidence_items=evidence,
                    errors=errors,
                    duration_seconds=time.time() - start,
                )
    """

    # Subclasses must set this to their platform identifier
    platform: str = "base"

    # Default rate limit delay in seconds between API calls
    default_rate_limit_delay: float = 0.1

    # Default retry configuration
    default_max_retries: int = 3
    default_retry_base_delay: float = 1.0
    default_retry_max_delay: float = 60.0

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the collector.

        Args:
            config: Settings object containing platform configuration.
            credential_store: Credential store for retrieving API credentials.
        """
        self.config = config
        self.credential_store = credential_store
        self.logger = logging.getLogger(f"nisify.collectors.{self.platform}")

        # Rate limiting state
        self._last_api_call: float = 0.0
        self._rate_limit_delay = self.default_rate_limit_delay

        # Retry configuration
        self._max_retries = self.default_max_retries
        self._retry_base_delay = self.default_retry_base_delay
        self._retry_max_delay = self.default_retry_max_delay

    @abstractmethod
    def collect(self) -> CollectionResult:
        """
        Collect evidence from the platform.

        This is the main entry point for evidence collection. Implementations
        should gather all relevant evidence types and return them in a
        CollectionResult.

        Returns:
            CollectionResult containing all gathered evidence and any errors.

        Raises:
            AuthenticationError: If authentication fails.
            CollectorConnectionError: If connection to the platform fails.
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connectivity to the platform.

        Verifies that the collector can authenticate and make basic API calls.
        Used for configuration validation and health checks.

        Returns:
            True if connection test succeeds, False otherwise.
        """
        pass

    @abstractmethod
    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns platform-specific permission strings that should be
        granted to the service account or API credentials.

        Returns:
            List of permission strings (format varies by platform).
        """
        pass

    def get_credential(self, key: str) -> str:
        """
        Retrieve a credential from the credential store.

        Args:
            key: The credential key (e.g., "api_key", "client_secret").

        Returns:
            The credential value.

        Raises:
            AuthenticationError: If the credential is not found or store is locked.
        """
        from nisify.config.credentials import (
            CredentialNotFoundError,
            CredentialStoreLockedError,
            CredentialStoreNotInitializedError,
        )

        try:
            return self.credential_store.get_credential(self.platform, key)
        except CredentialStoreNotInitializedError:
            raise AuthenticationError(
                "Credential store not initialized. Run 'nisify init' first.",
                platform=self.platform,
            )
        except CredentialStoreLockedError:
            raise AuthenticationError(
                "Credential store is locked. Run 'nisify configure unlock' first.",
                platform=self.platform,
            )
        except CredentialNotFoundError:
            raise AuthenticationError(
                f"Credential '{key}' not found for {self.platform}. "
                f"Run 'nisify configure set {self.platform}' to configure.",
                platform=self.platform,
            )

    def normalize_evidence(
        self,
        raw_data: dict[str, Any],
        evidence_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Normalize raw API data to an Evidence object.

        Args:
            raw_data: Raw data from the platform API.
            evidence_type: The NIST CSF evidence type this maps to.
            metadata: Optional additional context (API endpoint, filters, etc.).

        Returns:
            Normalized Evidence object.
        """
        return Evidence.create(
            platform=self.platform,
            evidence_type=evidence_type,
            raw_data=raw_data,
            metadata={
                "collector_version": "1.0.0",
                **(metadata or {}),
            },
        )

    def _rate_limit(self) -> None:
        """
        Apply rate limiting before an API call.

        Sleeps if necessary to maintain the configured delay between calls.
        """
        now = time.time()
        elapsed = now - self._last_api_call
        if elapsed < self._rate_limit_delay:
            sleep_time = self._rate_limit_delay - elapsed
            self.logger.debug(f"Rate limiting: sleeping {sleep_time:.3f}s")
            time.sleep(sleep_time)
        self._last_api_call = time.time()

    def _with_retry(
        self,
        func: Any,
        *args: Any,
        max_retries: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute a function with retry logic and exponential backoff.

        Retries on transient errors (connection errors, rate limits) but
        not on authentication errors or other permanent failures.

        Args:
            func: The function to execute.
            *args: Positional arguments to pass to the function.
            max_retries: Override the default max retries.
            **kwargs: Keyword arguments to pass to the function.

        Returns:
            The return value of the function.

        Raises:
            The last exception if all retries are exhausted.
        """
        retries = max_retries if max_retries is not None else self._max_retries
        last_exception: Exception | None = None

        for attempt in range(retries + 1):
            try:
                self._rate_limit()
                return func(*args, **kwargs)
            except AuthenticationError:
                # Don't retry auth errors
                raise
            except RateLimitError as e:
                last_exception = e
                if e.retry_after:
                    delay = e.retry_after
                else:
                    delay = min(
                        self._retry_base_delay * (2**attempt),
                        self._retry_max_delay,
                    )
                if attempt < retries:
                    self.logger.warning(
                        f"Rate limited, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(delay)
            except (CollectorConnectionError, OSError) as e:
                last_exception = e
                delay = min(
                    self._retry_base_delay * (2**attempt),
                    self._retry_max_delay,
                )
                if attempt < retries:
                    self.logger.warning(
                        f"Connection error, retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{retries}): {e}"
                    )
                    time.sleep(delay)

        # All retries exhausted
        if last_exception:
            raise last_exception
        raise CollectorError("Unknown error during retry", platform=self.platform)

    def _log_api_call(
        self,
        method: str,
        endpoint: str,
        status_code: int | None = None,
        duration_ms: float | None = None,
    ) -> None:
        """
        Log an API call for audit trail.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint URL or path.
            status_code: Response status code (if available).
            duration_ms: Request duration in milliseconds.
        """
        msg = f"API call: {method} {endpoint}"
        if status_code is not None:
            msg += f" -> {status_code}"
        if duration_ms is not None:
            msg += f" ({duration_ms:.0f}ms)"
        self.logger.info(msg)


# -----------------------------------------------------------------------------
# Collector Registry
# -----------------------------------------------------------------------------


class CollectorRegistry:
    """
    Registry for discovering and instantiating collectors.

    The registry maintains a mapping of platform names to collector classes,
    allowing dynamic discovery of available collectors and consistent
    instantiation.

    Example:
        # Register a collector
        CollectorRegistry.register(AwsCollector)

        # Get all registered platforms
        platforms = CollectorRegistry.get_platforms()

        # Create a collector instance
        collector = CollectorRegistry.create("aws", config, credential_store)
    """

    _collectors: dict[str, type[BaseCollector]] = {}

    @classmethod
    def register(cls, collector_class: type[BaseCollector]) -> type[BaseCollector]:
        """
        Register a collector class.

        Can be used as a decorator:
            @CollectorRegistry.register
            class MyCollector(BaseCollector):
                platform = "my_platform"

        Args:
            collector_class: The collector class to register.

        Returns:
            The collector class (for decorator usage).

        Raises:
            ValueError: If the collector has no platform defined.
        """
        platform = collector_class.platform
        if platform == "base":
            raise ValueError(
                f"Collector class {collector_class.__name__} must define 'platform'"
            )
        cls._collectors[platform] = collector_class
        logging.getLogger("nisify.collectors.registry").debug(
            f"Registered collector: {platform} -> {collector_class.__name__}"
        )
        return collector_class

    @classmethod
    def get_platforms(cls) -> list[str]:
        """
        Get all registered platform names.

        Returns:
            List of platform identifier strings.
        """
        return sorted(cls._collectors.keys())

    @classmethod
    def get_collector_class(cls, platform: str) -> type[BaseCollector] | None:
        """
        Get the collector class for a platform.

        Args:
            platform: Platform identifier.

        Returns:
            The collector class, or None if not registered.
        """
        return cls._collectors.get(platform)

    @classmethod
    def create(
        cls,
        platform: str,
        config: Settings,
        credential_store: CredentialStore,
    ) -> BaseCollector:
        """
        Create a collector instance for a platform.

        Args:
            platform: Platform identifier.
            config: Settings object.
            credential_store: Credential store.

        Returns:
            Instantiated collector.

        Raises:
            ValueError: If the platform is not registered.
        """
        collector_class = cls._collectors.get(platform)
        if collector_class is None:
            raise ValueError(
                f"Unknown platform: {platform}. "
                f"Available: {', '.join(cls.get_platforms())}"
            )
        return collector_class(config, credential_store)

    @classmethod
    def is_registered(cls, platform: str) -> bool:
        """
        Check if a platform is registered.

        Args:
            platform: Platform identifier.

        Returns:
            True if the platform has a registered collector.
        """
        return platform in cls._collectors

    @classmethod
    def clear(cls) -> None:
        """
        Clear all registered collectors.

        Primarily used for testing.
        """
        cls._collectors.clear()
