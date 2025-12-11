"""
Configuration management for Nisify.

This module handles loading, validating, and saving configuration settings,
as well as secure credential storage with encryption at rest.
"""

from nisify.config.credentials import (
    PLATFORM_CREDENTIAL_KEYS,
    CredentialError,
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreLockedError,
    CredentialStoreNotInitializedError,
    InvalidPassphraseError,
    get_credential_for_platform,
)
from nisify.config.settings import (
    ConfigurationError,
    Settings,
    load_config,
    save_config,
)

__all__ = [
    # Settings
    "Settings",
    "load_config",
    "save_config",
    "ConfigurationError",
    # Credentials
    "CredentialStore",
    "CredentialError",
    "CredentialStoreNotInitializedError",
    "CredentialStoreLockedError",
    "InvalidPassphraseError",
    "CredentialNotFoundError",
    "get_credential_for_platform",
    "PLATFORM_CREDENTIAL_KEYS",
]
