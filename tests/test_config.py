"""Tests for configuration modules (credentials and settings)."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from nisify.config.credentials import (
    PBKDF2_ITERATIONS,
    PLATFORM_CREDENTIAL_KEYS,
    SALT_LENGTH,
    SESSION_TIMEOUT_SECONDS,
    CredentialError,
    CredentialNotFoundError,
    CredentialSession,
    CredentialStore,
    CredentialStoreLockedError,
    CredentialStoreNotInitializedError,
    InvalidPassphraseError,
    get_credential_for_platform,
)
from nisify.config.settings import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILE,
    AwsConfig,
    CollectionConfig,
    ConfigurationError,
    DatadogConfig,
    GitLabConfig,
    GoogleConfig,
    JamfConfig,
    JiraConfig,
    NotionConfig,
    OktaConfig,
    PlatformConfig,
    ReportingConfig,
    Settings,
    SlabConfig,
    SnowflakeConfig,
    SpotDraftConfig,
    ZendeskConfig,
    ZoomConfig,
    _apply_environment_overrides,
    _set_nested_attr,
    _settings_to_dict,
    _validate_config,
    get_config_path,
    load_config,
    save_config,
)


class TestCredentialSession(unittest.TestCase):
    """Tests for CredentialSession class."""

    def test_session_creation(self) -> None:
        """Test creating a new session with a Fernet key."""
        # Create a real Fernet key
        key = Fernet.generate_key()
        fernet = Fernet(key)

        session = CredentialSession(fernet=fernet)

        self.assertIsInstance(session.fernet, Fernet)
        self.assertIsInstance(session.created_at, float)
        self.assertEqual(session.timeout_seconds, SESSION_TIMEOUT_SECONDS)

    def test_session_not_expired(self) -> None:
        """Test that a fresh session is not expired."""
        key = Fernet.generate_key()
        fernet = Fernet(key)

        session = CredentialSession(fernet=fernet)

        self.assertFalse(session.is_expired())

    def test_session_expired(self) -> None:
        """Test that a session expires after timeout."""
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Create session with very short timeout and backdate creation
        session = CredentialSession(fernet=fernet, timeout_seconds=1)
        session.created_at = time.time() - 2  # Set created_at to 2 seconds ago

        # Should be expired
        self.assertTrue(session.is_expired())

    def test_session_custom_timeout(self) -> None:
        """Test session with custom timeout."""
        key = Fernet.generate_key()
        fernet = Fernet(key)

        session = CredentialSession(fernet=fernet, timeout_seconds=7200)

        self.assertEqual(session.timeout_seconds, 7200)
        self.assertFalse(session.is_expired())

    def test_session_clear(self) -> None:
        """Test clearing session data."""
        key = Fernet.generate_key()
        fernet = Fernet(key)

        session = CredentialSession(fernet=fernet)
        session.clear()

        self.assertIsNone(session.fernet)


class TestCredentialStore(unittest.TestCase):
    """Tests for CredentialStore class."""

    def setUp(self) -> None:
        """Create temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)
        self.passphrase = "test-secure-passphrase-123"

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_store_initialization_paths(self) -> None:
        """Test that store sets up correct paths."""
        store = CredentialStore(self.config_dir)

        self.assertEqual(store.config_dir, self.config_dir)
        self.assertEqual(store.salt_path, self.config_dir / "salt")
        self.assertEqual(store.credentials_path, self.config_dir / "credentials.enc")

    def test_is_initialized_false_when_empty(self) -> None:
        """Test is_initialized returns False for empty directory."""
        store = CredentialStore(self.config_dir)

        self.assertFalse(store.is_initialized())

    def test_initialize_creates_files(self) -> None:
        """Test that initialize creates salt and credentials files."""
        store = CredentialStore(self.config_dir)

        store.initialize(self.passphrase)

        self.assertTrue(store.salt_path.exists())
        self.assertTrue(store.credentials_path.exists())
        self.assertTrue(store.is_initialized())

    def test_initialize_salt_is_correct_length(self) -> None:
        """Test that generated salt is correct length."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        salt = store.salt_path.read_bytes()
        self.assertEqual(len(salt), SALT_LENGTH)

    def test_initialize_starts_session(self) -> None:
        """Test that initialize starts an active session."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        self.assertTrue(store.is_unlocked())

    def test_initialize_fails_if_already_initialized(self) -> None:
        """Test that initializing twice raises error."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialError) as ctx:
            store.initialize(self.passphrase)

        self.assertIn("already initialized", str(ctx.exception))

    def test_initialize_rejects_short_passphrase(self) -> None:
        """Test that passphrase must be at least 12 characters."""
        store = CredentialStore(self.config_dir)

        with self.assertRaises(ValueError) as ctx:
            store.initialize("short")

        self.assertIn("at least 12 characters", str(ctx.exception))

    def test_initialize_accepts_minimum_passphrase(self) -> None:
        """Test that 12-character passphrase is accepted."""
        store = CredentialStore(self.config_dir)

        store.initialize("123456789012")  # Exactly 12 chars

        self.assertTrue(store.is_initialized())

    def test_unlock_not_initialized(self) -> None:
        """Test unlock fails when not initialized."""
        store = CredentialStore(self.config_dir)

        with self.assertRaises(CredentialStoreNotInitializedError):
            store.unlock(self.passphrase)

    def test_unlock_with_correct_passphrase(self) -> None:
        """Test unlocking with correct passphrase."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.lock()

        self.assertFalse(store.is_unlocked())

        store.unlock(self.passphrase)

        self.assertTrue(store.is_unlocked())

    def test_unlock_with_wrong_passphrase(self) -> None:
        """Test unlocking with wrong passphrase raises error."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.lock()

        with self.assertRaises(InvalidPassphraseError):
            store.unlock("wrong-passphrase")

    def test_unlock_custom_timeout(self) -> None:
        """Test unlock with custom timeout."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.lock()

        store.unlock(self.passphrase, timeout_seconds=7200)

        self.assertTrue(store.is_unlocked())
        self.assertEqual(store._session.timeout_seconds, 7200)

    def test_lock_clears_session(self) -> None:
        """Test that lock clears the session."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        self.assertTrue(store.is_unlocked())

        store.lock()

        self.assertFalse(store.is_unlocked())
        self.assertIsNone(store._session)

    def test_is_unlocked_false_when_no_session(self) -> None:
        """Test is_unlocked returns False with no session."""
        store = CredentialStore(self.config_dir)

        self.assertFalse(store.is_unlocked())

    def test_is_unlocked_false_when_expired(self) -> None:
        """Test is_unlocked returns False when session expired."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        # Force session to expire
        store._session.timeout_seconds = 0
        store._session.created_at = time.time() - 1

        self.assertFalse(store.is_unlocked())
        # Session should be cleared
        self.assertIsNone(store._session)

    def test_set_and_get_credential(self) -> None:
        """Test setting and getting a credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("okta", "api_token", "my-secret-token")

        result = store.get_credential("okta", "api_token")
        self.assertEqual(result, "my-secret-token")

    def test_set_multiple_credentials_same_platform(self) -> None:
        """Test storing multiple credentials for same platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("aws", "access_key_id", "AKIA123")
        store.set_credential("aws", "secret_access_key", "secret123")

        self.assertEqual(store.get_credential("aws", "access_key_id"), "AKIA123")
        self.assertEqual(store.get_credential("aws", "secret_access_key"), "secret123")

    def test_set_credentials_multiple_platforms(self) -> None:
        """Test storing credentials for multiple platforms."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("okta", "api_token", "okta-token")
        store.set_credential("jamf", "client_id", "jamf-client")

        self.assertEqual(store.get_credential("okta", "api_token"), "okta-token")
        self.assertEqual(store.get_credential("jamf", "client_id"), "jamf-client")

    def test_update_credential(self) -> None:
        """Test updating an existing credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("okta", "api_token", "old-token")
        store.set_credential("okta", "api_token", "new-token")

        self.assertEqual(store.get_credential("okta", "api_token"), "new-token")

    def test_get_credential_locked(self) -> None:
        """Test get_credential raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.get_credential("okta", "api_token")

    def test_get_credential_platform_not_found(self) -> None:
        """Test get_credential raises error for unknown platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialNotFoundError) as ctx:
            store.get_credential("nonexistent", "api_token")

        self.assertIn("nonexistent", str(ctx.exception))

    def test_get_credential_key_not_found(self) -> None:
        """Test get_credential raises error for unknown key."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")

        with self.assertRaises(CredentialNotFoundError) as ctx:
            store.get_credential("okta", "nonexistent_key")

        self.assertIn("nonexistent_key", str(ctx.exception))

    def test_set_credential_locked(self) -> None:
        """Test set_credential raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.set_credential("okta", "api_token", "token")

    def test_delete_credential(self) -> None:
        """Test deleting a credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.set_credential("okta", "client_id", "client")

        store.delete_credential("okta", "api_token")

        with self.assertRaises(CredentialNotFoundError):
            store.get_credential("okta", "api_token")

        # Other credential should still exist
        self.assertEqual(store.get_credential("okta", "client_id"), "client")

    def test_delete_credential_removes_empty_platform(self) -> None:
        """Test deleting last credential removes platform entry."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")

        store.delete_credential("okta", "api_token")

        self.assertEqual(store.list_platforms(), [])

    def test_delete_credential_not_found(self) -> None:
        """Test delete_credential raises error for unknown credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialNotFoundError):
            store.delete_credential("okta", "api_token")

    def test_delete_credential_locked(self) -> None:
        """Test delete_credential raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.delete_credential("okta", "api_token")

    def test_delete_platform_credentials(self) -> None:
        """Test deleting all credentials for a platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.set_credential("okta", "client_id", "client")
        store.set_credential("jamf", "client_id", "jamf-client")

        store.delete_platform_credentials("okta")

        self.assertEqual(store.list_platforms(), ["jamf"])

    def test_delete_platform_credentials_not_found(self) -> None:
        """Test delete_platform_credentials raises error for unknown platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialNotFoundError):
            store.delete_platform_credentials("nonexistent")

    def test_delete_platform_credentials_locked(self) -> None:
        """Test delete_platform_credentials raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.delete_platform_credentials("okta")

    def test_list_platforms(self) -> None:
        """Test listing all platforms with credentials."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.set_credential("jamf", "client_id", "client")
        store.set_credential("aws", "access_key_id", "key")

        platforms = store.list_platforms()

        self.assertEqual(set(platforms), {"okta", "jamf", "aws"})

    def test_list_platforms_empty(self) -> None:
        """Test listing platforms when none exist."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        platforms = store.list_platforms()

        self.assertEqual(platforms, [])

    def test_list_platforms_locked(self) -> None:
        """Test list_platforms raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.list_platforms()

    def test_list_credentials(self) -> None:
        """Test listing credential keys for a platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.set_credential("okta", "client_id", "client")

        keys = store.list_credentials("okta")

        self.assertEqual(set(keys), {"api_token", "client_id"})

    def test_list_credentials_not_found(self) -> None:
        """Test list_credentials raises error for unknown platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialNotFoundError):
            store.list_credentials("nonexistent")

    def test_list_credentials_locked(self) -> None:
        """Test list_credentials raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.list_credentials("okta")

    def test_has_credential_true(self) -> None:
        """Test has_credential returns True for existing credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")

        self.assertTrue(store.has_credential("okta", "api_token"))

    def test_has_credential_false_wrong_platform(self) -> None:
        """Test has_credential returns False for wrong platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")

        self.assertFalse(store.has_credential("jamf", "api_token"))

    def test_has_credential_false_wrong_key(self) -> None:
        """Test has_credential returns False for wrong key."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")

        self.assertFalse(store.has_credential("okta", "client_id"))

    def test_has_credential_locked(self) -> None:
        """Test has_credential raises error when locked."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        with self.assertRaises(CredentialStoreLockedError):
            store.has_credential("okta", "api_token")

    def test_change_passphrase(self) -> None:
        """Test changing the passphrase."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "my-secret-token")

        new_passphrase = "new-secure-passphrase-456"
        store.change_passphrase(self.passphrase, new_passphrase)

        # Should be unlocked with new session
        self.assertTrue(store.is_unlocked())

        # Lock and verify new passphrase works
        store.lock()
        store.unlock(new_passphrase)
        self.assertEqual(store.get_credential("okta", "api_token"), "my-secret-token")

        # Old passphrase should not work
        store.lock()
        with self.assertRaises(InvalidPassphraseError):
            store.unlock(self.passphrase)

    def test_change_passphrase_wrong_old(self) -> None:
        """Test change_passphrase fails with wrong old passphrase."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(InvalidPassphraseError):
            store.change_passphrase("wrong-passphrase", "new-passphrase")

    def test_change_passphrase_short_new(self) -> None:
        """Test change_passphrase rejects short new passphrase."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(ValueError):
            store.change_passphrase(self.passphrase, "short")

    def test_credentials_persist_across_sessions(self) -> None:
        """Test that credentials persist after closing and reopening store."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "persistent-token")
        store.lock()

        # Create new store instance pointing to same directory
        store2 = CredentialStore(self.config_dir)
        store2.unlock(self.passphrase)

        self.assertEqual(store2.get_credential("okta", "api_token"), "persistent-token")

    def test_credentials_encrypted_on_disk(self) -> None:
        """Test that credentials are encrypted in the file."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "secret-value")

        # Read raw file contents
        raw_data = store.credentials_path.read_bytes()

        # The raw data should not contain the plaintext credential
        self.assertNotIn(b"secret-value", raw_data)
        self.assertNotIn(b"api_token", raw_data)
        self.assertNotIn(b"okta", raw_data)


class TestCredentialStoreEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def setUp(self) -> None:
        """Create temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)
        self.passphrase = "test-secure-passphrase-123"

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_special_characters_in_passphrase(self) -> None:
        """Test passphrase with special characters."""
        store = CredentialStore(self.config_dir)
        special_passphrase = "p@$$w0rd!#$%^&*()"

        store.initialize(special_passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        store.unlock(special_passphrase)
        self.assertEqual(store.get_credential("okta", "api_token"), "token")

    def test_unicode_in_passphrase(self) -> None:
        """Test passphrase with unicode characters."""
        store = CredentialStore(self.config_dir)
        unicode_passphrase = "pässwörd-日本語-🔐"

        store.initialize(unicode_passphrase)
        store.set_credential("okta", "api_token", "token")
        store.lock()

        store.unlock(unicode_passphrase)
        self.assertEqual(store.get_credential("okta", "api_token"), "token")

    def test_unicode_in_credential_value(self) -> None:
        """Test credential value with unicode characters."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("test", "key", "value-日本語-émoji-🔑")

        result = store.get_credential("test", "key")
        self.assertEqual(result, "value-日本語-émoji-🔑")

    def test_empty_credential_value(self) -> None:
        """Test storing empty string as credential value."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        store.set_credential("test", "empty_key", "")

        result = store.get_credential("test", "empty_key")
        self.assertEqual(result, "")

    def test_long_credential_value(self) -> None:
        """Test storing very long credential value."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        long_value = "x" * 10000
        store.set_credential("test", "long_key", long_value)

        result = store.get_credential("test", "long_key")
        self.assertEqual(result, long_value)

    def test_require_unlocked_raises_when_locked(self) -> None:
        """Test _require_unlocked raises appropriate error."""
        store = CredentialStore(self.config_dir)

        with self.assertRaises(CredentialStoreLockedError) as ctx:
            store._require_unlocked()

        self.assertIn("locked", str(ctx.exception).lower())


class TestGetCredentialForPlatform(unittest.TestCase):
    """Tests for the get_credential_for_platform helper function."""

    def setUp(self) -> None:
        """Create temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)
        self.passphrase = "test-secure-passphrase-123"

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_all_credentials_for_platform(self) -> None:
        """Test getting all credentials for a platform."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("aws", "access_key_id", "AKIA123")
        store.set_credential("aws", "secret_access_key", "secret")

        result = get_credential_for_platform("aws", store)

        self.assertEqual(result, {
            "access_key_id": "AKIA123",
            "secret_access_key": "secret",
        })

    def test_get_credential_for_platform_empty(self) -> None:
        """Test getting credentials for platform with single credential."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)
        store.set_credential("okta", "api_token", "token123")

        result = get_credential_for_platform("okta", store)

        self.assertEqual(result, {"api_token": "token123"})

    def test_get_credential_for_platform_not_found(self) -> None:
        """Test error when platform has no credentials."""
        store = CredentialStore(self.config_dir)
        store.initialize(self.passphrase)

        with self.assertRaises(CredentialNotFoundError):
            get_credential_for_platform("nonexistent", store)


class TestPlatformCredentialKeys(unittest.TestCase):
    """Tests for platform credential key constants."""

    def test_platform_credential_keys_has_expected_platforms(self) -> None:
        """Test that expected platforms are defined."""
        expected_platforms = {
            "aws", "okta", "jamf", "google", "snowflake",
            "datadog", "gitlab", "jira", "zendesk", "zoom",
            "notion", "slab", "spotdraft"
        }

        self.assertEqual(set(PLATFORM_CREDENTIAL_KEYS.keys()), expected_platforms)

    def test_okta_credentials_has_api_token(self) -> None:
        """Test Okta credential keys."""
        from nisify.config.credentials import OKTA_CREDENTIALS

        self.assertIn("api_token", OKTA_CREDENTIALS)

    def test_jamf_credentials_has_client_credentials(self) -> None:
        """Test Jamf credential keys."""
        from nisify.config.credentials import JAMF_CREDENTIALS

        self.assertIn("client_id", JAMF_CREDENTIALS)
        self.assertIn("client_secret", JAMF_CREDENTIALS)

    def test_datadog_credentials_has_keys(self) -> None:
        """Test Datadog credential keys."""
        from nisify.config.credentials import DATADOG_CREDENTIALS

        self.assertIn("api_key", DATADOG_CREDENTIALS)
        self.assertIn("app_key", DATADOG_CREDENTIALS)

    def test_snowflake_credentials_has_auth_options(self) -> None:
        """Test Snowflake credential keys include both auth methods."""
        from nisify.config.credentials import SNOWFLAKE_CREDENTIALS

        self.assertIn("username", SNOWFLAKE_CREDENTIALS)
        self.assertIn("password", SNOWFLAKE_CREDENTIALS)
        self.assertIn("private_key_path", SNOWFLAKE_CREDENTIALS)


class TestSecurityConstants(unittest.TestCase):
    """Tests for security-related constants."""

    def test_pbkdf2_iterations_meets_minimum(self) -> None:
        """Test PBKDF2 iterations meets OWASP recommendation."""
        # OWASP minimum is 100,000 for PBKDF2-SHA256
        self.assertGreaterEqual(PBKDF2_ITERATIONS, 100_000)

    def test_salt_length_is_sufficient(self) -> None:
        """Test salt length is cryptographically sufficient."""
        # 256 bits (32 bytes) is the recommended minimum
        self.assertGreaterEqual(SALT_LENGTH, 32)

    def test_session_timeout_is_reasonable(self) -> None:
        """Test session timeout is within reasonable range."""
        # Should be between 5 minutes and 24 hours
        self.assertGreaterEqual(SESSION_TIMEOUT_SECONDS, 300)
        self.assertLessEqual(SESSION_TIMEOUT_SECONDS, 86400)


class TestCredentialExceptions(unittest.TestCase):
    """Tests for credential exception classes."""

    def test_credential_error_is_base(self) -> None:
        """Test CredentialError is the base exception."""
        self.assertTrue(issubclass(CredentialStoreNotInitializedError, CredentialError))
        self.assertTrue(issubclass(CredentialStoreLockedError, CredentialError))
        self.assertTrue(issubclass(InvalidPassphraseError, CredentialError))
        self.assertTrue(issubclass(CredentialNotFoundError, CredentialError))

    def test_exceptions_can_be_raised(self) -> None:
        """Test that all exception types can be raised and caught."""
        exceptions = [
            CredentialError("base error"),
            CredentialStoreNotInitializedError("not initialized"),
            CredentialStoreLockedError("locked"),
            InvalidPassphraseError("invalid"),
            CredentialNotFoundError("not found"),
        ]

        for exc in exceptions:
            with self.assertRaises(CredentialError):
                raise exc


# =============================================================================
# Settings Tests
# =============================================================================


class TestPlatformConfigs(unittest.TestCase):
    """Tests for platform configuration dataclasses."""

    def test_platform_config_defaults(self) -> None:
        """Test PlatformConfig default values."""
        config = PlatformConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.settings, {})

    def test_aws_config_defaults(self) -> None:
        """Test AwsConfig default values."""
        config = AwsConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.profile, "default")
        self.assertEqual(config.regions, ["us-east-1"])

    def test_okta_config_defaults(self) -> None:
        """Test OktaConfig default values."""
        config = OktaConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.domain, "")

    def test_jamf_config_defaults(self) -> None:
        """Test JamfConfig default values."""
        config = JamfConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.url, "")

    def test_google_config_defaults(self) -> None:
        """Test GoogleConfig default values."""
        config = GoogleConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.customer_id, "")
        self.assertEqual(config.service_account_path, "")

    def test_snowflake_config_defaults(self) -> None:
        """Test SnowflakeConfig default values."""
        config = SnowflakeConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.account, "")
        self.assertEqual(config.warehouse, "")

    def test_datadog_config_defaults(self) -> None:
        """Test DatadogConfig default values."""
        config = DatadogConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.site, "datadoghq.com")

    def test_gitlab_config_defaults(self) -> None:
        """Test GitLabConfig default values."""
        config = GitLabConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.url, "https://gitlab.com")

    def test_jira_config_defaults(self) -> None:
        """Test JiraConfig default values."""
        config = JiraConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.url, "")

    def test_zendesk_config_defaults(self) -> None:
        """Test ZendeskConfig default values."""
        config = ZendeskConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.subdomain, "")

    def test_zoom_config_defaults(self) -> None:
        """Test ZoomConfig default values."""
        config = ZoomConfig()
        self.assertFalse(config.enabled)

    def test_notion_config_defaults(self) -> None:
        """Test NotionConfig default values."""
        config = NotionConfig()
        self.assertFalse(config.enabled)

    def test_slab_config_defaults(self) -> None:
        """Test SlabConfig default values."""
        config = SlabConfig()
        self.assertFalse(config.enabled)

    def test_spotdraft_config_defaults(self) -> None:
        """Test SpotDraftConfig default values."""
        config = SpotDraftConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.subdomain, "")


class TestCollectionAndReportingConfigs(unittest.TestCase):
    """Tests for CollectionConfig and ReportingConfig."""

    def test_collection_config_defaults(self) -> None:
        """Test CollectionConfig default values."""
        config = CollectionConfig()
        self.assertEqual(config.schedule, "daily")
        self.assertEqual(config.retention_days, 365)

    def test_reporting_config_defaults(self) -> None:
        """Test ReportingConfig default values."""
        config = ReportingConfig()
        self.assertEqual(config.company_name, "")
        self.assertEqual(config.output_dir, str(DEFAULT_CONFIG_DIR / "reports"))


class TestSettings(unittest.TestCase):
    """Tests for the main Settings dataclass."""

    def test_settings_defaults(self) -> None:
        """Test Settings default values."""
        settings = Settings()

        self.assertEqual(settings.data_dir, str(DEFAULT_CONFIG_DIR / "data"))
        self.assertEqual(settings.log_level, "INFO")
        self.assertIsInstance(settings.aws, AwsConfig)
        self.assertIsInstance(settings.okta, OktaConfig)
        self.assertIsInstance(settings.jamf, JamfConfig)
        self.assertIsInstance(settings.google, GoogleConfig)
        self.assertIsInstance(settings.snowflake, SnowflakeConfig)
        self.assertIsInstance(settings.datadog, DatadogConfig)
        self.assertIsInstance(settings.gitlab, GitLabConfig)
        self.assertIsInstance(settings.jira, JiraConfig)
        self.assertIsInstance(settings.zendesk, ZendeskConfig)
        self.assertIsInstance(settings.zoom, ZoomConfig)
        self.assertIsInstance(settings.notion, NotionConfig)
        self.assertIsInstance(settings.slab, SlabConfig)
        self.assertIsInstance(settings.spotdraft, SpotDraftConfig)
        self.assertIsInstance(settings.collection, CollectionConfig)
        self.assertIsInstance(settings.reporting, ReportingConfig)

    def test_settings_all_platforms_disabled_by_default(self) -> None:
        """Test all platforms are disabled by default."""
        settings = Settings()

        self.assertFalse(settings.aws.enabled)
        self.assertFalse(settings.okta.enabled)
        self.assertFalse(settings.jamf.enabled)
        self.assertFalse(settings.google.enabled)
        self.assertFalse(settings.snowflake.enabled)
        self.assertFalse(settings.datadog.enabled)
        self.assertFalse(settings.gitlab.enabled)
        self.assertFalse(settings.jira.enabled)
        self.assertFalse(settings.zendesk.enabled)
        self.assertFalse(settings.zoom.enabled)
        self.assertFalse(settings.notion.enabled)
        self.assertFalse(settings.slab.enabled)
        self.assertFalse(settings.spotdraft.enabled)


class TestGetConfigPath(unittest.TestCase):
    """Tests for get_config_path function."""

    def test_default_config_path(self) -> None:
        """Test default config path when no environment variable."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove NISIFY_CONFIG if present
            os.environ.pop("NISIFY_CONFIG", None)
            path = get_config_path()
            self.assertEqual(path, DEFAULT_CONFIG_FILE)

    def test_config_path_from_environment(self) -> None:
        """Test config path from environment variable."""
        with patch.dict(os.environ, {"NISIFY_CONFIG": "/custom/path/config.yaml"}):
            path = get_config_path()
            self.assertEqual(path, Path("/custom/path/config.yaml"))


class TestLoadConfig(unittest.TestCase):
    """Tests for load_config function."""

    def setUp(self) -> None:
        """Create temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.yaml"

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_config_nonexistent_file_returns_defaults(self) -> None:
        """Test loading config when file doesn't exist returns defaults."""
        nonexistent = Path(self.temp_dir) / "nonexistent.yaml"
        settings = load_config(nonexistent)

        self.assertEqual(settings.log_level, "INFO")
        self.assertFalse(settings.aws.enabled)

    def test_load_config_from_yaml(self) -> None:
        """Test loading config from YAML file."""
        config_yaml = """
nisify:
  data_dir: /custom/data
  log_level: DEBUG

platforms:
  aws:
    enabled: true
    profile: production
    regions:
      - us-west-2
      - eu-west-1
  okta:
    enabled: true
    domain: mycompany.okta.com

collection:
  schedule: hourly
  retention_days: 180

reporting:
  company_name: Test Company
  output_dir: /custom/reports
"""
        self.config_path.write_text(config_yaml)
        settings = load_config(self.config_path)

        self.assertEqual(settings.data_dir, "/custom/data")
        self.assertEqual(settings.log_level, "DEBUG")
        self.assertTrue(settings.aws.enabled)
        self.assertEqual(settings.aws.profile, "production")
        self.assertEqual(settings.aws.regions, ["us-west-2", "eu-west-1"])
        self.assertTrue(settings.okta.enabled)
        self.assertEqual(settings.okta.domain, "mycompany.okta.com")
        self.assertEqual(settings.collection.schedule, "hourly")
        self.assertEqual(settings.collection.retention_days, 180)
        self.assertEqual(settings.reporting.company_name, "Test Company")
        self.assertEqual(settings.reporting.output_dir, "/custom/reports")

    def test_load_config_all_platforms(self) -> None:
        """Test loading config with all platforms enabled."""
        config_yaml = """
platforms:
  jamf:
    enabled: true
    url: https://mycompany.jamfcloud.com
  google:
    enabled: true
    customer_id: C12345
    service_account_path: /path/to/sa.json
  snowflake:
    enabled: true
    account: myaccount
    warehouse: COMPUTE_WH
  datadog:
    enabled: true
    site: datadoghq.eu
  gitlab:
    enabled: true
    url: https://gitlab.mycompany.com
  jira:
    enabled: true
    url: https://mycompany.atlassian.net
  zendesk:
    enabled: true
    subdomain: mycompany
  zoom:
    enabled: true
  notion:
    enabled: true
  slab:
    enabled: true
  spotdraft:
    enabled: true
    subdomain: mycompany
"""
        self.config_path.write_text(config_yaml)
        settings = load_config(self.config_path)

        self.assertTrue(settings.jamf.enabled)
        self.assertEqual(settings.jamf.url, "https://mycompany.jamfcloud.com")
        self.assertTrue(settings.google.enabled)
        self.assertEqual(settings.google.customer_id, "C12345")
        self.assertTrue(settings.snowflake.enabled)
        self.assertEqual(settings.snowflake.account, "myaccount")
        self.assertTrue(settings.datadog.enabled)
        self.assertEqual(settings.datadog.site, "datadoghq.eu")
        self.assertTrue(settings.gitlab.enabled)
        self.assertEqual(settings.gitlab.url, "https://gitlab.mycompany.com")
        self.assertTrue(settings.jira.enabled)
        self.assertEqual(settings.jira.url, "https://mycompany.atlassian.net")
        self.assertTrue(settings.zendesk.enabled)
        self.assertEqual(settings.zendesk.subdomain, "mycompany")
        self.assertTrue(settings.zoom.enabled)
        self.assertTrue(settings.notion.enabled)
        self.assertTrue(settings.slab.enabled)
        self.assertTrue(settings.spotdraft.enabled)
        self.assertEqual(settings.spotdraft.subdomain, "mycompany")

    def test_load_config_invalid_yaml(self) -> None:
        """Test loading invalid YAML raises ConfigurationError."""
        self.config_path.write_text("invalid: yaml: content: [")

        with self.assertRaises(ConfigurationError) as ctx:
            load_config(self.config_path)

        self.assertIn("Invalid YAML", str(ctx.exception))

    def test_load_config_empty_file(self) -> None:
        """Test loading empty config file returns defaults."""
        self.config_path.write_text("")
        settings = load_config(self.config_path)

        self.assertEqual(settings.log_level, "INFO")

    def test_load_config_invalid_log_level(self) -> None:
        """Test loading config with invalid log level raises error."""
        config_yaml = """
nisify:
  log_level: INVALID
"""
        self.config_path.write_text(config_yaml)

        with self.assertRaises(ConfigurationError) as ctx:
            load_config(self.config_path)

        self.assertIn("Invalid log_level", str(ctx.exception))

    def test_load_config_invalid_retention_days(self) -> None:
        """Test loading config with invalid retention_days raises error."""
        config_yaml = """
collection:
  retention_days: 0
"""
        self.config_path.write_text(config_yaml)

        with self.assertRaises(ConfigurationError) as ctx:
            load_config(self.config_path)

        self.assertIn("retention_days", str(ctx.exception))

    def test_load_config_invalid_schedule(self) -> None:
        """Test loading config with invalid schedule raises error."""
        config_yaml = """
collection:
  schedule: yearly
"""
        self.config_path.write_text(config_yaml)

        with self.assertRaises(ConfigurationError) as ctx:
            load_config(self.config_path)

        self.assertIn("Invalid schedule", str(ctx.exception))


class TestSaveConfig(unittest.TestCase):
    """Tests for save_config function."""

    def setUp(self) -> None:
        """Create temporary directory for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.yaml"

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_config_creates_file(self) -> None:
        """Test save_config creates config file."""
        settings = Settings()
        save_config(settings, self.config_path)

        self.assertTrue(self.config_path.exists())

    def test_save_config_creates_parent_directory(self) -> None:
        """Test save_config creates parent directory if needed."""
        nested_path = Path(self.temp_dir) / "nested" / "dir" / "config.yaml"
        settings = Settings()

        save_config(settings, nested_path)

        self.assertTrue(nested_path.exists())

    def test_save_and_load_roundtrip(self) -> None:
        """Test that saved config can be loaded back."""
        settings = Settings()
        settings.data_dir = "/custom/data"
        settings.log_level = "DEBUG"
        settings.aws.enabled = True
        settings.aws.profile = "production"
        settings.aws.regions = ["us-west-2", "eu-central-1"]
        settings.okta.enabled = True
        settings.okta.domain = "test.okta.com"
        settings.collection.schedule = "weekly"
        settings.collection.retention_days = 90
        settings.reporting.company_name = "Test Corp"

        save_config(settings, self.config_path)
        loaded = load_config(self.config_path)

        self.assertEqual(loaded.data_dir, "/custom/data")
        self.assertEqual(loaded.log_level, "DEBUG")
        self.assertTrue(loaded.aws.enabled)
        self.assertEqual(loaded.aws.profile, "production")
        self.assertEqual(loaded.aws.regions, ["us-west-2", "eu-central-1"])
        self.assertTrue(loaded.okta.enabled)
        self.assertEqual(loaded.okta.domain, "test.okta.com")
        self.assertEqual(loaded.collection.schedule, "weekly")
        self.assertEqual(loaded.collection.retention_days, 90)
        self.assertEqual(loaded.reporting.company_name, "Test Corp")


class TestApplyEnvironmentOverrides(unittest.TestCase):
    """Tests for _apply_environment_overrides function."""

    def test_override_data_dir(self) -> None:
        """Test NISIFY_DATA_DIR override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_DATA_DIR": "/env/data"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.data_dir, "/env/data")

    def test_override_log_level(self) -> None:
        """Test NISIFY_LOG_LEVEL override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_LOG_LEVEL": "WARNING"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.log_level, "WARNING")

    def test_override_aws_profile(self) -> None:
        """Test NISIFY_AWS_PROFILE override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_AWS_PROFILE": "staging"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.aws.profile, "staging")

    def test_override_aws_regions(self) -> None:
        """Test NISIFY_AWS_REGIONS override (comma-separated)."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_AWS_REGIONS": "us-west-2,eu-west-1,ap-south-1"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.aws.regions, ["us-west-2", "eu-west-1", "ap-south-1"])

    def test_override_okta_domain(self) -> None:
        """Test NISIFY_OKTA_DOMAIN override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_OKTA_DOMAIN": "env.okta.com"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.okta.domain, "env.okta.com")

    def test_override_jamf_url(self) -> None:
        """Test NISIFY_JAMF_URL override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_JAMF_URL": "https://env.jamfcloud.com"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.jamf.url, "https://env.jamfcloud.com")

    def test_override_google_customer_id(self) -> None:
        """Test NISIFY_GOOGLE_CUSTOMER_ID override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_GOOGLE_CUSTOMER_ID": "C98765"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.google.customer_id, "C98765")

    def test_override_snowflake_account(self) -> None:
        """Test NISIFY_SNOWFLAKE_ACCOUNT override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_SNOWFLAKE_ACCOUNT": "env_account"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.snowflake.account, "env_account")

    def test_override_datadog_site(self) -> None:
        """Test NISIFY_DATADOG_SITE override."""
        settings = Settings()
        with patch.dict(os.environ, {"NISIFY_DATADOG_SITE": "datadoghq.eu"}):
            settings = _apply_environment_overrides(settings)
        self.assertEqual(settings.datadog.site, "datadoghq.eu")

    def test_multiple_overrides(self) -> None:
        """Test multiple environment overrides at once."""
        settings = Settings()
        env_vars = {
            "NISIFY_DATA_DIR": "/env/data",
            "NISIFY_LOG_LEVEL": "ERROR",
            "NISIFY_AWS_PROFILE": "env-profile",
        }
        with patch.dict(os.environ, env_vars):
            settings = _apply_environment_overrides(settings)

        self.assertEqual(settings.data_dir, "/env/data")
        self.assertEqual(settings.log_level, "ERROR")
        self.assertEqual(settings.aws.profile, "env-profile")


class TestSetNestedAttr(unittest.TestCase):
    """Tests for _set_nested_attr function."""

    def test_set_simple_attr(self) -> None:
        """Test setting a simple attribute."""
        settings = Settings()
        _set_nested_attr(settings, "data_dir", "/new/path")
        self.assertEqual(settings.data_dir, "/new/path")

    def test_set_nested_attr(self) -> None:
        """Test setting a nested attribute."""
        settings = Settings()
        _set_nested_attr(settings, "aws.profile", "new-profile")
        self.assertEqual(settings.aws.profile, "new-profile")

    def test_set_deeply_nested_attr(self) -> None:
        """Test setting collection settings."""
        settings = Settings()
        _set_nested_attr(settings, "collection.schedule", "weekly")
        self.assertEqual(settings.collection.schedule, "weekly")


class TestValidateConfig(unittest.TestCase):
    """Tests for _validate_config function."""

    def test_valid_config(self) -> None:
        """Test validation passes for valid config."""
        settings = Settings()
        # Should not raise
        _validate_config(settings)

    def test_invalid_log_level(self) -> None:
        """Test validation fails for invalid log level."""
        settings = Settings()
        settings.log_level = "INVALID"

        with self.assertRaises(ConfigurationError) as ctx:
            _validate_config(settings)

        self.assertIn("Invalid log_level", str(ctx.exception))
        self.assertIn("INVALID", str(ctx.exception))

    def test_all_valid_log_levels(self) -> None:
        """Test all valid log levels pass validation."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            settings = Settings()
            settings.log_level = level
            _validate_config(settings)  # Should not raise

    def test_invalid_retention_days_zero(self) -> None:
        """Test validation fails for zero retention_days."""
        settings = Settings()
        settings.collection.retention_days = 0

        with self.assertRaises(ConfigurationError) as ctx:
            _validate_config(settings)

        self.assertIn("retention_days", str(ctx.exception))

    def test_invalid_retention_days_negative(self) -> None:
        """Test validation fails for negative retention_days."""
        settings = Settings()
        settings.collection.retention_days = -1

        with self.assertRaises(ConfigurationError) as ctx:
            _validate_config(settings)

        self.assertIn("retention_days", str(ctx.exception))

    def test_invalid_schedule(self) -> None:
        """Test validation fails for invalid schedule."""
        settings = Settings()
        settings.collection.schedule = "monthly"

        with self.assertRaises(ConfigurationError) as ctx:
            _validate_config(settings)

        self.assertIn("Invalid schedule", str(ctx.exception))

    def test_all_valid_schedules(self) -> None:
        """Test all valid schedules pass validation."""
        for schedule in ["hourly", "daily", "weekly"]:
            settings = Settings()
            settings.collection.schedule = schedule
            _validate_config(settings)  # Should not raise


class TestSettingsToDict(unittest.TestCase):
    """Tests for _settings_to_dict function."""

    def test_settings_to_dict_default(self) -> None:
        """Test converting default settings to dict."""
        settings = Settings()
        result = _settings_to_dict(settings)

        self.assertIn("nisify", result)
        self.assertIn("platforms", result)
        self.assertIn("collection", result)
        self.assertIn("reporting", result)

    def test_settings_to_dict_contains_all_platforms(self) -> None:
        """Test dict contains all platform configurations."""
        settings = Settings()
        result = _settings_to_dict(settings)

        platforms = result["platforms"]
        expected_platforms = {
            "aws", "okta", "jamf", "google", "snowflake",
            "datadog", "gitlab", "jira", "zendesk", "zoom",
            "notion", "slab", "spotdraft"
        }
        self.assertEqual(set(platforms.keys()), expected_platforms)

    def test_settings_to_dict_aws_structure(self) -> None:
        """Test AWS config structure in dict."""
        settings = Settings()
        settings.aws.enabled = True
        settings.aws.profile = "test"
        settings.aws.regions = ["us-west-2"]

        result = _settings_to_dict(settings)

        self.assertEqual(result["platforms"]["aws"]["enabled"], True)
        self.assertEqual(result["platforms"]["aws"]["profile"], "test")
        self.assertEqual(result["platforms"]["aws"]["regions"], ["us-west-2"])


class TestConfigurationErrorException(unittest.TestCase):
    """Tests for ConfigurationError exception."""

    def test_configuration_error_can_be_raised(self) -> None:
        """Test ConfigurationError can be raised and caught."""
        with self.assertRaises(ConfigurationError) as ctx:
            raise ConfigurationError("Test error message")

        self.assertEqual(str(ctx.exception), "Test error message")

    def test_configuration_error_inherits_from_exception(self) -> None:
        """Test ConfigurationError inherits from Exception."""
        self.assertTrue(issubclass(ConfigurationError, Exception))


class TestDefaultConstants(unittest.TestCase):
    """Tests for default configuration constants."""

    def test_default_config_dir_is_home_based(self) -> None:
        """Test DEFAULT_CONFIG_DIR is in user's home directory."""
        self.assertEqual(DEFAULT_CONFIG_DIR, Path.home() / ".nisify")

    def test_default_config_file_is_yaml(self) -> None:
        """Test DEFAULT_CONFIG_FILE is a YAML file."""
        self.assertEqual(DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_DIR / "config.yaml")


class TestCredentialStoreEdgeCases(unittest.TestCase):
    """Tests for edge cases in credential store."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialize_chmod_error_continues(self) -> None:
        """Test that OSError during chmod in initialize is handled gracefully."""
        store = CredentialStore(config_dir=self.config_dir)

        # Mock os.chmod to raise OSError
        with patch("os.chmod") as mock_chmod:
            mock_chmod.side_effect = OSError("Permission denied")

            # Should not raise - continues despite chmod error (lines 193-195)
            store.initialize("test-passphrase-12345678")

            self.assertTrue(store.is_initialized())

    def test_write_secure_file_chmod_error_continues(self) -> None:
        """Test that OSError during chmod in _write_secure_file is handled gracefully."""
        store = CredentialStore(config_dir=self.config_dir)
        store.initialize("test-passphrase-12345678")
        store.unlock("test-passphrase-12345678")

        # Mock os.chmod to raise OSError after initialization
        original_chmod = os.chmod
        call_count = [0]

        def selective_chmod(path, mode):
            call_count[0] += 1
            # Let first few calls succeed (for initialization), then fail
            if call_count[0] > 5:
                raise OSError("Permission denied")
            return original_chmod(path, mode)

        with patch("os.chmod", side_effect=selective_chmod):
            # Should not raise - continues despite chmod error (lines 540-542)
            store.set_credential("aws", "access_key", "test_key")

        # Credential should still be saved
        retrieved = store.get_credential("aws", "access_key")
        self.assertEqual(retrieved, "test_key")

    def test_write_secure_file_cleanup_on_exception(self) -> None:
        """Test that temp file is cleaned up on exception in _write_secure_file."""
        store = CredentialStore(config_dir=self.config_dir)
        store.initialize("test-passphrase-12345678")
        store.unlock("test-passphrase-12345678")

        # Mock Path.rename to raise an exception during save
        with patch.object(Path, "rename") as mock_rename:
            mock_rename.side_effect = PermissionError("Cannot rename file")

            # Should raise the exception (lines 547-551)
            with self.assertRaises(PermissionError):
                store.set_credential("aws", "access_key", "test_key")


class TestSettingsEdgeCases(unittest.TestCase):
    """Tests for edge cases in settings module."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.yaml"

    def tearDown(self) -> None:
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_config_with_default_path(self) -> None:
        """Test load_config with default path (None)."""
        # When path is None, it should use get_config_path() (line 227)
        # We patch get_config_path to return our test path
        with patch("nisify.config.settings.get_config_path") as mock_get_path:
            mock_get_path.return_value = self.config_path

            # Create a config file
            self.config_path.write_text("nisify:\n  data_dir: /test/dir\n")

            settings = load_config(config_path=None)

            # Should have loaded from the default path
            mock_get_path.assert_called_once()
            self.assertEqual(settings.data_dir, "/test/dir")

    def test_load_config_oserror(self) -> None:
        """Test load_config raises ConfigurationError on OSError."""
        # Create a config file that we can't read
        self.config_path.write_text("nisify: {}")

        # Mock open to raise OSError
        with patch("builtins.open") as mock_open:
            mock_open.side_effect = OSError("Permission denied")

            with self.assertRaises(ConfigurationError) as ctx:
                load_config(config_path=self.config_path)

            self.assertIn("Cannot read config file", str(ctx.exception))

    def test_save_config_with_default_path(self) -> None:
        """Test save_config with default path (None)."""
        # When path is None, it should use get_config_path() (line 261)
        with patch("nisify.config.settings.get_config_path") as mock_get_path:
            mock_get_path.return_value = self.config_path

            settings = Settings()
            save_config(settings, config_path=None)

            # Should have saved to the default path
            mock_get_path.assert_called_once()
            self.assertTrue(self.config_path.exists())

    def test_save_config_oserror(self) -> None:
        """Test save_config raises ConfigurationError on OSError."""
        settings = Settings()

        # Mock open to raise OSError
        with patch("builtins.open") as mock_open:
            mock_open.side_effect = OSError("Permission denied")

            with self.assertRaises(ConfigurationError) as ctx:
                save_config(settings, config_path=self.config_path)

            self.assertIn("Cannot write config file", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
