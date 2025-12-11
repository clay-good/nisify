"""
Secure credential storage for Nisify.

This module provides encrypted storage for sensitive credentials (API tokens,
passwords, client secrets) using Fernet symmetric encryption with PBKDF2
key derivation.

Security Design:
    - Credentials are never stored in plaintext
    - Encryption key derived from user passphrase using PBKDF2 (600,000 iterations)
    - Random 256-bit salt generated per installation and stored separately
    - Credentials decrypted into memory only when needed
    - Minimum 12-character passphrase required
    - File permissions set to owner-only (0600)

Threat Model:
    - Protects against: filesystem access by unauthorized users, accidental
      exposure in backups, casual inspection of config directory
    - Does NOT protect against: memory inspection, keyloggers, root access,
      or compromise of the running process
"""

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from nisify.config.settings import DEFAULT_CONFIG_DIR

# Security parameters - do not reduce these values
# OWASP 2023 recommends 600,000 iterations for PBKDF2-SHA256
# See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 32  # 256 bits
SESSION_TIMEOUT_SECONDS = 3600  # 1 hour default
MIN_PASSPHRASE_LENGTH = 12  # NIST recommends 8+, but 12+ is better for key derivation


class CredentialError(Exception):
    """Base exception for credential-related errors."""

    pass


class CredentialStoreNotInitializedError(CredentialError):
    """Raised when credential store has not been initialized."""

    pass


class CredentialStoreLockedError(CredentialError):
    """Raised when credential store is locked and passphrase is required."""

    pass


class InvalidPassphraseError(CredentialError):
    """Raised when the provided passphrase is incorrect."""

    pass


class CredentialNotFoundError(CredentialError):
    """Raised when a requested credential does not exist."""

    pass


@dataclass
class CredentialSession:
    """
    Represents an active credential session with decrypted access.

    The session tracks when it was created and enforces a timeout
    after which the passphrase must be re-entered.
    """

    fernet: Fernet
    created_at: float = field(default_factory=time.time)
    timeout_seconds: int = SESSION_TIMEOUT_SECONDS

    def is_expired(self) -> bool:
        """Check if this session has expired."""
        return time.time() - self.created_at > self.timeout_seconds

    def clear(self) -> None:
        """
        Clear sensitive data from memory.

        Note: Python does not guarantee immediate memory clearing due to
        garbage collection and string interning. This is a best-effort
        attempt to reduce the window of exposure.
        """
        # Replace the fernet key reference - the actual key may still
        # exist in memory until garbage collected
        self.fernet = None  # type: ignore


class CredentialStore:
    """
    Encrypted credential storage with session-based access.

    This class manages encrypted storage of platform credentials. Credentials
    are organized by platform and key, allowing storage of multiple values
    per platform (e.g., api_key, client_secret).

    Usage:
        store = CredentialStore()

        # First time setup
        if not store.is_initialized():
            store.initialize("my-secure-passphrase")

        # Unlock to access credentials
        store.unlock("my-secure-passphrase")

        # Store credentials
        store.set_credential("okta", "api_token", "00abc123...")

        # Retrieve credentials
        token = store.get_credential("okta", "api_token")

        # Lock when done
        store.lock()

    File Structure:
        ~/.nisify/salt           - Random salt for key derivation (32 bytes)
        ~/.nisify/credentials.enc - Encrypted JSON blob of all credentials

    Attributes:
        config_dir: Directory containing credential files.
        salt_path: Path to the salt file.
        credentials_path: Path to the encrypted credentials file.
    """

    def __init__(self, config_dir: Path | None = None) -> None:
        """
        Initialize the credential store.

        Args:
            config_dir: Directory for credential files. Defaults to ~/.nisify
        """
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.salt_path = self.config_dir / "salt"
        self.credentials_path = self.config_dir / "credentials.enc"
        self._session: CredentialSession | None = None

    def is_initialized(self) -> bool:
        """
        Check if the credential store has been initialized.

        Returns:
            True if salt and credentials files exist.
        """
        return self.salt_path.exists() and self.credentials_path.exists()

    def initialize(self, passphrase: str) -> None:
        """
        Initialize a new credential store with the given passphrase.

        Creates the config directory if needed, generates a random salt,
        and creates an empty encrypted credentials file.

        Args:
            passphrase: The passphrase to use for encryption. Should be
                       strong (12+ characters, mixed case, numbers, symbols).

        Raises:
            CredentialError: If the store is already initialized or if
                           files cannot be created.
            ValueError: If the passphrase is too short (minimum 12 characters).
        """
        if self.is_initialized():
            raise CredentialError(
                "Credential store already initialized. "
                "Delete ~/.nisify/salt and ~/.nisify/credentials.enc to reset."
            )

        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(
                f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters. "
                "Longer passphrases provide better security."
            )

        # Create config directory with restrictive permissions
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Set directory permissions to owner-only (Unix)
            os.chmod(self.config_dir, 0o700)
        except OSError:
            # Windows or permission error - continue anyway
            pass

        # Generate cryptographically secure random salt
        salt = secrets.token_bytes(SALT_LENGTH)

        # Write salt file with restrictive permissions
        self._write_secure_file(self.salt_path, salt)

        # Derive key and create empty credentials
        fernet = self._derive_key(passphrase, salt)
        empty_credentials: dict[str, dict[str, str]] = {}
        encrypted = fernet.encrypt(json.dumps(empty_credentials).encode())

        # Write encrypted credentials file
        self._write_secure_file(self.credentials_path, encrypted)

        # Start a session
        self._session = CredentialSession(fernet=fernet)

    def unlock(self, passphrase: str, timeout_seconds: int | None = None) -> None:
        """
        Unlock the credential store with the given passphrase.

        Derives the encryption key from the passphrase and verifies it
        can decrypt the credentials file. If successful, starts a session
        that allows credential access until timeout or lock().

        Args:
            passphrase: The passphrase used during initialization.
            timeout_seconds: Session timeout in seconds. Defaults to 1 hour.

        Raises:
            CredentialStoreNotInitializedError: If store not initialized.
            InvalidPassphraseError: If passphrase is incorrect.
        """
        if not self.is_initialized():
            raise CredentialStoreNotInitializedError(
                "Credential store not initialized. Run 'nisify init' first."
            )

        salt = self.salt_path.read_bytes()
        fernet = self._derive_key(passphrase, salt)

        # Verify the passphrase by attempting to decrypt
        try:
            encrypted = self.credentials_path.read_bytes()
            fernet.decrypt(encrypted)
        except InvalidToken as e:
            raise InvalidPassphraseError(
                "Invalid passphrase. Cannot decrypt credentials."
            ) from e

        timeout = timeout_seconds or SESSION_TIMEOUT_SECONDS
        self._session = CredentialSession(fernet=fernet, timeout_seconds=timeout)

    def lock(self) -> None:
        """
        Lock the credential store, clearing the session.

        After locking, the passphrase must be provided again to access
        credentials.
        """
        if self._session is not None:
            self._session.clear()
            self._session = None

    def is_unlocked(self) -> bool:
        """
        Check if the credential store is currently unlocked.

        Returns:
            True if unlocked and session has not expired.
        """
        if self._session is None:
            return False
        if self._session.is_expired():
            self.lock()
            return False
        return True

    def get_credential(self, platform: str, key: str) -> str:
        """
        Retrieve a credential value.

        Args:
            platform: Platform identifier (e.g., "okta", "aws").
            key: Credential key (e.g., "api_token", "client_secret").

        Returns:
            The credential value as a string.

        Raises:
            CredentialStoreLockedError: If store is locked.
            CredentialNotFoundError: If credential does not exist.
        """
        self._require_unlocked()

        credentials = self._load_credentials()

        if platform not in credentials:
            raise CredentialNotFoundError(
                f"No credentials stored for platform: {platform}"
            )

        if key not in credentials[platform]:
            raise CredentialNotFoundError(
                f"Credential '{key}' not found for platform: {platform}"
            )

        return credentials[platform][key]

    def set_credential(self, platform: str, key: str, value: str) -> None:
        """
        Store a credential value.

        Args:
            platform: Platform identifier (e.g., "okta", "aws").
            key: Credential key (e.g., "api_token", "client_secret").
            value: The credential value to store.

        Raises:
            CredentialStoreLockedError: If store is locked.
        """
        self._require_unlocked()

        credentials = self._load_credentials()

        if platform not in credentials:
            credentials[platform] = {}

        credentials[platform][key] = value

        self._save_credentials(credentials)

    def delete_credential(self, platform: str, key: str) -> None:
        """
        Delete a credential value.

        Args:
            platform: Platform identifier.
            key: Credential key.

        Raises:
            CredentialStoreLockedError: If store is locked.
            CredentialNotFoundError: If credential does not exist.
        """
        self._require_unlocked()

        credentials = self._load_credentials()

        if platform not in credentials or key not in credentials.get(platform, {}):
            raise CredentialNotFoundError(
                f"Credential '{key}' not found for platform: {platform}"
            )

        del credentials[platform][key]

        # Remove platform entry if empty
        if not credentials[platform]:
            del credentials[platform]

        self._save_credentials(credentials)

    def delete_platform_credentials(self, platform: str) -> None:
        """
        Delete all credentials for a platform.

        Args:
            platform: Platform identifier.

        Raises:
            CredentialStoreLockedError: If store is locked.
            CredentialNotFoundError: If platform has no credentials.
        """
        self._require_unlocked()

        credentials = self._load_credentials()

        if platform not in credentials:
            raise CredentialNotFoundError(
                f"No credentials stored for platform: {platform}"
            )

        del credentials[platform]
        self._save_credentials(credentials)

    def list_platforms(self) -> list[str]:
        """
        List all platforms with stored credentials.

        Returns:
            List of platform identifiers.

        Raises:
            CredentialStoreLockedError: If store is locked.
        """
        self._require_unlocked()
        credentials = self._load_credentials()
        return list(credentials.keys())

    def list_credentials(self, platform: str) -> list[str]:
        """
        List all credential keys for a platform.

        Args:
            platform: Platform identifier.

        Returns:
            List of credential keys (not values).

        Raises:
            CredentialStoreLockedError: If store is locked.
            CredentialNotFoundError: If platform has no credentials.
        """
        self._require_unlocked()

        credentials = self._load_credentials()

        if platform not in credentials:
            raise CredentialNotFoundError(
                f"No credentials stored for platform: {platform}"
            )

        return list(credentials[platform].keys())

    def has_credential(self, platform: str, key: str) -> bool:
        """
        Check if a credential exists without retrieving it.

        Args:
            platform: Platform identifier.
            key: Credential key.

        Returns:
            True if the credential exists.

        Raises:
            CredentialStoreLockedError: If store is locked.
        """
        self._require_unlocked()

        credentials = self._load_credentials()
        return platform in credentials and key in credentials.get(platform, {})

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        """
        Change the encryption passphrase.

        Decrypts all credentials with the old passphrase, generates a new
        salt, and re-encrypts with the new passphrase.

        Args:
            old_passphrase: Current passphrase.
            new_passphrase: New passphrase (minimum 8 characters).

        Raises:
            InvalidPassphraseError: If old passphrase is incorrect.
            ValueError: If new passphrase is too short.
        """
        if len(new_passphrase) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(
                f"New passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
            )

        # Unlock with old passphrase
        self.unlock(old_passphrase)

        # Load current credentials
        credentials = self._load_credentials()

        # Lock the old session
        self.lock()

        # Generate new salt
        new_salt = secrets.token_bytes(SALT_LENGTH)
        self._write_secure_file(self.salt_path, new_salt)

        # Derive new key and re-encrypt
        new_fernet = self._derive_key(new_passphrase, new_salt)
        encrypted = new_fernet.encrypt(json.dumps(credentials).encode())
        self._write_secure_file(self.credentials_path, encrypted)

        # Start new session
        self._session = CredentialSession(fernet=new_fernet)

    def _require_unlocked(self) -> None:
        """Raise an error if the store is not unlocked."""
        if not self.is_unlocked():
            raise CredentialStoreLockedError(
                "Credential store is locked. Call unlock() with passphrase first."
            )

    def _derive_key(self, passphrase: str, salt: bytes) -> Fernet:
        """
        Derive an encryption key from passphrase and salt.

        Uses PBKDF2 with SHA-256 and 100,000 iterations as recommended
        by OWASP for password-based key derivation.

        Args:
            passphrase: User-provided passphrase.
            salt: Random salt bytes.

        Returns:
            Fernet instance configured with the derived key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet requires 32-byte keys
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return Fernet(key)

    def _load_credentials(self) -> dict[str, dict[str, str]]:
        """Load and decrypt credentials from file."""
        assert self._session is not None

        encrypted = self.credentials_path.read_bytes()
        decrypted = self._session.fernet.decrypt(encrypted)
        data: dict[str, dict[str, str]] = json.loads(decrypted.decode())
        return data

    def _save_credentials(self, credentials: dict[str, dict[str, str]]) -> None:
        """Encrypt and save credentials to file."""
        assert self._session is not None

        encrypted = self._session.fernet.encrypt(json.dumps(credentials).encode())
        self._write_secure_file(self.credentials_path, encrypted)

    def _write_secure_file(self, path: Path, data: bytes) -> None:
        """
        Write data to file with restrictive permissions.

        Uses atomic write (write to temp, then rename) to prevent
        partial writes from corrupting the file.
        """
        # Write to temporary file first
        temp_path = path.with_suffix(".tmp")

        try:
            temp_path.write_bytes(data)

            # Set restrictive permissions (owner read/write only)
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                # Windows or permission error - continue anyway
                pass

            # Atomic rename
            temp_path.rename(path)

        except Exception:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise


def get_credential_for_platform(
    platform: str,
    credential_store: CredentialStore | None = None,
) -> dict[str, str]:
    """
    Get all credentials for a platform as a dictionary.

    Convenience function for collectors that need multiple credentials.

    Args:
        platform: Platform identifier.
        credential_store: Optional CredentialStore instance. If not provided,
                         creates a new instance (which must be unlocked separately).

    Returns:
        Dictionary of credential key-value pairs.

    Raises:
        CredentialStoreLockedError: If store is locked.
        CredentialNotFoundError: If platform has no credentials.
    """
    store = credential_store or CredentialStore()

    keys = store.list_credentials(platform)
    return {key: store.get_credential(platform, key) for key in keys}


# Platform-specific credential key constants
# These define the expected credential keys for each platform

AWS_CREDENTIALS = {
    # AWS uses IAM roles or profiles, not stored credentials by default
    # Optional: access keys for non-profile authentication
    "access_key_id": "AWS Access Key ID (optional, prefer IAM roles)",
    "secret_access_key": "AWS Secret Access Key (optional)",
}

OKTA_CREDENTIALS = {
    "api_token": "Okta API Token (created in Admin > Security > API)",
}

JAMF_CREDENTIALS = {
    "client_id": "Jamf Pro API Client ID",
    "client_secret": "Jamf Pro API Client Secret",
}

GOOGLE_CREDENTIALS: dict[str, str] = {
    # Google uses service account JSON file, path stored in config
    # No credentials stored here by default
}

SNOWFLAKE_CREDENTIALS = {
    "username": "Snowflake username",
    "password": "Snowflake password (or use private_key_path)",
    "private_key_path": "Path to private key file (alternative to password)",
    "private_key_passphrase": "Passphrase for private key (if encrypted)",
}

DATADOG_CREDENTIALS = {
    "api_key": "Datadog API Key",
    "app_key": "Datadog Application Key",
}

GITLAB_CREDENTIALS = {
    "gitlab_url": "GitLab URL (e.g., https://gitlab.com or self-hosted)",
    "gitlab_token": "GitLab Personal Access Token (api or read_api scope)",
}

JIRA_CREDENTIALS = {
    "jira_url": "Jira URL (e.g., https://your-org.atlassian.net)",
    "jira_email": "Jira account email",
    "jira_api_token": "Jira API Token (from id.atlassian.com)",
}

ZENDESK_CREDENTIALS = {
    "zendesk_subdomain": "Zendesk subdomain (e.g., 'company' for company.zendesk.com)",
    "zendesk_email": "Zendesk admin/agent email",
    "zendesk_api_token": "Zendesk API Token (Admin > Channels > API)",
}

ZOOM_CREDENTIALS = {
    "zoom_account_id": "Zoom Account ID (from Server-to-Server OAuth app)",
    "zoom_client_id": "Zoom Client ID",
    "zoom_client_secret": "Zoom Client Secret",
}

NOTION_CREDENTIALS = {
    "notion_api_token": "Notion Internal Integration Token (from notion.so/my-integrations)",
}

SLAB_CREDENTIALS = {
    "slab_api_token": "Slab API Token (from Settings > Integrations > API)",
}

SPOTDRAFT_CREDENTIALS = {
    "spotdraft_api_key": "SpotDraft API Key",
    "spotdraft_subdomain": "SpotDraft subdomain (optional)",
}

PLATFORM_CREDENTIAL_KEYS: dict[str, dict[str, str]] = {
    "aws": AWS_CREDENTIALS,
    "okta": OKTA_CREDENTIALS,
    "jamf": JAMF_CREDENTIALS,
    "google": GOOGLE_CREDENTIALS,
    "snowflake": SNOWFLAKE_CREDENTIALS,
    "datadog": DATADOG_CREDENTIALS,
    "gitlab": GITLAB_CREDENTIALS,
    "jira": JIRA_CREDENTIALS,
    "zendesk": ZENDESK_CREDENTIALS,
    "zoom": ZOOM_CREDENTIALS,
    "notion": NOTION_CREDENTIALS,
    "slab": SLAB_CREDENTIALS,
    "spotdraft": SPOTDRAFT_CREDENTIALS,
}
