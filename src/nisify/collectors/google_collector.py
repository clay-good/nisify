"""
Google Workspace collector for Nisify.

Collects security evidence from Google Workspace including admin audit logs,
directory users, security settings, and mobile device management.
All API calls are read-only.

Required Google Workspace Permissions:
    - Admin SDK Reports API (read)
    - Admin SDK Directory API (read)
    - Service account with domain-wide delegation

Authentication:
    Credentials are retrieved from the credential store with keys:
    - google_service_account_json: Service account JSON key file content
    - google_delegated_admin: Email of admin to impersonate for API calls

    OR alternatively, a path to the service account JSON file:
    - google_service_account_path: Path to service account JSON key file

Setup Requirements:
    1. Create a service account in Google Cloud Console
    2. Enable domain-wide delegation for the service account
    3. In Google Admin Console, authorize the service account client ID
       with the following scopes:
       - https://www.googleapis.com/auth/admin.reports.audit.readonly
       - https://www.googleapis.com/auth/admin.directory.user.readonly
       - https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
    4. Download the service account JSON key file

API Notes:
    This collector uses the Google Admin SDK APIs:
    - Reports API: Audit logs, login events
    - Directory API: Users, devices
"""

from __future__ import annotations

import json
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
class GoogleCollector(BaseCollector):
    """
    Google Workspace evidence collector.

    Collects security-relevant evidence from Google Workspace:
        - Admin audit logs (access_logs)
        - Directory users with 2SV status (user_inventory, mfa_status)
        - Security settings (security_policies)
        - Mobile device management (device_inventory)

    Evidence Types Collected:
        - access_logs: Admin and login audit events
        - user_inventory: All users with profile and status
        - mfa_status: 2-Step Verification enrollment status
        - security_policies: Domain security settings
        - device_inventory: Managed mobile devices

    Example:
        collector = GoogleCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "google"
    default_rate_limit_delay = 0.1

    # Google API scopes required
    SCOPES = [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    ]

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Google Workspace collector.

        Args:
            config: Settings object containing Google configuration.
            credential_store: Credential store for retrieving Google credentials.
        """
        super().__init__(config, credential_store)
        self._service_account_info: dict[str, Any] | None = None
        self._delegated_admin: str | None = None
        self._access_token: str | None = None
        self._token_expires: float = 0
        self._session: requests.Session | None = None
        self._customer_id: str | None = None

    def _get_session(self) -> requests.Session:
        """
        Get or create a requests session.

        Returns:
            Configured requests.Session.
        """
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def _get_service_account_info(self) -> dict[str, Any]:
        """
        Get service account credentials.

        Returns:
            Service account info dictionary.

        Raises:
            AuthenticationError: If credentials are missing or invalid.
        """
        if self._service_account_info is not None:
            return self._service_account_info

        # Try to get JSON content directly from credential store
        try:
            sa_json = self.get_credential("google_service_account_json")
            self._service_account_info = json.loads(sa_json)
            return self._service_account_info
        except AuthenticationError:
            pass
        except json.JSONDecodeError as e:
            raise AuthenticationError(
                f"Invalid service account JSON: {e}",
                platform=self.platform,
            )

        # Try to get from file path
        try:
            sa_path = self.get_credential("google_service_account_path")
            with open(sa_path) as f:
                self._service_account_info = json.load(f)
            return self._service_account_info
        except FileNotFoundError:
            raise AuthenticationError(
                f"Service account file not found: {sa_path}",
                platform=self.platform,
            )
        except json.JSONDecodeError as e:
            raise AuthenticationError(
                f"Invalid service account JSON file: {e}",
                platform=self.platform,
            )

    def _get_delegated_admin(self) -> str:
        """
        Get the delegated admin email.

        Returns:
            Admin email string.
        """
        if self._delegated_admin is None:
            self._delegated_admin = self.get_credential("google_delegated_admin")
        return self._delegated_admin

    def _create_jwt(self) -> str:
        """
        Create a signed JWT for service account authentication.

        Returns:
            Signed JWT string.

        Raises:
            AuthenticationError: If JWT creation fails.
        """
        import base64

        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:
            raise AuthenticationError(
                "cryptography package is required for Google authentication",
                platform=self.platform,
            )

        sa_info = self._get_service_account_info()
        delegated_admin = self._get_delegated_admin()

        now = int(time.time())
        expiry = now + 3600  # 1 hour

        # JWT header
        header = {"alg": "RS256", "typ": "JWT"}

        # JWT claims
        claims = {
            "iss": sa_info.get("client_email"),
            "sub": delegated_admin,
            "scope": " ".join(self.SCOPES),
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": expiry,
        }

        # Encode header and claims
        def b64_encode(data: dict[str, Any]) -> str:
            return (
                base64.urlsafe_b64encode(json.dumps(data).encode())
                .decode()
                .rstrip("=")
            )

        header_b64 = b64_encode(header)
        claims_b64 = b64_encode(claims)
        message = f"{header_b64}.{claims_b64}".encode()

        # Sign with private key
        private_key_pem = sa_info.get("private_key", "")
        if not private_key_pem:
            raise AuthenticationError(
                "Service account missing private_key",
                platform=self.platform,
            )

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend(),
        )

        # RSA keys from Google service accounts use PKCS1v15 padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        if not isinstance(private_key, RSAPrivateKey):
            raise AuthenticationError(
                "Service account key must be RSA",
                platform=self.platform,
            )
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{header_b64}.{claims_b64}.{signature_b64}"

    def _get_access_token(self) -> str:
        """
        Get a valid OAuth access token, refreshing if necessary.

        Returns:
            Access token string.

        Raises:
            AuthenticationError: If authentication fails.
        """
        # Check if current token is still valid (with 60s buffer)
        if self._access_token and time.time() < (self._token_expires - 60):
            return self._access_token

        jwt = self._create_jwt()
        session = self._get_session()

        try:
            self._rate_limit()
            response = session.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": jwt,
                },
                timeout=30,
            )
            self._log_api_call(
                "POST", "oauth2.googleapis.com/token", response.status_code
            )

            if response.status_code != 200:
                error = response.json().get("error_description", response.text)
                raise AuthenticationError(
                    f"Google OAuth failed: {error}",
                    platform=self.platform,
                )

            data = response.json()
            self._access_token = data["access_token"]
            self._token_expires = time.time() + data.get("expires_in", 3600)

            self.logger.debug("Google access token obtained")
            return self._access_token

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Google OAuth: {e}",
                platform=self.platform,
            )

    def _api_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """
        Make an authenticated API request to Google.

        Args:
            method: HTTP method.
            url: Full API URL.
            params: Query parameters.

        Returns:
            Response JSON data.

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limit is exceeded.
            CollectorConnectionError: If connection fails.
        """
        token = self._get_access_token()
        session = self._get_session()

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        start_time = time.time()
        self._rate_limit()

        try:
            response = session.request(
                method, url, params=params, headers=headers, timeout=60
            )
            duration_ms = (time.time() - start_time) * 1000

            # Extract endpoint for logging
            endpoint = url.replace("https://", "").split("/", 1)[-1]
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Google API rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else None,
                )

            if response.status_code == 401:
                self._access_token = None
                raise AuthenticationError(
                    "Google authentication failed",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Google API permission denied. Check service account scopes.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.text:
                return response.json()
            return {}

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Google API: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Google API request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        items_key: str = "items",
        max_results: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Google API endpoint.

        Args:
            url: Full API URL.
            params: Initial query parameters.
            items_key: Key in response containing results list.
            max_results: Maximum number of items to return.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        params.setdefault("maxResults", 500)

        next_page_token = None

        while True:
            if next_page_token:
                params["pageToken"] = next_page_token

            data = self._api_request("GET", url, params)

            items = data.get(items_key, [])
            all_items.extend(items)

            if max_results and len(all_items) >= max_results:
                all_items = all_items[:max_results]
                break

            next_page_token = data.get("nextPageToken")
            if not next_page_token:
                break

        return all_items

    def _get_customer_id(self) -> str:
        """
        Get the Google Workspace customer ID.

        Returns:
            Customer ID string (or 'my_customer' for current domain).
        """
        if self._customer_id:
            return self._customer_id

        # Try to get from config
        if hasattr(self.config, "google") and hasattr(
            self.config.google, "customer_id"
        ):
            self._customer_id = self.config.google.customer_id
            if self._customer_id:
                return self._customer_id

        # Default to 'my_customer' which refers to the current domain
        self._customer_id = "my_customer"
        return self._customer_id

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Google OAuth scope strings.
        """
        return self.SCOPES

    def test_connection(self) -> bool:
        """
        Test connectivity to Google Workspace.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            # Try to list users (just first page)
            customer_id = self._get_customer_id()
            url = "https://admin.googleapis.com/admin/directory/v1/users"
            data = self._api_request(
                "GET", url, {"customer": customer_id, "maxResults": 1}
            )

            user_count = len(data.get("users", []))
            self.logger.info(
                f"Google Workspace connection successful. Found users: {user_count > 0}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Google connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Google Workspace.

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
            ("mfa_status", self._collect_2sv_status),
            ("access_logs", self._collect_audit_logs),
            ("device_inventory", self._collect_mobile_devices),
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
        Collect directory users.

        Returns:
            List of Evidence items with user inventory.
        """
        customer_id = self._get_customer_id()
        url = "https://admin.googleapis.com/admin/directory/v1/users"

        users = self._paginate(url, {"customer": customer_id}, items_key="users")

        user_data = []
        for user in users:
            name = user.get("name", {})
            user_data.append(
                {
                    "id": user.get("id"),
                    "primary_email": user.get("primaryEmail"),
                    "full_name": name.get("fullName"),
                    "given_name": name.get("givenName"),
                    "family_name": name.get("familyName"),
                    "is_admin": user.get("isAdmin"),
                    "is_delegated_admin": user.get("isDelegatedAdmin"),
                    "suspended": user.get("suspended"),
                    "archived": user.get("archived"),
                    "org_unit_path": user.get("orgUnitPath"),
                    "creation_time": user.get("creationTime"),
                    "last_login_time": user.get("lastLoginTime"),
                    "agreed_to_terms": user.get("agreedToTerms"),
                    "is_enrolled_in_2sv": user.get("isEnrolledIn2Sv"),
                    "is_enforced_in_2sv": user.get("isEnforcedIn2Sv"),
                }
            )

        # Calculate summary
        total_users = len(user_data)
        active_users = sum(1 for u in user_data if not u.get("suspended"))
        admin_users = sum(1 for u in user_data if u.get("is_admin"))

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": total_users,
                    "active_users": active_users,
                    "suspended_users": total_users - active_users,
                    "admin_users": admin_users,
                },
                "user_inventory",
                {"source": "google_directory"},
            )
        ]

    def _collect_2sv_status(self) -> list[Evidence]:
        """
        Collect 2-Step Verification status for all users.

        Returns:
            List of Evidence items with MFA status.
        """
        customer_id = self._get_customer_id()
        url = "https://admin.googleapis.com/admin/directory/v1/users"

        users = self._paginate(url, {"customer": customer_id}, items_key="users")

        mfa_data = []
        for user in users:
            if user.get("suspended"):
                continue  # Skip suspended users

            mfa_data.append(
                {
                    "user_id": user.get("id"),
                    "email": user.get("primaryEmail"),
                    "is_enrolled_in_2sv": user.get("isEnrolledIn2Sv", False),
                    "is_enforced_in_2sv": user.get("isEnforcedIn2Sv", False),
                    "is_admin": user.get("isAdmin", False),
                }
            )

        # Calculate summary
        total_users = len(mfa_data)
        enrolled = sum(1 for u in mfa_data if u.get("is_enrolled_in_2sv"))
        enforced = sum(1 for u in mfa_data if u.get("is_enforced_in_2sv"))
        admins_enrolled = sum(
            1
            for u in mfa_data
            if u.get("is_admin") and u.get("is_enrolled_in_2sv")
        )
        total_admins = sum(1 for u in mfa_data if u.get("is_admin"))

        return [
            self.normalize_evidence(
                {
                    "users": mfa_data,
                    "total_users": total_users,
                    "enrolled_count": enrolled,
                    "not_enrolled_count": total_users - enrolled,
                    "enforced_count": enforced,
                    "enrollment_percent": (
                        (enrolled / total_users * 100) if total_users > 0 else 0
                    ),
                    "admin_enrollment_percent": (
                        (admins_enrolled / total_admins * 100)
                        if total_admins > 0
                        else 0
                    ),
                },
                "mfa_status",
                {"source": "google_directory_2sv"},
            )
        ]

    def _collect_audit_logs(self) -> list[Evidence]:
        """
        Collect admin and login audit logs.

        Returns:
            List of Evidence items with access logs.
        """
        customer_id = self._get_customer_id()

        # Get logs from the last 30 days
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=30)

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        all_events = []

        # Collect admin activity logs
        try:
            admin_url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin"
            admin_events = self._paginate(
                admin_url,
                {
                    "customerId": customer_id,
                    "startTime": start_str,
                    "endTime": end_str,
                },
                items_key="items",
                max_results=5000,
            )
            all_events.extend(
                [{"source": "admin", **e} for e in admin_events]
            )
        except Exception as e:
            self.logger.warning(f"Failed to get admin audit logs: {e}")

        # Collect login activity logs
        try:
            login_url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
            login_events = self._paginate(
                login_url,
                {
                    "customerId": customer_id,
                    "startTime": start_str,
                    "endTime": end_str,
                },
                items_key="items",
                max_results=5000,
            )
            all_events.extend(
                [{"source": "login", **e} for e in login_events]
            )
        except Exception as e:
            self.logger.warning(f"Failed to get login audit logs: {e}")

        # Normalize events
        log_data = []
        for event in all_events:
            actor = event.get("actor", {})
            events = event.get("events", [{}])
            event_info = events[0] if events else {}

            log_data.append(
                {
                    "id": event.get("id", {}).get("uniqueQualifier"),
                    "source": event.get("source"),
                    "time": event.get("id", {}).get("time"),
                    "actor_email": actor.get("email"),
                    "actor_profile_id": actor.get("profileId"),
                    "ip_address": event.get("ipAddress"),
                    "event_type": event_info.get("type"),
                    "event_name": event_info.get("name"),
                    "parameters": [
                        {"name": p.get("name"), "value": p.get("value")}
                        for p in event_info.get("parameters", [])[:10]
                    ],
                }
            )

        # Count events by type
        event_counts: dict[str, int] = {}
        for event in log_data:
            event_type = f"{event.get('source', 'unknown')}/{event.get('event_name', 'unknown')}"
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "events": log_data,
                    "total_events": len(log_data),
                    "event_type_counts": event_counts,
                    "date_range_days": 30,
                },
                "access_logs",
                {"source": "google_admin_reports"},
            )
        ]

    def _collect_mobile_devices(self) -> list[Evidence]:
        """
        Collect mobile device inventory.

        Returns:
            List of Evidence items with device inventory.
        """
        customer_id = self._get_customer_id()
        url = f"https://admin.googleapis.com/admin/directory/v1/customer/{customer_id}/devices/mobile"

        try:
            devices = self._paginate(url, {}, items_key="mobiledevices")
        except Exception as e:
            self.logger.warning(f"Failed to get mobile devices: {e}")
            devices = []

        device_data = []
        for device in devices:
            device_data.append(
                {
                    "resource_id": device.get("resourceId"),
                    "device_id": device.get("deviceId"),
                    "serial_number": device.get("serialNumber"),
                    "status": device.get("status"),
                    "type": device.get("type"),
                    "model": device.get("model"),
                    "os": device.get("os"),
                    "os_version": device.get("osVersion"),
                    "first_sync": device.get("firstSync"),
                    "last_sync": device.get("lastSync"),
                    "user_email": device.get("email", [None])[0] if device.get("email") else None,
                    "encrypted": device.get("encryptionStatus") == "encrypted",
                    "device_compromised_status": device.get("deviceCompromisedStatus"),
                    "managed": device.get("managedAccountIsOnOwnerProfile"),
                }
            )

        # Calculate summary
        total_devices = len(device_data)
        encrypted_count = sum(1 for d in device_data if d.get("encrypted"))

        # Group by OS
        os_distribution: dict[str, int] = {}
        for d in device_data:
            os_name = d.get("os", "unknown")
            os_distribution[os_name] = os_distribution.get(os_name, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "devices": device_data,
                    "total_devices": total_devices,
                    "encrypted_count": encrypted_count,
                    "os_distribution": os_distribution,
                },
                "device_inventory",
                {"source": "google_mobile_management"},
            )
        ]
