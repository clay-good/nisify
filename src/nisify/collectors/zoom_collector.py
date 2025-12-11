"""
Zoom collector for Nisify.

Collects security evidence from Zoom including users, meetings, recordings,
security settings, and audit logs. All API calls are read-only.

Required Zoom Permissions (Server-to-Server OAuth):
    - user:read:admin
    - meeting:read:admin
    - recording:read:admin
    - dashboard:read:admin
    - report:read:admin

Authentication:
    Credentials are retrieved from the credential store with keys:
    - zoom_account_id: Account ID from Server-to-Server OAuth app
    - zoom_client_id: Client ID from Server-to-Server OAuth app
    - zoom_client_secret: Client Secret from Server-to-Server OAuth app

Rate Limiting:
    Zoom API has rate limits based on plan type. This collector:
    - Monitors X-RateLimit-Remaining headers
    - Uses exponential backoff on 429 responses
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
class ZoomCollector(BaseCollector):
    """
    Zoom evidence collector.

    Collects security-relevant evidence from Zoom:
        - User directory (user_inventory)
        - Meeting settings (meeting_security)
        - Recording settings (data_protection)
        - Security settings (security_config)
        - Sign-in/sign-out activity (access_logs)

    Evidence Types Collected:
        - user_inventory: All users with roles and settings
        - meeting_security: Meeting security configurations
        - data_protection: Recording and data handling settings
        - security_config: Account-level security settings
        - access_logs: User activity and sign-in events

    Example:
        collector = ZoomCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "zoom"
    default_rate_limit_delay = 0.1

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Zoom collector.

        Args:
            config: Settings object containing Zoom configuration.
            credential_store: Credential store for retrieving Zoom credentials.
        """
        super().__init__(config, credential_store)
        self._base_url = "https://api.zoom.us/v2"
        self._access_token: str | None = None
        self._token_expires_at: float = 0
        self._session: requests.Session | None = None

    def _get_access_token(self) -> str:
        """
        Get OAuth access token, refreshing if necessary.

        Returns:
            Valid access token.

        Raises:
            AuthenticationError: If authentication fails.
        """
        # Check if we have a valid token
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        # Get credentials
        account_id = self.get_credential("zoom_account_id")
        client_id = self.get_credential("zoom_client_id")
        client_secret = self.get_credential("zoom_client_secret")

        # Request new token
        token_url = "https://zoom.us/oauth/token"
        try:
            response = requests.post(
                token_url,
                params={"grant_type": "account_credentials", "account_id": account_id},
                auth=(client_id, client_secret),
                timeout=30,
            )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Zoom OAuth authentication failed. Check client ID and secret.",
                    platform=self.platform,
                )

            response.raise_for_status()
            data = response.json()

            self._access_token = data["access_token"]
            self._token_expires_at = time.time() + data.get("expires_in", 3600)

            return self._access_token

        except requests.exceptions.RequestException as e:
            raise AuthenticationError(
                f"Failed to obtain Zoom access token: {e}",
                platform=self.platform,
            )

    def _get_session(self) -> requests.Session:
        """
        Get or create a requests session with authentication.

        Returns:
            Configured requests.Session.
        """
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(
                {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
            )

        # Update authorization header with current token
        token = self._get_access_token()
        self._session.headers["Authorization"] = f"Bearer {token}"

        return self._session

    def _api_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        """
        Make an API request to Zoom.

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

            # Check rate limit headers
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining and int(remaining) < 5:
                self.logger.warning(f"Rate limit low: {remaining} requests remaining")

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Zoom rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else 60,
                )

            if response.status_code == 401:
                # Token might have expired, clear it
                self._access_token = None
                raise AuthenticationError(
                    "Zoom authentication failed. Token may have expired.",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Zoom permission denied. Check OAuth scopes.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}, dict(response.headers)

            return response.json(), dict(response.headers)

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Zoom: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Zoom request timed out: {e}",
                platform=self.platform,
            )

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        """
        Paginate through a Zoom API endpoint.

        Zoom uses next_page_token for pagination.

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
        params.setdefault("page_size", 300)

        next_page_token = None

        while True:
            if next_page_token:
                params["next_page_token"] = next_page_token

            data, _ = self._api_request("GET", endpoint, params)

            # Find results in response
            if results_key and results_key in data:
                items = data[results_key]
            else:
                # Try common keys
                for key in ["users", "meetings", "recordings", "activity_logs"]:
                    if key in data:
                        items = data[key]
                        break
                else:
                    items = []

            all_items.extend(items)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Check for next page
            next_page_token = data.get("next_page_token")
            if not next_page_token:
                break

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Zoom permission strings.
        """
        return [
            "user:read:admin",
            "meeting:read:admin",
            "recording:read:admin",
            "dashboard:read:admin",
            "report:read:admin",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Zoom.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            data, _ = self._api_request("GET", "/users/me")
            self.logger.info(
                f"Zoom connection successful. User: {data.get('email')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Zoom connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Zoom.

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
            ("meeting_security", self._collect_meeting_settings),
            ("data_protection", self._collect_recording_settings),
            ("security_config", self._collect_security_settings),
            ("access_logs", self._collect_activity_logs),
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
        users = self._paginate("/users", {"status": "active"}, results_key="users")

        user_data = []
        for user in users:
            user_data.append(
                {
                    "id": user.get("id"),
                    "email": user.get("email"),
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "type": user.get("type"),  # 1=Basic, 2=Licensed, 3=On-prem
                    "role_name": user.get("role_name"),
                    "role_id": user.get("role_id"),
                    "pmi": user.get("pmi"),
                    "timezone": user.get("timezone"),
                    "verified": user.get("verified"),
                    "created_at": user.get("created_at"),
                    "last_login_time": user.get("last_login_time"),
                    "language": user.get("language"),
                    "status": user.get("status"),
                    "dept": user.get("dept"),
                    "group_ids": user.get("group_ids", []),
                }
            )

        # Type mapping
        type_names: dict[int, str] = {1: "Basic", 2: "Licensed", 3: "On-prem"}
        type_counts: dict[str, int] = {}
        for user in user_data:
            user_type = user.get("type")
            t = type_names.get(user_type, "Unknown") if user_type is not None else "Unknown"
            type_counts[t] = type_counts.get(t, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "users": user_data,
                    "total_users": len(user_data),
                    "user_type_counts": type_counts,
                    "verified_users": sum(1 for u in user_data if u.get("verified")),
                },
                "user_inventory",
                {"source": "zoom_users"},
            )
        ]

    def _collect_meeting_settings(self) -> list[Evidence]:
        """
        Collect meeting security settings.

        Returns:
            List of Evidence items with meeting security configuration.
        """
        meeting_data: dict[str, Any] = {
            "account_settings": {},
            "user_settings_sample": [],
        }

        # Get account-level meeting settings
        try:
            data, _ = self._api_request("GET", "/accounts/me/settings")
            meeting_settings = data.get("meeting", {})
            meeting_data["account_settings"] = {
                "require_password_for_scheduling_new_meetings": meeting_settings.get(
                    "require_password_for_scheduling_new_meetings"
                ),
                "require_password_for_instant_meetings": meeting_settings.get(
                    "require_password_for_instant_meetings"
                ),
                "require_password_for_pmi_meetings": meeting_settings.get(
                    "require_password_for_pmi_meetings"
                ),
                "embed_password_in_join_link": meeting_settings.get(
                    "embed_password_in_join_link"
                ),
                "waiting_room": meeting_settings.get("waiting_room"),
                "participant_video": meeting_settings.get("participant_video"),
                "host_video": meeting_settings.get("host_video"),
                "personal_meeting": meeting_settings.get("personal_meeting"),
                "mute_upon_entry": meeting_settings.get("mute_upon_entry"),
                "screen_sharing": meeting_settings.get("screen_sharing"),
                "who_can_share_screen": meeting_settings.get("who_can_share_screen"),
                "who_can_share_screen_when_someone_is_sharing": meeting_settings.get(
                    "who_can_share_screen_when_someone_is_sharing"
                ),
                "annotation": meeting_settings.get("annotation"),
                "whiteboard": meeting_settings.get("whiteboard"),
                "remote_control": meeting_settings.get("remote_control"),
                "allow_participants_to_rename": meeting_settings.get(
                    "allow_participants_to_rename"
                ),
            }
        except Exception as e:
            self.logger.warning(f"Failed to get account meeting settings: {e}")

        # Sample user settings (first 10 users)
        try:
            users = self._paginate("/users", {"status": "active"}, results_key="users", limit=10)
            for user in users:
                try:
                    user_settings, _ = self._api_request(
                        "GET", f"/users/{user['id']}/settings"
                    )
                    meeting = user_settings.get("meeting", {})
                    meeting_data["user_settings_sample"].append(
                        {
                            "user_id": user["id"],
                            "email": user.get("email"),
                            "waiting_room": meeting.get("waiting_room"),
                            "require_password": meeting.get("require_password"),
                            "pmi_password": meeting.get("pmi_password"),
                            "e2e_encryption": meeting.get("end_to_end_encrypted_meetings"),
                        }
                    )
                except Exception:
                    pass
        except Exception as e:
            self.logger.warning(f"Failed to get user meeting settings: {e}")

        return [
            self.normalize_evidence(
                {
                    "account_settings": meeting_data["account_settings"],
                    "user_settings_sample": meeting_data["user_settings_sample"],
                    "password_required": meeting_data["account_settings"].get(
                        "require_password_for_scheduling_new_meetings", False
                    ),
                    "waiting_room_enabled": meeting_data["account_settings"].get(
                        "waiting_room", False
                    ),
                },
                "meeting_security",
                {"source": "zoom_meeting_settings"},
            )
        ]

    def _collect_recording_settings(self) -> list[Evidence]:
        """
        Collect recording and data protection settings.

        Returns:
            List of Evidence items with data protection configuration.
        """
        recording_data = {}

        # Get account-level recording settings
        try:
            data, _ = self._api_request("GET", "/accounts/me/settings")
            recording = data.get("recording", {})
            recording_data = {
                "local_recording": recording.get("local_recording"),
                "cloud_recording": recording.get("cloud_recording"),
                "auto_recording": recording.get("auto_recording"),
                "auto_delete_cmr": recording.get("auto_delete_cmr"),
                "auto_delete_cmr_days": recording.get("auto_delete_cmr_days"),
                "record_speaker_view": recording.get("record_speaker_view"),
                "record_gallery_view": recording.get("record_gallery_view"),
                "record_audio_file": recording.get("record_audio_file"),
                "save_chat_text": recording.get("save_chat_text"),
                "show_timestamp": recording.get("show_timestamp"),
                "recording_audio_transcript": recording.get("recording_audio_transcript"),
                "ip_address_access_control": recording.get("ip_address_access_control", {}),
                "recording_password_requirement": recording.get(
                    "recording_password_requirement", {}
                ),
            }
        except Exception as e:
            self.logger.warning(f"Failed to get recording settings: {e}")

        return [
            self.normalize_evidence(
                {
                    "recording_settings": recording_data,
                    "cloud_recording_enabled": recording_data.get("cloud_recording", False),
                    "auto_delete_enabled": recording_data.get("auto_delete_cmr", False),
                    "auto_delete_days": recording_data.get("auto_delete_cmr_days"),
                },
                "data_protection",
                {"source": "zoom_recording_settings"},
            )
        ]

    def _collect_security_settings(self) -> list[Evidence]:
        """
        Collect account-level security settings.

        Returns:
            List of Evidence items with security configuration.
        """
        security_data = {}

        # Get security settings
        try:
            data, _ = self._api_request("GET", "/accounts/me/settings")
            security = data.get("security", {})
            security_data = {
                "password_requirement": security.get("password_requirement", {}),
                "sign_in_with_two_factor_auth": security.get("sign_in_with_two_factor_auth"),
                "sign_in_with_two_factor_auth_roles": security.get(
                    "sign_in_with_two_factor_auth_roles", []
                ),
                "admin_change_name_pic": security.get("admin_change_name_pic"),
                "admin_change_user_info": security.get("admin_change_user_info"),
                "import_photos_from_devices": security.get("import_photos_from_devices"),
                "hide_billing_info": security.get("hide_billing_info"),
                "embed_password_in_join_link": security.get("embed_password_in_join_link"),
            }

            # Get authentication settings
            auth = data.get("authentication_option", {})
            security_data["authentication"] = {
                "meeting_authentication": auth.get("meeting_authentication"),
                "recording_authentication": auth.get("recording_authentication"),
            }
        except Exception as e:
            self.logger.warning(f"Failed to get security settings: {e}")

        return [
            self.normalize_evidence(
                {
                    "security_settings": security_data,
                    "two_factor_auth_required": security_data.get(
                        "sign_in_with_two_factor_auth", False
                    ),
                },
                "security_config",
                {"source": "zoom_security_settings"},
            )
        ]

    def _collect_activity_logs(self) -> list[Evidence]:
        """
        Collect user activity and sign-in logs.

        Returns:
            List of Evidence items with access logs.
        """
        # Get activity from last 30 days
        end_date = datetime.now(UTC)
        start_date = end_date - timedelta(days=30)

        activity_data = []

        # Get sign-in/sign-out activities
        try:
            data, _ = self._api_request(
                "GET",
                "/report/activities",
                {
                    "from": start_date.strftime("%Y-%m-%d"),
                    "to": end_date.strftime("%Y-%m-%d"),
                    "page_size": 300,
                },
            )
            activities = data.get("activity_logs", [])

            for activity in activities:
                activity_data.append(
                    {
                        "email": activity.get("email"),
                        "time": activity.get("time"),
                        "type": activity.get("type"),
                        "ip_address": activity.get("ip_address"),
                        "client_type": activity.get("client_type"),
                        "version": activity.get("version"),
                    }
                )
        except Exception as e:
            self.logger.warning(f"Failed to get activity logs: {e}")

        # Activity type breakdown
        type_counts: dict[str, int] = {}
        for activity in activity_data:
            t = activity.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "activities": activity_data,
                    "total_activities": len(activity_data),
                    "activity_type_counts": type_counts,
                    "date_range_days": 30,
                },
                "access_logs",
                {"source": "zoom_activity_logs"},
            )
        ]
