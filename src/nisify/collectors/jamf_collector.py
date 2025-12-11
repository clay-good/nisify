"""
Jamf Pro collector for Nisify.

Collects security evidence from Jamf Pro including computer inventory,
FileVault status, macOS Security Compliance, software inventory, and
configuration profiles. All API calls are read-only.

Required Jamf Permissions:
    - Read access to Computers
    - Read access to Computer Extension Attributes
    - Read access to Configuration Profiles
    - Read access to Computer Inventory Collection

Authentication:
    Credentials are retrieved from the credential store with keys:
    - jamf_url: Your Jamf Pro URL (e.g., "https://your-org.jamfcloud.com")
    - jamf_client_id: API client ID (for OAuth)
    - jamf_client_secret: API client secret (for OAuth)

    API clients are created in Jamf Pro under:
    Settings > System > API Roles and Clients

API Notes:
    This collector uses both the Classic API and the Jamf Pro API (JPAPI):
    - Classic API: /JSSResource/* endpoints (XML or JSON)
    - Jamf Pro API: /api/* endpoints (JSON only)

    Token refresh is handled automatically when using OAuth authentication.
"""

from __future__ import annotations

import json
import re
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
class JamfCollector(BaseCollector):
    """
    Jamf Pro evidence collector.

    Collects security-relevant evidence from Jamf Pro:
        - Computer inventory (device_inventory)
        - FileVault encryption status (encryption_status)
        - macOS Security Compliance (endpoint_compliance)
        - Software inventory (software_inventory)
        - Configuration profiles (security_configurations)

    Evidence Types Collected:
        - device_inventory: All managed computers with OS versions, last check-in
        - encryption_status: FileVault status and recovery key escrow
        - endpoint_compliance: mSCP baseline compliance results from Extension Attributes
        - software_inventory: Installed applications per device
        - security_configurations: Deployed configuration profiles and compliance

    mSCP Compliance Parsing:
        The macOS Security Compliance Project (mSCP) provides a standard way to
        measure compliance against security baselines. This collector parses
        compliance Extension Attribute values that follow the mSCP format.

    Example:
        collector = JamfCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "jamf"
    default_rate_limit_delay = 0.2

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the Jamf collector.

        Args:
            config: Settings object containing Jamf configuration.
            credential_store: Credential store for retrieving Jamf credentials.
        """
        super().__init__(config, credential_store)
        self._base_url: str | None = None
        self._access_token: str | None = None
        self._token_expires: float = 0
        self._session: requests.Session | None = None

    def _get_session(self) -> requests.Session:
        """
        Get or create a requests session.

        Returns:
            Configured requests.Session.
        """
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def _get_base_url(self) -> str:
        """
        Get the Jamf Pro base URL.

        Returns:
            Base URL string.

        Raises:
            AuthenticationError: If URL is not configured.
        """
        if self._base_url is not None:
            return self._base_url

        url = self.get_credential("jamf_url")
        url = url.strip()
        if url.endswith("/"):
            url = url[:-1]
        if not url.startswith("https://"):
            if url.startswith("http://"):
                url = "https://" + url[7:]
            else:
                url = "https://" + url

        self._base_url = url
        return self._base_url

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

        base_url = self._get_base_url()
        client_id = self.get_credential("jamf_client_id")
        client_secret = self.get_credential("jamf_client_secret")

        session = self._get_session()
        token_url = f"{base_url}/api/oauth/token"

        try:
            self._rate_limit()
            response = session.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            self._log_api_call("POST", "/api/oauth/token", response.status_code)

            if response.status_code == 401:
                raise AuthenticationError(
                    "Jamf authentication failed. Check client credentials.",
                    platform=self.platform,
                )

            response.raise_for_status()
            data = response.json()

            self._access_token = data["access_token"]
            # Token typically expires in 30 minutes
            expires_in = data.get("expires_in", 1800)
            self._token_expires = time.time() + expires_in

            self.logger.debug(f"Jamf token obtained, expires in {expires_in}s")
            return self._access_token

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Jamf: {e}",
                platform=self.platform,
            )

    def _api_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        use_classic_api: bool = False,
    ) -> Any:
        """
        Make an authenticated API request to Jamf.

        Args:
            method: HTTP method.
            endpoint: API endpoint path.
            params: Query parameters.
            use_classic_api: If True, use Classic API format.

        Returns:
            Response JSON data.

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limit is exceeded.
            CollectorConnectionError: If connection fails.
        """
        base_url = self._get_base_url()
        token = self._get_access_token()
        session = self._get_session()

        url = f"{base_url}{endpoint}"
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
            self._log_api_call(method, endpoint, response.status_code, duration_ms)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Jamf rate limit exceeded",
                    platform=self.platform,
                    retry_after=float(retry_after) if retry_after else None,
                )

            if response.status_code == 401:
                # Token might have expired, clear it and retry once
                self._access_token = None
                raise AuthenticationError(
                    "Jamf authentication failed",
                    platform=self.platform,
                )

            if response.status_code == 403:
                raise AuthenticationError(
                    "Jamf permission denied. Check API client privileges.",
                    platform=self.platform,
                )

            response.raise_for_status()

            if response.text:
                return response.json()
            return {}

        except requests.exceptions.ConnectionError as e:
            raise CollectorConnectionError(
                f"Failed to connect to Jamf: {e}",
                platform=self.platform,
            )
        except requests.exceptions.Timeout as e:
            raise CollectorConnectionError(
                f"Jamf request timed out: {e}",
                platform=self.platform,
            )

    def _paginate_jpapi(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "results",
    ) -> list[Any]:
        """
        Paginate through a Jamf Pro API (JPAPI) endpoint.

        JPAPI uses page/page-size parameters for pagination.

        Args:
            endpoint: API endpoint path.
            params: Initial query parameters.
            results_key: Key in response containing results list.

        Returns:
            List of all items from all pages.
        """
        all_items: list[Any] = []
        params = params or {}
        page = 0
        page_size = 100

        while True:
            params["page"] = page
            params["page-size"] = page_size

            data = self._api_request("GET", endpoint, params)

            items = data.get(results_key, [])
            all_items.extend(items)

            total_count = data.get("totalCount", len(items))
            if len(all_items) >= total_count or len(items) < page_size:
                break

            page += 1

        return all_items

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of permissions required for this collector.

        Returns:
            List of Jamf permission strings.
        """
        return [
            "Read Computers",
            "Read Computer Extension Attributes",
            "Read macOS Configuration Profiles",
            "Read Computer Inventory Collection",
            "Read Computer Hardware/Software Reports",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to Jamf Pro.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            # Test by getting Jamf Pro version
            data = self._api_request("GET", "/api/v1/jamf-pro-version")
            version = data.get("version", "unknown")
            self.logger.info(f"Jamf Pro connection successful. Version: {version}")
            return True
        except Exception as e:
            self.logger.error(f"Jamf connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from Jamf Pro.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        collectors = [
            ("device_inventory", self._collect_computer_inventory),
            ("encryption_status", self._collect_filevault_status),
            ("endpoint_compliance", self._collect_compliance_status),
            ("software_inventory", self._collect_software_inventory),
            ("security_configurations", self._collect_configuration_profiles),
            ("hardware_lifecycle", self._collect_hardware_lifecycle),
            ("maintenance_records", self._collect_maintenance_records),
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

    def _collect_computer_inventory(self) -> list[Evidence]:
        """
        Collect computer inventory.

        Returns:
            List of Evidence items with device inventory.
        """
        computers = self._paginate_jpapi("/api/v1/computers-inventory")

        device_data = []
        for computer in computers:
            general = computer.get("general", {})
            hardware = computer.get("hardware", {})
            os_info = computer.get("operatingSystem", {})

            device_data.append(
                {
                    "id": computer.get("id"),
                    "name": general.get("name"),
                    "serial_number": hardware.get("serialNumber"),
                    "udid": general.get("udid"),
                    "managed": general.get("remoteManagement", {}).get("managed"),
                    "supervised": general.get("supervised"),
                    "last_contact": general.get("lastContactTime"),
                    "last_enrolled": general.get("lastEnrolledDate"),
                    "os_name": os_info.get("name"),
                    "os_version": os_info.get("version"),
                    "os_build": os_info.get("build"),
                    "model": hardware.get("model"),
                    "model_identifier": hardware.get("modelIdentifier"),
                    "processor_type": hardware.get("processorType"),
                    "total_ram_mb": hardware.get("totalRamMegabytes"),
                    "sip_status": hardware.get("sipStatus"),
                }
            )

        # Calculate summary
        total_devices = len(device_data)
        managed_count = sum(1 for d in device_data if d.get("managed"))

        # Group by OS version
        os_versions: dict[str, int] = {}
        for d in device_data:
            os_ver = d.get("os_version", "unknown")
            os_versions[os_ver] = os_versions.get(os_ver, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "devices": device_data,
                    "total_devices": total_devices,
                    "managed_count": managed_count,
                    "unmanaged_count": total_devices - managed_count,
                    "os_version_distribution": os_versions,
                },
                "device_inventory",
                {"source": "jamf_computer_inventory"},
            )
        ]

    def _collect_filevault_status(self) -> list[Evidence]:
        """
        Collect FileVault encryption status for all computers.

        Returns:
            List of Evidence items with encryption status.
        """
        # Get computers with disk encryption info
        computers = self._paginate_jpapi(
            "/api/v1/computers-inventory",
            {"section": "DISK_ENCRYPTION"},
        )

        encryption_data = []
        for computer in computers:
            general = computer.get("general", {})
            disk_encryption = computer.get("diskEncryption", {})

            # Get boot partition encryption status
            boot_encrypted = False
            individual_recovery_key_valid = False
            institutional_recovery_key_present = False

            if disk_encryption:
                boot_encrypted = disk_encryption.get("bootPartitionEncryptionDetails", {}).get(
                    "partitionFileVault2State"
                ) == "ENCRYPTED"
                individual_recovery_key_valid = disk_encryption.get(
                    "individualRecoveryKeyValidityStatus"
                ) == "VALID"
                institutional_recovery_key_present = disk_encryption.get(
                    "institutionalRecoveryKeyPresent", False
                )

            encryption_data.append(
                {
                    "computer_id": computer.get("id"),
                    "computer_name": general.get("name"),
                    "serial_number": computer.get("hardware", {}).get("serialNumber"),
                    "filevault_enabled": boot_encrypted,
                    "recovery_key_valid": individual_recovery_key_valid,
                    "institutional_key_present": institutional_recovery_key_present,
                    "filevault_status": disk_encryption.get(
                        "bootPartitionEncryptionDetails", {}
                    ).get("partitionFileVault2State"),
                }
            )

        # Calculate summary
        total_devices = len(encryption_data)
        encrypted_count = sum(1 for d in encryption_data if d.get("filevault_enabled"))
        key_escrowed_count = sum(
            1 for d in encryption_data if d.get("recovery_key_valid")
        )

        return [
            self.normalize_evidence(
                {
                    "devices": encryption_data,
                    "total_devices": total_devices,
                    "encrypted_count": encrypted_count,
                    "unencrypted_count": total_devices - encrypted_count,
                    "recovery_key_escrowed_count": key_escrowed_count,
                    "encryption_percent": (
                        (encrypted_count / total_devices * 100)
                        if total_devices > 0
                        else 0
                    ),
                },
                "encryption_status",
                {"source": "jamf_disk_encryption"},
            )
        ]

    def _collect_compliance_status(self) -> list[Evidence]:
        """
        Collect macOS Security Compliance Project (mSCP) compliance status.

        This parses Extension Attribute values that contain mSCP compliance results.
        The mSCP format typically includes pass/fail counts and individual control results.

        Returns:
            List of Evidence items with endpoint compliance.
        """
        # First, get Extension Attributes to find compliance-related ones
        try:
            ea_response = self._api_request(
                "GET", "/api/v1/computer-extension-attributes"
            )
            extension_attributes = ea_response.get("results", [])
        except Exception as e:
            self.logger.warning(f"Failed to get Extension Attributes: {e}")
            extension_attributes = []

        # Look for compliance-related EAs (mSCP compliance EA names vary)
        compliance_ea_ids = []
        compliance_ea_names: dict[str, str] = {}
        compliance_keywords = [
            "compliance",
            "mscp",
            "cis",
            "stig",
            "security",
            "baseline",
        ]

        for ea in extension_attributes:
            ea_name = ea.get("name", "").lower()
            if any(kw in ea_name for kw in compliance_keywords):
                ea_id = ea.get("id")
                compliance_ea_ids.append(ea_id)
                compliance_ea_names[str(ea_id)] = ea.get("name")

        if not compliance_ea_ids:
            self.logger.info("No compliance Extension Attributes found")
            return [
                self.normalize_evidence(
                    {
                        "devices": [],
                        "total_devices": 0,
                        "message": "No compliance Extension Attributes configured",
                    },
                    "endpoint_compliance",
                    {"source": "jamf_extension_attributes"},
                )
            ]

        # Get computers with Extension Attributes
        computers = self._paginate_jpapi(
            "/api/v1/computers-inventory",
            {"section": "EXTENSION_ATTRIBUTES"},
        )

        compliance_data = []
        for computer in computers:
            general = computer.get("general", {})
            ext_attrs = computer.get("extensionAttributes", [])

            device_compliance: dict[str, Any] = {
                "computer_id": computer.get("id"),
                "computer_name": general.get("name"),
                "serial_number": computer.get("hardware", {}).get("serialNumber"),
                "compliance_results": {},
            }

            for ea in ext_attrs:
                ea_id = str(ea.get("definitionId"))
                if ea_id in compliance_ea_names:
                    ea_name = compliance_ea_names[ea_id]
                    ea_value = ea.get("values", [])
                    if ea_value:
                        value = ea_value[0] if isinstance(ea_value, list) else ea_value
                        parsed = self._parse_mscp_compliance(value)
                        device_compliance["compliance_results"][ea_name] = parsed

            if device_compliance["compliance_results"]:
                compliance_data.append(device_compliance)

        # Calculate overall compliance
        total_devices = len(compliance_data)
        compliant_count = 0
        for device in compliance_data:
            all_passing = True
            for result in device["compliance_results"].values():
                if isinstance(result, dict) and result.get("failed_count", 0) > 0:
                    all_passing = False
                    break
            if all_passing:
                compliant_count += 1

        return [
            self.normalize_evidence(
                {
                    "devices": compliance_data,
                    "total_devices": total_devices,
                    "fully_compliant_count": compliant_count,
                    "non_compliant_count": total_devices - compliant_count,
                    "compliance_ea_names": list(compliance_ea_names.values()),
                },
                "endpoint_compliance",
                {"source": "jamf_extension_attributes", "parsing": "mscp_format"},
            )
        ]

    def _parse_mscp_compliance(self, value: Any) -> dict[str, Any]:
        """
        Parse mSCP compliance Extension Attribute value.

        mSCP compliance results can be in various formats:
        - JSON: {"passed": 50, "failed": 5, "controls": {...}}
        - Plain text: "Passed: 50, Failed: 5"
        - XML-like format

        Args:
            value: The Extension Attribute value to parse.

        Returns:
            Parsed compliance data dictionary.
        """
        if not value:
            return {"raw_value": None, "parsed": False}

        # Handle string values
        if isinstance(value, str):
            value_str = value.strip()

            # Try JSON parsing first
            if value_str.startswith("{") or value_str.startswith("["):
                try:
                    return {
                        "raw_value": value_str,
                        "parsed": True,
                        "data": json.loads(value_str),
                    }
                except json.JSONDecodeError:
                    pass

            # Try to parse "Passed: X, Failed: Y" format
            passed_match = re.search(r"pass(?:ed)?[:\s]+(\d+)", value_str, re.IGNORECASE)
            failed_match = re.search(r"fail(?:ed)?[:\s]+(\d+)", value_str, re.IGNORECASE)

            if passed_match or failed_match:
                passed = int(passed_match.group(1)) if passed_match else 0
                failed = int(failed_match.group(1)) if failed_match else 0
                return {
                    "raw_value": value_str,
                    "parsed": True,
                    "passed_count": passed,
                    "failed_count": failed,
                    "total_count": passed + failed,
                    "compliance_percent": (
                        (passed / (passed + failed) * 100)
                        if (passed + failed) > 0
                        else 0
                    ),
                }

            # Try simple pass/fail status
            value_lower = value_str.lower()
            if value_lower in ["pass", "passed", "compliant", "true", "yes"]:
                return {
                    "raw_value": value_str,
                    "parsed": True,
                    "compliant": True,
                    "failed_count": 0,
                }
            if value_lower in ["fail", "failed", "non-compliant", "false", "no"]:
                return {
                    "raw_value": value_str,
                    "parsed": True,
                    "compliant": False,
                    "failed_count": 1,
                }

        # Return unparsed
        return {
            "raw_value": str(value) if value else None,
            "parsed": False,
        }

    def _collect_software_inventory(self) -> list[Evidence]:
        """
        Collect software inventory for all computers.

        Returns:
            List of Evidence items with software inventory.
        """
        computers = self._paginate_jpapi(
            "/api/v1/computers-inventory",
            {"section": "APPLICATIONS"},
        )

        software_data = []
        all_applications: dict[str, int] = {}

        for computer in computers:
            general = computer.get("general", {})
            applications = computer.get("applications", [])

            device_apps = []
            for app in applications:
                app_name = app.get("name", "")
                app_version = app.get("version", "")

                device_apps.append(
                    {
                        "name": app_name,
                        "version": app_version,
                        "path": app.get("path"),
                        "bundle_id": app.get("bundleId"),
                    }
                )

                # Track global app counts
                app_key = f"{app_name} ({app_version})"
                all_applications[app_key] = all_applications.get(app_key, 0) + 1

            software_data.append(
                {
                    "computer_id": computer.get("id"),
                    "computer_name": general.get("name"),
                    "serial_number": computer.get("hardware", {}).get("serialNumber"),
                    "application_count": len(device_apps),
                    "applications": device_apps[:100],  # Limit per device
                }
            )

        # Get top installed applications
        top_apps = sorted(
            all_applications.items(), key=lambda x: x[1], reverse=True
        )[:50]

        return [
            self.normalize_evidence(
                {
                    "devices": software_data,
                    "total_devices": len(software_data),
                    "unique_applications": len(all_applications),
                    "top_applications": [
                        {"name": name, "install_count": count}
                        for name, count in top_apps
                    ],
                },
                "software_inventory",
                {"source": "jamf_applications"},
            )
        ]

    def _collect_configuration_profiles(self) -> list[Evidence]:
        """
        Collect configuration profile information.

        Returns:
            List of Evidence items with security configurations.
        """
        # Get all configuration profiles
        try:
            profiles_response = self._api_request(
                "GET", "/api/v1/configuration-profiles"
            )
            profiles = profiles_response.get("results", [])
        except Exception as e:
            self.logger.warning(f"Failed to get configuration profiles: {e}")
            profiles = []

        profile_data = []
        for profile in profiles:
            profile_data.append(
                {
                    "id": profile.get("id"),
                    "name": profile.get("name"),
                    "description": profile.get("description"),
                    "level": profile.get("level"),
                    "distribution_method": profile.get("distributionMethod"),
                    "user_removable": profile.get("userRemovable"),
                    "redeploy_on_update": profile.get("redeployOnUpdate"),
                }
            )

        # Get profile deployment status per computer
        computers = self._paginate_jpapi(
            "/api/v1/computers-inventory",
            {"section": "CONFIGURATION_PROFILES"},
        )

        deployment_data = []
        for computer in computers:
            general = computer.get("general", {})
            config_profiles = computer.get("configurationProfiles", [])

            deployment_data.append(
                {
                    "computer_id": computer.get("id"),
                    "computer_name": general.get("name"),
                    "profile_count": len(config_profiles),
                    "profiles": [
                        {
                            "id": p.get("id"),
                            "name": p.get("displayName"),
                            "last_installed": p.get("lastInstalled"),
                        }
                        for p in config_profiles
                    ],
                }
            )

        return [
            self.normalize_evidence(
                {
                    "profiles": profile_data,
                    "total_profiles": len(profile_data),
                    "deployment_status": deployment_data,
                    "total_devices": len(deployment_data),
                },
                "security_configurations",
                {"source": "jamf_configuration_profiles"},
            )
        ]

    def _collect_hardware_lifecycle(self) -> list[Evidence]:
        """
        Collect hardware lifecycle information including purchase date, warranty status.

        Returns:
            List of Evidence items with hardware lifecycle data.
        """
        # Get computers with purchasing info
        computers = self._paginate_jpapi(
            "/api/v1/computers-inventory",
            {"section": "PURCHASING"},
        )

        lifecycle_data = []
        for computer in computers:
            general = computer.get("general", {})
            hardware = computer.get("hardware", {})
            purchasing = computer.get("purchasing", {})

            # Calculate warranty status if we have purchase date and warranty period
            warranty_expires = purchasing.get("warrantyExpires")
            warranty_status = "unknown"
            if warranty_expires:
                try:
                    expiry_date = datetime.fromisoformat(
                        warranty_expires.replace("Z", "+00:00")
                    )
                    if expiry_date > datetime.now(UTC):
                        warranty_status = "active"
                    else:
                        warranty_status = "expired"
                except (ValueError, TypeError):
                    pass

            lifecycle_data.append(
                {
                    "computer_id": computer.get("id"),
                    "computer_name": general.get("name"),
                    "serial_number": hardware.get("serialNumber"),
                    "model": hardware.get("model"),
                    "model_identifier": hardware.get("modelIdentifier"),
                    "purchase_date": purchasing.get("poDate"),
                    "purchase_price": purchasing.get("purchasePrice"),
                    "warranty_expires": warranty_expires,
                    "warranty_status": warranty_status,
                    "lease_expires": purchasing.get("leaseExpires"),
                    "po_number": purchasing.get("poNumber"),
                    "vendor": purchasing.get("vendor"),
                    "life_expectancy_years": purchasing.get("lifeExpectancy"),
                    "purchasing_account": purchasing.get("purchasingAccount"),
                    "asset_tag": general.get("assetTag"),
                }
            )

        # Calculate summary statistics
        total_devices = len(lifecycle_data)
        warranty_active = sum(
            1 for d in lifecycle_data if d.get("warranty_status") == "active"
        )
        warranty_expired = sum(
            1 for d in lifecycle_data if d.get("warranty_status") == "expired"
        )

        # Group by model for refresh planning
        model_counts: dict[str, int] = {}
        for d in lifecycle_data:
            model = d.get("model", "Unknown")
            model_counts[model] = model_counts.get(model, 0) + 1

        return [
            self.normalize_evidence(
                {
                    "devices": lifecycle_data,
                    "total_devices": total_devices,
                    "warranty_active_count": warranty_active,
                    "warranty_expired_count": warranty_expired,
                    "warranty_unknown_count": total_devices - warranty_active - warranty_expired,
                    "model_distribution": model_counts,
                },
                "hardware_lifecycle",
                {"source": "jamf_purchasing_info"},
            )
        ]

    def _collect_maintenance_records(self) -> list[Evidence]:
        """
        Collect maintenance/management history from computer history.

        Returns:
            List of Evidence items with maintenance records.
        """
        # Get all computers first
        computers = self._paginate_jpapi("/api/v1/computers-inventory")

        maintenance_data = []
        for computer in computers[:100]:  # Limit to avoid too many API calls
            computer_id = computer.get("id")
            general = computer.get("general", {})

            # Get computer history (management commands, policy runs, etc.)
            try:
                history = self._api_request(
                    "GET", f"/api/v1/computers-inventory/{computer_id}/history"
                )
                history_results = history.get("results", [])
            except Exception:
                history_results = []

            # Get management commands history
            mgmt_commands = []
            policy_runs = []
            for event in history_results:
                event_type = event.get("objectType")
                if event_type == "ManagementCommand":
                    mgmt_commands.append(
                        {
                            "command": event.get("details", {}).get("commandType"),
                            "status": event.get("details", {}).get("status"),
                            "timestamp": event.get("timestamp"),
                        }
                    )
                elif event_type == "PolicyRun":
                    policy_runs.append(
                        {
                            "policy_name": event.get("details", {}).get("policyName"),
                            "status": event.get("details", {}).get("status"),
                            "timestamp": event.get("timestamp"),
                        }
                    )

            maintenance_data.append(
                {
                    "computer_id": computer_id,
                    "computer_name": general.get("name"),
                    "serial_number": computer.get("hardware", {}).get("serialNumber"),
                    "last_contact": general.get("lastContactTime"),
                    "last_enrolled": general.get("lastEnrolledDate"),
                    "mdm_capable": general.get("mdmCapable", {}).get("capable"),
                    "recent_management_commands": mgmt_commands[:20],
                    "recent_policy_runs": policy_runs[:20],
                    "total_management_commands": len(mgmt_commands),
                    "total_policy_runs": len(policy_runs),
                }
            )

        # Calculate summary
        total_devices = len(maintenance_data)
        mdm_capable_count = sum(
            1 for d in maintenance_data if d.get("mdm_capable")
        )
        total_commands = sum(
            d.get("total_management_commands", 0) for d in maintenance_data
        )
        total_policies = sum(
            d.get("total_policy_runs", 0) for d in maintenance_data
        )

        return [
            self.normalize_evidence(
                {
                    "devices": maintenance_data,
                    "total_devices": total_devices,
                    "mdm_capable_count": mdm_capable_count,
                    "total_management_commands": total_commands,
                    "total_policy_runs": total_policies,
                },
                "maintenance_records",
                {"source": "jamf_computer_history"},
            )
        ]
