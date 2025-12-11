"""
AWS collector for Nisify.

Collects security evidence from AWS services including Security Hub, IAM,
CloudTrail, AWS Config, and S3. All API calls are read-only.

Required IAM Permissions:
    - securityhub:GetFindings
    - iam:GetAccountPasswordPolicy
    - iam:ListUsers
    - iam:ListMFADevices
    - iam:ListAccessKeys
    - iam:GetAccessKeyLastUsed
    - cloudtrail:DescribeTrails
    - cloudtrail:GetTrailStatus
    - config:DescribeComplianceByConfigRule
    - config:DescribeConfigRules
    - s3:ListBuckets
    - s3:GetBucketEncryption
    - s3:GetBucketPublicAccessBlock
    - s3:GetBucketVersioning

Authentication:
    Credentials are retrieved from the credential store with keys:
    - aws_access_key_id
    - aws_secret_access_key
    - aws_session_token (optional, for temporary credentials)

    Alternatively, boto3 will use the default credential chain
    (environment variables, ~/.aws/credentials, IAM role, etc.)
    if credentials are not found in the credential store.

Multi-Region Support:
    The collector iterates through all configured regions and aggregates
    findings. Configure regions in settings.yaml under aws.regions.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from nisify.collectors.base import (
    AuthenticationError,
    BaseCollector,
    CollectionResult,
    CollectorConnectionError,
    CollectorRegistry,
    Evidence,
)

if TYPE_CHECKING:
    from nisify.config.credentials import CredentialStore
    from nisify.config.settings import Settings

# boto3 is imported lazily to allow the module to load even if boto3 is not installed


@CollectorRegistry.register
class AwsCollector(BaseCollector):
    """
    AWS evidence collector.

    Collects security-relevant evidence from AWS services:
        - Security Hub findings (security_findings)
        - IAM password policy (password_policy)
        - IAM MFA status (mfa_status)
        - IAM access keys (access_keys)
        - CloudTrail configuration (audit_logging)
        - AWS Config compliance (config_compliance)
        - S3 bucket security (data_protection)

    Evidence Types Collected:
        - security_findings: Security Hub findings with severity and compliance status
        - password_policy: IAM password policy configuration
        - mfa_status: MFA enrollment status for all IAM users
        - access_keys: Access key age and rotation status
        - audit_logging: CloudTrail configuration and status
        - config_compliance: AWS Config rule compliance status
        - data_protection: S3 bucket encryption, public access, versioning

    Example:
        collector = AwsCollector(config, credential_store)
        if collector.test_connection():
            result = collector.collect()
            for evidence in result.evidence_items:
                print(f"{evidence.evidence_type}: {len(evidence.raw_data)} items")
    """

    platform = "aws"
    default_rate_limit_delay = 0.2  # AWS has generous rate limits

    def __init__(
        self,
        config: Settings,
        credential_store: CredentialStore,
    ) -> None:
        """
        Initialize the AWS collector.

        Args:
            config: Settings object containing AWS configuration.
            credential_store: Credential store for retrieving AWS credentials.
        """
        super().__init__(config, credential_store)
        self._boto3: Any = None
        self._session: Any = None
        self._regions: list[str] = []

    def _get_boto3(self) -> Any:
        """Lazily import and return boto3."""
        if self._boto3 is None:
            try:
                import boto3

                self._boto3 = boto3
            except ImportError:
                raise CollectorConnectionError(
                    "boto3 is not installed. Install it with: pip install boto3",
                    platform=self.platform,
                )
        return self._boto3

    def _get_session(self) -> Any:
        """
        Get or create a boto3 session with credentials.

        Returns:
            boto3.Session object.

        Raises:
            AuthenticationError: If credentials are invalid.
        """
        if self._session is not None:
            return self._session

        boto3 = self._get_boto3()

        # Try to get credentials from credential store
        try:
            access_key = self.get_credential("aws_access_key_id")
            secret_key = self.get_credential("aws_secret_access_key")

            # Session token is optional
            try:
                session_token = self.get_credential("aws_session_token")
            except AuthenticationError:
                session_token = None

            self._session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
            )
        except AuthenticationError:
            # Fall back to default credential chain
            self.logger.info(
                "No AWS credentials in store, using default credential chain"
            )
            self._session = boto3.Session()

        return self._session

    def _get_client(self, service: str, region: str | None = None) -> Any:
        """
        Get a boto3 client for a service.

        Args:
            service: AWS service name (e.g., "iam", "s3").
            region: AWS region (uses default if not specified).

        Returns:
            boto3 service client.
        """
        session = self._get_session()
        return session.client(service, region_name=region)

    def _get_regions(self) -> list[str]:
        """
        Get the list of AWS regions to collect from.

        Returns:
            List of region names.
        """
        if self._regions:
            return self._regions

        # Get from config
        if hasattr(self.config, "aws") and hasattr(self.config.aws, "regions"):
            configured_regions = self.config.aws.regions
            if configured_regions:
                self._regions = configured_regions
                return self._regions

        # Default to us-east-1 only
        self._regions = ["us-east-1"]
        return self._regions

    def get_required_permissions(self) -> list[str]:
        """
        Get the list of IAM permissions required for this collector.

        Returns:
            List of IAM permission strings.
        """
        return [
            "securityhub:GetFindings",
            "securityhub:DescribeHub",
            "iam:GetAccountPasswordPolicy",
            "iam:ListUsers",
            "iam:ListMFADevices",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "config:DescribeComplianceByConfigRule",
            "config:DescribeConfigRules",
            "s3:ListBuckets",
            "s3:GetBucketEncryption",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketVersioning",
            "s3:GetBucketLocation",
            "cloudwatch:DescribeAlarms",
            "rds:DescribeDBInstances",
            "elasticloadbalancing:DescribeLoadBalancers",
            "autoscaling:DescribeAutoScalingGroups",
        ]

    def test_connection(self) -> bool:
        """
        Test connectivity to AWS.

        Attempts to call sts:GetCallerIdentity to verify credentials.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            sts = self._get_client("sts")
            self._rate_limit()
            identity = sts.get_caller_identity()
            self.logger.info(
                f"AWS connection successful. Account: {identity.get('Account')}, "
                f"ARN: {identity.get('Arn')}"
            )
            return True
        except Exception as e:
            self.logger.error(f"AWS connection test failed: {e}")
            return False

    def collect(self) -> CollectionResult:
        """
        Collect evidence from AWS.

        Gathers evidence from all configured services and regions.

        Returns:
            CollectionResult with all collected evidence.
        """
        start_time = time.time()
        evidence_items: list[Evidence] = []
        errors: list[str] = []
        collected_types: list[str] = []
        failed_types: list[str] = []

        # Define collection methods
        collectors = [
            ("security_findings", self._collect_security_hub_findings),
            ("password_policy", self._collect_password_policy),
            ("mfa_status", self._collect_mfa_status),
            ("access_keys", self._collect_access_keys),
            ("audit_logging", self._collect_cloudtrail),
            ("config_compliance", self._collect_config_compliance),
            ("data_protection", self._collect_s3_security),
            ("detection_rules", self._collect_cloudwatch_alarms),
            ("ha_config", self._collect_high_availability),
        ]

        for evidence_type, collector_func in collectors:
            try:
                self.logger.info(f"Collecting {evidence_type}...")
                items = collector_func()
                evidence_items.extend(items)
                collected_types.append(evidence_type)
                self.logger.info(
                    f"Collected {len(items)} items for {evidence_type}"
                )
            except AuthenticationError:
                # Auth errors are fatal
                raise
            except Exception as e:
                self.logger.error(f"Failed to collect {evidence_type}: {e}")
                errors.append(f"{evidence_type}: {str(e)}")
                failed_types.append(evidence_type)

        duration = time.time() - start_time

        # Determine success status
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

    def _collect_security_hub_findings(self) -> list[Evidence]:
        """
        Collect Security Hub findings.

        Returns:
            List of Evidence items with security findings.
        """
        all_findings: list[dict[str, Any]] = []

        for region in self._get_regions():
            try:
                client = self._get_client("securityhub", region)

                # Check if Security Hub is enabled
                try:
                    self._rate_limit()
                    client.describe_hub()
                except client.exceptions.InvalidAccessException:
                    self.logger.warning(
                        f"Security Hub not enabled in {region}, skipping"
                    )
                    continue

                # Get findings with pagination
                paginator = client.get_paginator("get_findings")
                filters = {
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
                }

                for page in paginator.paginate(Filters=filters):
                    self._rate_limit()
                    self._log_api_call("GET", f"securityhub:GetFindings ({region})")
                    findings = page.get("Findings", [])
                    for finding in findings:
                        all_findings.append(
                            {
                                "id": finding.get("Id"),
                                "title": finding.get("Title"),
                                "description": finding.get("Description"),
                                "severity": finding.get("Severity", {}).get("Label"),
                                "compliance_status": finding.get("Compliance", {}).get(
                                    "Status"
                                ),
                                "resource_type": finding.get("Resources", [{}])[0].get(
                                    "Type"
                                ),
                                "resource_id": finding.get("Resources", [{}])[0].get(
                                    "Id"
                                ),
                                "region": region,
                                "created_at": finding.get("CreatedAt"),
                                "updated_at": finding.get("UpdatedAt"),
                                "product_name": finding.get("ProductName"),
                                "generator_id": finding.get("GeneratorId"),
                            }
                        )
            except Exception as e:
                self.logger.warning(
                    f"Failed to collect Security Hub findings from {region}: {e}"
                )

        if not all_findings:
            return []

        return [
            self.normalize_evidence(
                {"findings": all_findings, "total_count": len(all_findings)},
                "security_findings",
                {"source": "aws_security_hub", "regions": self._get_regions()},
            )
        ]

    def _collect_password_policy(self) -> list[Evidence]:
        """
        Collect IAM password policy.

        Returns:
            List of Evidence items with password policy.
        """
        iam = self._get_client("iam")

        try:
            self._rate_limit()
            self._log_api_call("GET", "iam:GetAccountPasswordPolicy")
            response = iam.get_account_password_policy()
            policy = response.get("PasswordPolicy", {})

            return [
                self.normalize_evidence(
                    {
                        "minimum_password_length": policy.get("MinimumPasswordLength"),
                        "require_symbols": policy.get("RequireSymbols"),
                        "require_numbers": policy.get("RequireNumbers"),
                        "require_uppercase": policy.get("RequireUppercaseCharacters"),
                        "require_lowercase": policy.get("RequireLowercaseCharacters"),
                        "allow_users_to_change": policy.get(
                            "AllowUsersToChangePassword"
                        ),
                        "max_password_age": policy.get("MaxPasswordAge"),
                        "password_reuse_prevention": policy.get(
                            "PasswordReusePrevention"
                        ),
                        "hard_expiry": policy.get("HardExpiry"),
                        "expire_passwords": policy.get("ExpirePasswords"),
                    },
                    "password_policy",
                    {"source": "aws_iam"},
                )
            ]
        except iam.exceptions.NoSuchEntityException:
            # No password policy set
            return [
                self.normalize_evidence(
                    {"policy_exists": False, "message": "No password policy configured"},
                    "password_policy",
                    {"source": "aws_iam"},
                )
            ]

    def _collect_mfa_status(self) -> list[Evidence]:
        """
        Collect MFA status for all IAM users.

        Returns:
            List of Evidence items with MFA status.
        """
        iam = self._get_client("iam")
        users_mfa: list[dict[str, Any]] = []

        # List all users with pagination
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            self._rate_limit()
            self._log_api_call("GET", "iam:ListUsers")

            for user in page.get("Users", []):
                username = user.get("UserName")

                # Get MFA devices for user
                self._rate_limit()
                self._log_api_call("GET", f"iam:ListMFADevices ({username})")
                mfa_response = iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get("MFADevices", [])

                users_mfa.append(
                    {
                        "username": username,
                        "user_id": user.get("UserId"),
                        "arn": user.get("Arn"),
                        "mfa_enabled": len(mfa_devices) > 0,
                        "mfa_device_count": len(mfa_devices),
                        "mfa_devices": [
                            {
                                "serial_number": d.get("SerialNumber"),
                                "enable_date": (
                                    d.get("EnableDate").isoformat()
                                    if d.get("EnableDate")
                                    else None
                                ),
                            }
                            for d in mfa_devices
                        ],
                        "created_at": (
                            user.get("CreateDate").isoformat()
                            if user.get("CreateDate")
                            else None
                        ),
                        "password_last_used": (
                            user.get("PasswordLastUsed").isoformat()
                            if user.get("PasswordLastUsed")
                            else None
                        ),
                    }
                )

        # Calculate summary
        total_users = len(users_mfa)
        mfa_enabled_count = sum(1 for u in users_mfa if u["mfa_enabled"])

        return [
            self.normalize_evidence(
                {
                    "users": users_mfa,
                    "total_users": total_users,
                    "mfa_enabled_count": mfa_enabled_count,
                    "mfa_disabled_count": total_users - mfa_enabled_count,
                    "mfa_coverage_percent": (
                        (mfa_enabled_count / total_users * 100) if total_users > 0 else 0
                    ),
                },
                "mfa_status",
                {"source": "aws_iam"},
            )
        ]

    def _collect_access_keys(self) -> list[Evidence]:
        """
        Collect access key information for all IAM users.

        Returns:
            List of Evidence items with access key status.
        """
        iam = self._get_client("iam")
        access_keys_data: list[dict[str, Any]] = []

        # List all users with pagination
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            self._rate_limit()
            self._log_api_call("GET", "iam:ListUsers")

            for user in page.get("Users", []):
                username = user.get("UserName")

                # List access keys for user
                self._rate_limit()
                self._log_api_call("GET", f"iam:ListAccessKeys ({username})")
                keys_response = iam.list_access_keys(UserName=username)

                for key in keys_response.get("AccessKeyMetadata", []):
                    access_key_id = key.get("AccessKeyId")

                    # Get last used info
                    self._rate_limit()
                    self._log_api_call(
                        "GET", f"iam:GetAccessKeyLastUsed ({access_key_id})"
                    )
                    last_used_response = iam.get_access_key_last_used(
                        AccessKeyId=access_key_id
                    )
                    last_used = last_used_response.get("AccessKeyLastUsed", {})

                    create_date = key.get("CreateDate")
                    age_days = None
                    if create_date:
                        age_days = (
                            datetime.now(UTC) - create_date.replace(tzinfo=UTC)
                        ).days

                    access_keys_data.append(
                        {
                            "username": username,
                            "access_key_id": access_key_id,
                            "status": key.get("Status"),
                            "created_at": (
                                create_date.isoformat() if create_date else None
                            ),
                            "age_days": age_days,
                            "last_used_date": (
                                last_used.get("LastUsedDate").isoformat()
                                if last_used.get("LastUsedDate")
                                else None
                            ),
                            "last_used_service": last_used.get("ServiceName"),
                            "last_used_region": last_used.get("Region"),
                        }
                    )

        # Calculate summary
        total_keys = len(access_keys_data)
        active_keys = sum(1 for k in access_keys_data if k["status"] == "Active")
        old_keys = sum(
            1 for k in access_keys_data if k["age_days"] and k["age_days"] > 90
        )

        return [
            self.normalize_evidence(
                {
                    "access_keys": access_keys_data,
                    "total_keys": total_keys,
                    "active_keys": active_keys,
                    "inactive_keys": total_keys - active_keys,
                    "keys_older_than_90_days": old_keys,
                },
                "access_keys",
                {"source": "aws_iam"},
            )
        ]

    def _collect_cloudtrail(self) -> list[Evidence]:
        """
        Collect CloudTrail configuration.

        Returns:
            List of Evidence items with CloudTrail status.
        """
        all_trails: list[dict[str, Any]] = []

        for region in self._get_regions():
            try:
                client = self._get_client("cloudtrail", region)

                self._rate_limit()
                self._log_api_call("GET", f"cloudtrail:DescribeTrails ({region})")
                response = client.describe_trails(includeShadowTrails=False)

                for trail in response.get("trailList", []):
                    trail_name = trail.get("Name")
                    trail_arn = trail.get("TrailARN")

                    # Get trail status
                    self._rate_limit()
                    self._log_api_call(
                        "GET", f"cloudtrail:GetTrailStatus ({trail_name})"
                    )
                    status_response = client.get_trail_status(Name=trail_arn)

                    all_trails.append(
                        {
                            "name": trail_name,
                            "arn": trail_arn,
                            "home_region": trail.get("HomeRegion"),
                            "is_multi_region": trail.get("IsMultiRegionTrail"),
                            "is_organization_trail": trail.get("IsOrganizationTrail"),
                            "s3_bucket": trail.get("S3BucketName"),
                            "log_file_validation_enabled": trail.get(
                                "LogFileValidationEnabled"
                            ),
                            "kms_key_id": trail.get("KMSKeyId"),
                            "has_custom_event_selectors": trail.get(
                                "HasCustomEventSelectors"
                            ),
                            "has_insight_selectors": trail.get("HasInsightSelectors"),
                            "is_logging": status_response.get("IsLogging"),
                            "latest_delivery_time": (
                                status_response.get("LatestDeliveryTime").isoformat()
                                if status_response.get("LatestDeliveryTime")
                                else None
                            ),
                            "latest_delivery_error": status_response.get(
                                "LatestDeliveryError"
                            ),
                            "region": region,
                        }
                    )
            except Exception as e:
                self.logger.warning(
                    f"Failed to collect CloudTrail from {region}: {e}"
                )

        # Calculate summary
        total_trails = len(all_trails)
        logging_enabled = sum(1 for t in all_trails if t["is_logging"])
        multi_region = sum(1 for t in all_trails if t["is_multi_region"])
        log_validation = sum(
            1 for t in all_trails if t["log_file_validation_enabled"]
        )

        return [
            self.normalize_evidence(
                {
                    "trails": all_trails,
                    "total_trails": total_trails,
                    "logging_enabled_count": logging_enabled,
                    "multi_region_count": multi_region,
                    "log_validation_enabled_count": log_validation,
                },
                "audit_logging",
                {"source": "aws_cloudtrail", "regions": self._get_regions()},
            )
        ]

    def _collect_config_compliance(self) -> list[Evidence]:
        """
        Collect AWS Config compliance status.

        Returns:
            List of Evidence items with Config compliance.
        """
        all_rules: list[dict[str, Any]] = []

        for region in self._get_regions():
            try:
                client = self._get_client("config", region)

                # Get all config rules
                self._rate_limit()
                self._log_api_call("GET", f"config:DescribeConfigRules ({region})")

                try:
                    rules_response = client.describe_config_rules()
                except client.exceptions.NoSuchConfigRuleException:
                    self.logger.warning(f"No Config rules in {region}")
                    continue

                rule_names = [
                    r.get("ConfigRuleName")
                    for r in rules_response.get("ConfigRules", [])
                ]

                if not rule_names:
                    continue

                # Get compliance for rules
                self._rate_limit()
                self._log_api_call(
                    "GET", f"config:DescribeComplianceByConfigRule ({region})"
                )
                compliance_response = client.describe_compliance_by_config_rule(
                    ConfigRuleNames=rule_names[:25]  # API limit
                )

                for compliance in compliance_response.get("ComplianceByConfigRules", []):
                    rule_name = compliance.get("ConfigRuleName")
                    rule_details: dict[str, Any] = next(
                        (
                            r
                            for r in rules_response.get("ConfigRules", [])
                            if r.get("ConfigRuleName") == rule_name
                        ),
                        {},
                    )

                    all_rules.append(
                        {
                            "rule_name": rule_name,
                            "rule_id": rule_details.get("ConfigRuleId"),
                            "rule_arn": rule_details.get("ConfigRuleArn"),
                            "compliance_type": compliance.get("Compliance", {}).get(
                                "ComplianceType"
                            ),
                            "source": rule_details.get("Source", {}).get("Owner"),
                            "source_identifier": rule_details.get("Source", {}).get(
                                "SourceIdentifier"
                            ),
                            "region": region,
                        }
                    )
            except Exception as e:
                self.logger.warning(f"Failed to collect Config rules from {region}: {e}")

        # Calculate summary
        total_rules = len(all_rules)
        compliant = sum(
            1 for r in all_rules if r["compliance_type"] == "COMPLIANT"
        )
        non_compliant = sum(
            1 for r in all_rules if r["compliance_type"] == "NON_COMPLIANT"
        )

        return [
            self.normalize_evidence(
                {
                    "rules": all_rules,
                    "total_rules": total_rules,
                    "compliant_count": compliant,
                    "non_compliant_count": non_compliant,
                    "compliance_percent": (
                        (compliant / total_rules * 100) if total_rules > 0 else 0
                    ),
                },
                "config_compliance",
                {"source": "aws_config", "regions": self._get_regions()},
            )
        ]

    def _collect_s3_security(self) -> list[Evidence]:
        """
        Collect S3 bucket security configuration.

        Returns:
            List of Evidence items with S3 security status.
        """
        s3 = self._get_client("s3")
        buckets_data: list[dict[str, Any]] = []

        # List all buckets
        self._rate_limit()
        self._log_api_call("GET", "s3:ListBuckets")
        response = s3.list_buckets()

        for bucket in response.get("Buckets", []):
            bucket_name = bucket.get("Name")
            bucket_info: dict[str, Any] = {
                "name": bucket_name,
                "created_at": (
                    bucket.get("CreationDate").isoformat()
                    if bucket.get("CreationDate")
                    else None
                ),
            }

            # Get bucket location
            try:
                self._rate_limit()
                self._log_api_call("GET", f"s3:GetBucketLocation ({bucket_name})")
                location = s3.get_bucket_location(Bucket=bucket_name)
                bucket_info["region"] = location.get("LocationConstraint") or "us-east-1"
            except Exception as e:
                bucket_info["region"] = "unknown"
                bucket_info["location_error"] = str(e)

            # Get encryption status
            try:
                self._rate_limit()
                self._log_api_call("GET", f"s3:GetBucketEncryption ({bucket_name})")
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                    "Rules", []
                )
                if rules:
                    sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    bucket_info["encryption_enabled"] = True
                    bucket_info["encryption_algorithm"] = sse.get("SSEAlgorithm")
                    bucket_info["kms_key_id"] = sse.get("KMSMasterKeyID")
                else:
                    bucket_info["encryption_enabled"] = False
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    bucket_info["encryption_enabled"] = False
                else:
                    bucket_info["encryption_error"] = str(e)

            # Get public access block
            try:
                self._rate_limit()
                self._log_api_call(
                    "GET", f"s3:GetBucketPublicAccessBlock ({bucket_name})"
                )
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access.get("PublicAccessBlockConfiguration", {})
                bucket_info["block_public_acls"] = config.get("BlockPublicAcls")
                bucket_info["ignore_public_acls"] = config.get("IgnorePublicAcls")
                bucket_info["block_public_policy"] = config.get("BlockPublicPolicy")
                bucket_info["restrict_public_buckets"] = config.get(
                    "RestrictPublicBuckets"
                )
                bucket_info["all_public_access_blocked"] = all(
                    [
                        config.get("BlockPublicAcls"),
                        config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("RestrictPublicBuckets"),
                    ]
                )
            except s3.exceptions.ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    bucket_info["all_public_access_blocked"] = False
                    bucket_info["block_public_acls"] = False
                    bucket_info["ignore_public_acls"] = False
                    bucket_info["block_public_policy"] = False
                    bucket_info["restrict_public_buckets"] = False
                else:
                    bucket_info["public_access_error"] = str(e)

            # Get versioning status
            try:
                self._rate_limit()
                self._log_api_call("GET", f"s3:GetBucketVersioning ({bucket_name})")
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                bucket_info["versioning_status"] = versioning.get("Status", "Disabled")
                bucket_info["mfa_delete"] = versioning.get("MFADelete", "Disabled")
            except Exception as e:
                bucket_info["versioning_error"] = str(e)

            buckets_data.append(bucket_info)

        # Calculate summary
        total_buckets = len(buckets_data)
        encrypted = sum(1 for b in buckets_data if b.get("encryption_enabled"))
        public_blocked = sum(
            1 for b in buckets_data if b.get("all_public_access_blocked")
        )
        versioned = sum(
            1 for b in buckets_data if b.get("versioning_status") == "Enabled"
        )

        return [
            self.normalize_evidence(
                {
                    "buckets": buckets_data,
                    "total_buckets": total_buckets,
                    "encrypted_count": encrypted,
                    "public_access_blocked_count": public_blocked,
                    "versioning_enabled_count": versioned,
                    "encryption_percent": (
                        (encrypted / total_buckets * 100) if total_buckets > 0 else 0
                    ),
                    "public_access_blocked_percent": (
                        (public_blocked / total_buckets * 100)
                        if total_buckets > 0
                        else 0
                    ),
                },
                "data_protection",
                {"source": "aws_s3"},
            )
        ]

    def _collect_cloudwatch_alarms(self) -> list[Evidence]:
        """
        Collect CloudWatch Alarms as detection rules.

        Returns:
            List of Evidence items with alarm configurations.
        """
        all_alarms: list[dict[str, Any]] = []

        for region in self._get_regions():
            try:
                client = self._get_client("cloudwatch", region)

                # Get all alarms with pagination
                paginator = client.get_paginator("describe_alarms")

                for page in paginator.paginate():
                    self._rate_limit()
                    self._log_api_call("GET", f"cloudwatch:DescribeAlarms ({region})")

                    for alarm in page.get("MetricAlarms", []):
                        all_alarms.append(
                            {
                                "name": alarm.get("AlarmName"),
                                "arn": alarm.get("AlarmArn"),
                                "description": alarm.get("AlarmDescription"),
                                "state": alarm.get("StateValue"),
                                "metric_name": alarm.get("MetricName"),
                                "namespace": alarm.get("Namespace"),
                                "statistic": alarm.get("Statistic"),
                                "period": alarm.get("Period"),
                                "evaluation_periods": alarm.get("EvaluationPeriods"),
                                "threshold": alarm.get("Threshold"),
                                "comparison_operator": alarm.get("ComparisonOperator"),
                                "actions_enabled": alarm.get("ActionsEnabled"),
                                "alarm_actions": alarm.get("AlarmActions", []),
                                "region": region,
                            }
                        )

                    # Also get composite alarms
                    for alarm in page.get("CompositeAlarms", []):
                        all_alarms.append(
                            {
                                "name": alarm.get("AlarmName"),
                                "arn": alarm.get("AlarmArn"),
                                "description": alarm.get("AlarmDescription"),
                                "state": alarm.get("StateValue"),
                                "type": "composite",
                                "alarm_rule": alarm.get("AlarmRule"),
                                "actions_enabled": alarm.get("ActionsEnabled"),
                                "alarm_actions": alarm.get("AlarmActions", []),
                                "region": region,
                            }
                        )
            except Exception as e:
                self.logger.warning(
                    f"Failed to collect CloudWatch alarms from {region}: {e}"
                )

        # Calculate summary
        total_alarms = len(all_alarms)
        active_alarms = sum(1 for a in all_alarms if a.get("state") == "ALARM")
        ok_alarms = sum(1 for a in all_alarms if a.get("state") == "OK")
        with_actions = sum(1 for a in all_alarms if a.get("actions_enabled"))

        return [
            self.normalize_evidence(
                {
                    "alarms": all_alarms,
                    "total_alarms": total_alarms,
                    "active_alarm_count": active_alarms,
                    "ok_count": ok_alarms,
                    "actions_enabled_count": with_actions,
                },
                "detection_rules",
                {"source": "aws_cloudwatch", "regions": self._get_regions()},
            )
        ]

    def _collect_high_availability(self) -> list[Evidence]:
        """
        Collect high availability configuration (RDS Multi-AZ, ELB, ASG).

        Returns:
            List of Evidence items with HA configuration.
        """
        ha_config: dict[str, Any] = {
            "rds_instances": [],
            "load_balancers": [],
            "auto_scaling_groups": [],
        }

        for region in self._get_regions():
            # Collect RDS Multi-AZ configuration
            try:
                rds = self._get_client("rds", region)
                self._rate_limit()
                self._log_api_call("GET", f"rds:DescribeDBInstances ({region})")
                response = rds.describe_db_instances()

                for instance in response.get("DBInstances", []):
                    ha_config["rds_instances"].append(
                        {
                            "identifier": instance.get("DBInstanceIdentifier"),
                            "engine": instance.get("Engine"),
                            "multi_az": instance.get("MultiAZ"),
                            "availability_zone": instance.get("AvailabilityZone"),
                            "storage_encrypted": instance.get("StorageEncrypted"),
                            "auto_minor_version_upgrade": instance.get(
                                "AutoMinorVersionUpgrade"
                            ),
                            "backup_retention_period": instance.get(
                                "BackupRetentionPeriod"
                            ),
                            "region": region,
                        }
                    )
            except Exception as e:
                self.logger.warning(f"Failed to collect RDS from {region}: {e}")

            # Collect ELB configuration
            try:
                elb = self._get_client("elbv2", region)
                self._rate_limit()
                self._log_api_call(
                    "GET", f"elasticloadbalancing:DescribeLoadBalancers ({region})"
                )
                response = elb.describe_load_balancers()

                for lb in response.get("LoadBalancers", []):
                    azs = lb.get("AvailabilityZones", [])
                    ha_config["load_balancers"].append(
                        {
                            "name": lb.get("LoadBalancerName"),
                            "arn": lb.get("LoadBalancerArn"),
                            "type": lb.get("Type"),
                            "scheme": lb.get("Scheme"),
                            "availability_zones": [az.get("ZoneName") for az in azs],
                            "az_count": len(azs),
                            "state": lb.get("State", {}).get("Code"),
                            "region": region,
                        }
                    )
            except Exception as e:
                self.logger.warning(f"Failed to collect ELB from {region}: {e}")

            # Collect Auto Scaling Groups
            try:
                asg = self._get_client("autoscaling", region)
                self._rate_limit()
                self._log_api_call(
                    "GET", f"autoscaling:DescribeAutoScalingGroups ({region})"
                )
                response = asg.describe_auto_scaling_groups()

                for group in response.get("AutoScalingGroups", []):
                    azs = group.get("AvailabilityZones", [])
                    ha_config["auto_scaling_groups"].append(
                        {
                            "name": group.get("AutoScalingGroupName"),
                            "arn": group.get("AutoScalingGroupARN"),
                            "min_size": group.get("MinSize"),
                            "max_size": group.get("MaxSize"),
                            "desired_capacity": group.get("DesiredCapacity"),
                            "availability_zones": azs,
                            "az_count": len(azs),
                            "health_check_type": group.get("HealthCheckType"),
                            "region": region,
                        }
                    )
            except Exception as e:
                self.logger.warning(f"Failed to collect ASG from {region}: {e}")

        # Calculate summary
        rds_multi_az = sum(
            1 for r in ha_config["rds_instances"] if r.get("multi_az")
        )
        elb_multi_az = sum(
            1 for lb in ha_config["load_balancers"] if lb.get("az_count", 0) > 1
        )
        asg_multi_az = sum(
            1 for asg in ha_config["auto_scaling_groups"] if asg.get("az_count", 0) > 1
        )

        ha_config["summary"] = {
            "total_rds_instances": len(ha_config["rds_instances"]),
            "rds_multi_az_count": rds_multi_az,
            "total_load_balancers": len(ha_config["load_balancers"]),
            "elb_multi_az_count": elb_multi_az,
            "total_auto_scaling_groups": len(ha_config["auto_scaling_groups"]),
            "asg_multi_az_count": asg_multi_az,
        }

        return [
            self.normalize_evidence(
                ha_config,
                "ha_config",
                {"source": "aws_ha", "regions": self._get_regions()},
            )
        ]
