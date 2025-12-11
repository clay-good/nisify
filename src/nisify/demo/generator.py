"""
Demo data generator for Nisify.

Generates realistic sample evidence and maturity data for demonstrations
and evaluation without requiring actual platform credentials.

Profiles:
    - startup: Small company, basic security, many gaps
    - growing: Mid-size company, moderate security, some gaps
    - mature: Large company, strong security, few gaps
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from nisify.collectors.base import CollectionResult, Evidence
from nisify.config.settings import DEFAULT_CONFIG_DIR
from nisify.nist import get_all_functions
from nisify.storage.evidence_store import EvidenceStore
from nisify.storage.models import ControlMapping, MaturitySnapshot

logger = logging.getLogger(__name__)


class DemoProfile(Enum):
    """Demo organization profiles with different maturity levels."""

    STARTUP = "startup"  # Low maturity, many gaps
    GROWING = "growing"  # Medium maturity, moderate gaps
    MATURE = "mature"  # High maturity, few gaps


# Platform configurations for demo data
DEMO_PLATFORMS = {
    "aws": {
        "name": "Amazon Web Services",
        "evidence_types": [
            "iam_configuration",
            "security_hub_findings",
            "cloudtrail_status",
            "config_rules",
            "s3_encryption",
            "vpc_flow_logs",
        ],
    },
    "okta": {
        "name": "Okta",
        "evidence_types": [
            "user_inventory",
            "mfa_status",
            "system_logs",
            "security_policies",
            "admin_roles",
        ],
    },
    "jamf": {
        "name": "Jamf Pro",
        "evidence_types": [
            "device_inventory",
            "filevault_status",
            "compliance_status",
            "configuration_profiles",
        ],
    },
    "google": {
        "name": "Google Workspace",
        "evidence_types": [
            "admin_audit_logs",
            "directory_users",
            "2sv_status",
            "security_settings",
        ],
    },
}

# Maturity level distributions by profile
# Format: [level_0_weight, level_1_weight, level_2_weight, level_3_weight, level_4_weight]
MATURITY_DISTRIBUTIONS = {
    DemoProfile.STARTUP: [0.2, 0.35, 0.30, 0.10, 0.05],
    DemoProfile.GROWING: [0.05, 0.15, 0.35, 0.35, 0.10],
    DemoProfile.MATURE: [0.02, 0.05, 0.15, 0.40, 0.38],
}

# Organization names for profiles
ORG_NAMES = {
    DemoProfile.STARTUP: "TechStart Inc.",
    DemoProfile.GROWING: "GrowthCo Solutions",
    DemoProfile.MATURE: "Enterprise Global Corp",
}


@dataclass
class DemoConfig:
    """Configuration for demo data generation."""

    profile: DemoProfile
    organization: str
    days_of_history: int = 30
    platforms: list[str] | None = None


class DemoGenerator:
    """
    Generates realistic demo data for Nisify.

    Creates sample evidence, control mappings, and maturity snapshots
    that can be used to demonstrate the dashboard and reporting features.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        config: DemoConfig | None = None,
    ) -> None:
        """
        Initialize demo generator.

        Args:
            data_dir: Directory for data storage. Defaults to ~/.nisify/data
            config: Demo configuration. Defaults to growing profile.
        """
        self.data_dir = data_dir or (DEFAULT_CONFIG_DIR / "data")
        self.config = config or DemoConfig(
            profile=DemoProfile.GROWING,
            organization=ORG_NAMES[DemoProfile.GROWING],
        )
        self.store = EvidenceStore(data_dir=self.data_dir)
        self._functions = get_all_functions()

    def generate(self) -> dict[str, Any]:
        """
        Generate all demo data.

        Returns:
            Summary of generated data.
        """
        logger.info(f"Generating demo data for profile: {self.config.profile.value}")
        logger.info(f"Organization: {self.config.organization}")

        platforms = self.config.platforms or list(DEMO_PLATFORMS.keys())

        # Generate historical data
        total_evidence = 0
        total_mappings = 0
        total_snapshots = 0

        # Generate data for each day in history
        days = self.config.days_of_history
        for day_offset in range(days, -1, -1):
            timestamp = datetime.now(UTC) - timedelta(days=day_offset)

            # Generate collection results
            for platform in platforms:
                result = self._generate_collection_result(platform, timestamp)
                run_id = self.store.save_collection_run(result)
                total_evidence += len(result.evidence_items)

                # Generate mappings for this evidence
                for evidence in result.evidence_items:
                    mappings = self._generate_mappings(evidence)
                    for mapping in mappings:
                        self.store.save_control_mapping(mapping)
                        total_mappings += 1

            # Generate maturity snapshots at end of each "day"
            # (using slight time offset for historical snapshots)
            snapshot_time = timestamp.replace(hour=23, minute=59, second=59)
            snapshots = self._generate_maturity_snapshots(snapshot_time)
            self.store.save_maturity_snapshots(snapshots)
            total_snapshots += len(snapshots)

            if day_offset % 7 == 0:
                logger.debug(f"Generated data for day -{day_offset}")

        summary = {
            "profile": self.config.profile.value,
            "organization": self.config.organization,
            "platforms": platforms,
            "days_of_history": days,
            "evidence_items": total_evidence,
            "control_mappings": total_mappings,
            "maturity_snapshots": total_snapshots,
        }

        logger.info(f"Demo data generation complete: {total_evidence} evidence items")
        return summary

    def _generate_collection_result(
        self,
        platform: str,
        timestamp: datetime,
    ) -> CollectionResult:
        """Generate a collection result for a platform."""
        platform_config = DEMO_PLATFORMS.get(platform, {})
        evidence_types = platform_config.get("evidence_types", [])

        evidence_items = []
        for evidence_type in evidence_types:
            evidence = self._generate_evidence(platform, evidence_type, timestamp)
            evidence_items.append(evidence)

        return CollectionResult(
            platform=platform,
            timestamp=timestamp,
            success=True,
            evidence_items=evidence_items,
            errors=[],
            duration_seconds=round(random.uniform(2.5, 15.0), 2),
            partial=False,
        )

    def _generate_evidence(
        self,
        platform: str,
        evidence_type: str,
        timestamp: datetime,
    ) -> Evidence:
        """Generate a single evidence item."""
        raw_data = self._generate_evidence_data(platform, evidence_type)

        evidence = Evidence(
            id=str(uuid.uuid4()),
            platform=platform,
            evidence_type=evidence_type,
            collected_at=timestamp,
            raw_data=raw_data,
            metadata={
                "demo": True,
                "profile": self.config.profile.value,
                "generated_at": datetime.now(UTC).isoformat(),
            },
        )
        return evidence

    def _generate_evidence_data(
        self,
        platform: str,
        evidence_type: str,
    ) -> dict[str, Any]:
        """Generate realistic raw data for an evidence type."""
        profile = self.config.profile

        # Scale factors based on profile
        user_counts = {
            DemoProfile.STARTUP: random.randint(15, 50),
            DemoProfile.GROWING: random.randint(100, 500),
            DemoProfile.MATURE: random.randint(1000, 5000),
        }
        user_count = user_counts[profile]

        device_counts = {
            DemoProfile.STARTUP: random.randint(20, 75),
            DemoProfile.GROWING: random.randint(150, 600),
            DemoProfile.MATURE: random.randint(1500, 6000),
        }
        device_count = device_counts[profile]

        # MFA rates based on profile
        mfa_rates = {
            DemoProfile.STARTUP: random.uniform(0.50, 0.75),
            DemoProfile.GROWING: random.uniform(0.80, 0.95),
            DemoProfile.MATURE: random.uniform(0.95, 1.0),
        }
        mfa_rate = mfa_rates[profile]

        # Compliance rates based on profile
        compliance_rates = {
            DemoProfile.STARTUP: random.uniform(0.60, 0.80),
            DemoProfile.GROWING: random.uniform(0.85, 0.95),
            DemoProfile.MATURE: random.uniform(0.95, 0.99),
        }
        compliance_rate = compliance_rates[profile]

        # Generate data based on evidence type
        if evidence_type == "mfa_status":
            mfa_enabled = int(user_count * mfa_rate)
            return {
                "total_users": user_count,
                "mfa_enabled": mfa_enabled,
                "mfa_disabled": user_count - mfa_enabled,
                "mfa_rate": round(mfa_rate * 100, 1),
                "enforcement_policy": "required" if mfa_rate > 0.9 else "optional",
            }

        elif evidence_type == "user_inventory":
            return {
                "total_users": user_count,
                "active_users": int(user_count * 0.85),
                "inactive_users": int(user_count * 0.15),
                "admin_users": max(3, int(user_count * 0.05)),
                "service_accounts": max(2, int(user_count * 0.03)),
            }

        elif evidence_type == "device_inventory":
            compliant = int(device_count * compliance_rate)
            return {
                "total_devices": device_count,
                "compliant_devices": compliant,
                "non_compliant_devices": device_count - compliant,
                "managed_devices": int(device_count * 0.95),
                "os_distribution": {
                    "macOS": int(device_count * 0.65),
                    "Windows": int(device_count * 0.30),
                    "Linux": int(device_count * 0.05),
                },
            }

        elif evidence_type == "filevault_status":
            encrypted = int(device_count * compliance_rate)
            return {
                "total_devices": device_count,
                "encrypted_devices": encrypted,
                "unencrypted_devices": device_count - encrypted,
                "encryption_rate": round(compliance_rate * 100, 1),
            }

        elif evidence_type == "security_hub_findings":
            # Findings counts based on profile (lower = more mature)
            finding_multipliers = {
                DemoProfile.STARTUP: 3.0,
                DemoProfile.GROWING: 1.5,
                DemoProfile.MATURE: 0.5,
            }
            multiplier = finding_multipliers[profile]
            return {
                "total_findings": int(50 * multiplier),
                "critical": int(5 * multiplier),
                "high": int(15 * multiplier),
                "medium": int(20 * multiplier),
                "low": int(10 * multiplier),
                "compliance_score": round(100 - (25 * multiplier), 1),
            }

        elif evidence_type == "iam_configuration":
            return {
                "total_users": user_count,
                "users_with_mfa": int(user_count * mfa_rate),
                "access_keys_active": max(5, int(user_count * 0.1)),
                "access_keys_rotated_90days": int(user_count * 0.08 * compliance_rate),
                "roles_count": max(10, int(user_count * 0.2)),
                "policies_count": max(20, int(user_count * 0.4)),
            }

        elif evidence_type == "cloudtrail_status":
            return {
                "trails_configured": 2 if profile == DemoProfile.MATURE else 1,
                "multi_region": profile != DemoProfile.STARTUP,
                "log_file_validation": profile != DemoProfile.STARTUP,
                "s3_bucket_logging": profile == DemoProfile.MATURE,
                "encryption_enabled": profile != DemoProfile.STARTUP,
            }

        elif evidence_type == "config_rules":
            rule_counts = {
                DemoProfile.STARTUP: random.randint(5, 15),
                DemoProfile.GROWING: random.randint(25, 50),
                DemoProfile.MATURE: random.randint(75, 150),
            }
            rule_count = rule_counts[profile]
            compliant_rules = int(rule_count * compliance_rate)
            return {
                "total_rules": rule_count,
                "compliant": compliant_rules,
                "non_compliant": rule_count - compliant_rules,
                "compliance_percentage": round(compliance_rate * 100, 1),
            }

        elif evidence_type == "s3_encryption":
            bucket_counts = {
                DemoProfile.STARTUP: random.randint(5, 15),
                DemoProfile.GROWING: random.randint(20, 50),
                DemoProfile.MATURE: random.randint(100, 300),
            }
            bucket_count = bucket_counts[profile]
            encrypted = int(bucket_count * compliance_rate)
            return {
                "total_buckets": bucket_count,
                "encrypted_buckets": encrypted,
                "unencrypted_buckets": bucket_count - encrypted,
                "default_encryption_enabled": profile != DemoProfile.STARTUP,
            }

        elif evidence_type == "vpc_flow_logs":
            vpc_counts = {
                DemoProfile.STARTUP: random.randint(1, 3),
                DemoProfile.GROWING: random.randint(3, 10),
                DemoProfile.MATURE: random.randint(10, 50),
            }
            vpc_count = vpc_counts[profile]
            logged = int(vpc_count * compliance_rate)
            return {
                "total_vpcs": vpc_count,
                "flow_logs_enabled": logged,
                "flow_logs_disabled": vpc_count - logged,
            }

        elif evidence_type == "system_logs":
            log_days = {
                DemoProfile.STARTUP: 30,
                DemoProfile.GROWING: 90,
                DemoProfile.MATURE: 365,
            }
            return {
                "log_retention_days": log_days[profile],
                "total_events_30d": random.randint(10000, 100000),
                "security_events_30d": random.randint(50, 500),
                "failed_logins_30d": random.randint(10, 100),
            }

        elif evidence_type == "security_policies":
            return {
                "password_policy": {
                    "min_length": 12 if profile != DemoProfile.STARTUP else 8,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_symbols": profile != DemoProfile.STARTUP,
                    "max_age_days": 90 if profile != DemoProfile.STARTUP else 0,
                },
                "session_policy": {
                    "timeout_minutes": 60 if profile == DemoProfile.MATURE else 480,
                    "idle_timeout_minutes": 30 if profile == DemoProfile.MATURE else 120,
                },
            }

        elif evidence_type == "admin_roles":
            admin_counts = {
                DemoProfile.STARTUP: random.randint(2, 5),
                DemoProfile.GROWING: random.randint(5, 15),
                DemoProfile.MATURE: random.randint(10, 30),
            }
            return {
                "total_admins": admin_counts[profile],
                "super_admins": max(1, admin_counts[profile] // 5),
                "read_only_admins": admin_counts[profile] // 3,
                "privileged_access_managed": profile != DemoProfile.STARTUP,
            }

        elif evidence_type == "admin_audit_logs":
            return {
                "audit_logging_enabled": True,
                "log_retention_days": 365 if profile == DemoProfile.MATURE else 180,
                "events_30d": random.randint(5000, 50000),
                "admin_actions_30d": random.randint(100, 1000),
            }

        elif evidence_type == "directory_users":
            return {
                "total_users": user_count,
                "active_users": int(user_count * 0.9),
                "suspended_users": int(user_count * 0.05),
                "org_units": max(3, user_count // 50),
            }

        elif evidence_type == "2sv_status":
            enrolled = int(user_count * mfa_rate)
            return {
                "total_users": user_count,
                "2sv_enrolled": enrolled,
                "2sv_not_enrolled": user_count - enrolled,
                "enforcement": "on" if mfa_rate > 0.9 else "off",
            }

        elif evidence_type == "security_settings":
            return {
                "less_secure_apps_disabled": profile != DemoProfile.STARTUP,
                "password_recovery_configured": True,
                "api_access_controlled": profile != DemoProfile.STARTUP,
                "advanced_protection_enrolled": profile == DemoProfile.MATURE,
            }

        elif evidence_type == "compliance_status":
            compliant = int(device_count * compliance_rate)
            return {
                "total_devices": device_count,
                "compliant": compliant,
                "non_compliant": device_count - compliant,
                "pending": int(device_count * 0.02),
            }

        elif evidence_type == "configuration_profiles":
            profile_counts = {
                DemoProfile.STARTUP: random.randint(3, 8),
                DemoProfile.GROWING: random.randint(10, 25),
                DemoProfile.MATURE: random.randint(30, 75),
            }
            count = profile_counts[profile]
            return {
                "total_profiles": count,
                "security_profiles": int(count * 0.4),
                "compliance_profiles": int(count * 0.3),
                "configuration_profiles": int(count * 0.3),
            }

        # Default generic data
        return {
            "status": "collected",
            "items": random.randint(10, 100),
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def _generate_mappings(self, evidence: Evidence) -> list[ControlMapping]:
        """Generate control mappings for an evidence item."""
        mappings = []

        # Map evidence types to relevant NIST controls
        evidence_control_map = {
            "mfa_status": ["PR.AC-01", "PR.AC-05", "PR.AC-07"],
            "user_inventory": ["PR.AC-01", "PR.AC-04", "ID.AM-01"],
            "device_inventory": ["ID.AM-01", "ID.AM-02", "PR.AC-04"],
            "filevault_status": ["PR.DS-01", "PR.DS-02", "PR.DS-05"],
            "security_hub_findings": ["DE.CM-01", "DE.CM-07", "RS.AN-01"],
            "iam_configuration": ["PR.AC-01", "PR.AC-04", "PR.AC-05"],
            "cloudtrail_status": ["DE.CM-01", "DE.AE-03", "RS.AN-01"],
            "config_rules": ["DE.CM-01", "ID.GV-01", "PR.IP-01"],
            "s3_encryption": ["PR.DS-01", "PR.DS-02", "PR.DS-05"],
            "vpc_flow_logs": ["DE.CM-01", "DE.AE-03", "PR.DS-05"],
            "system_logs": ["DE.CM-01", "DE.AE-03", "RS.AN-01"],
            "security_policies": ["PR.AC-01", "PR.AC-05", "ID.GV-01"],
            "admin_roles": ["PR.AC-04", "PR.AC-05", "ID.GV-01"],
            "admin_audit_logs": ["DE.CM-01", "DE.AE-03", "RS.AN-01"],
            "directory_users": ["PR.AC-01", "PR.AC-04", "ID.AM-01"],
            "2sv_status": ["PR.AC-01", "PR.AC-05", "PR.AC-07"],
            "security_settings": ["PR.AC-01", "PR.IP-01", "ID.GV-01"],
            "compliance_status": ["ID.GV-01", "ID.RA-01", "PR.IP-01"],
            "configuration_profiles": ["PR.IP-01", "PR.DS-01", "PR.AC-03"],
        }

        control_ids = evidence_control_map.get(
            evidence.evidence_type, ["ID.AM-01", "PR.AC-01"]
        )

        for control_id in control_ids:
            confidence = random.uniform(0.7, 1.0)
            mapping = ControlMapping.create(
                evidence_id=evidence.id,
                control_id=control_id,
                mapping_confidence=round(confidence, 2),
                mapping_reason=f"Evidence type '{evidence.evidence_type}' from {evidence.platform} supports this control",
            )
            mappings.append(mapping)

        return mappings

    def _generate_maturity_snapshots(
        self,
        timestamp: datetime,
    ) -> list[MaturitySnapshot]:
        """Generate maturity snapshots for all controls."""
        snapshots = []
        distribution = MATURITY_DISTRIBUTIONS[self.config.profile]

        # Generate snapshots for each function, category, and subcategory
        for function in self._functions:
            function_levels = []

            for category in function.categories:
                category_levels = []

                for subcategory in category.subcategories:
                    # Determine maturity level based on profile distribution
                    level = self._random_maturity_level(distribution)
                    category_levels.append(level)

                    # Create subcategory snapshot
                    evidence_count = level * 2 + random.randint(0, 3)
                    confidence = 0.5 + (level * 0.1) + random.uniform(0, 0.1)

                    snapshot = MaturitySnapshot(
                        id=str(uuid.uuid4()),
                        timestamp=timestamp,
                        function_id=function.id,
                        category_id=category.id,
                        subcategory_id=subcategory.id,
                        maturity_level=level,
                        evidence_count=evidence_count,
                        confidence=min(1.0, round(confidence, 2)),
                        details={
                            "demo": True,
                            "profile": self.config.profile.value,
                        },
                    )
                    snapshots.append(snapshot)

                # Create category rollup (average of subcategories)
                if category_levels:
                    avg_level = sum(category_levels) / len(category_levels)
                    function_levels.append(avg_level)

                    cat_snapshot = MaturitySnapshot(
                        id=str(uuid.uuid4()),
                        timestamp=timestamp,
                        function_id=function.id,
                        category_id=category.id,
                        subcategory_id=None,
                        maturity_level=round(avg_level),
                        evidence_count=sum(category_levels) * 2,
                        confidence=0.85,
                        details={"rollup": "category"},
                    )
                    snapshots.append(cat_snapshot)

            # Create function rollup (average of categories)
            if function_levels:
                func_avg = sum(function_levels) / len(function_levels)
                func_snapshot = MaturitySnapshot(
                    id=str(uuid.uuid4()),
                    timestamp=timestamp,
                    function_id=function.id,
                    category_id=None,
                    subcategory_id=None,
                    maturity_level=round(func_avg),
                    evidence_count=len(function_levels) * 10,
                    confidence=0.9,
                    details={"rollup": "function"},
                )
                snapshots.append(func_snapshot)

        return snapshots

    def _random_maturity_level(self, distribution: list[float]) -> int:
        """Select a maturity level based on the distribution weights."""
        r = random.random()
        cumulative = 0.0
        for level, weight in enumerate(distribution):
            cumulative += weight
            if r < cumulative:
                return level
        return 4  # Default to highest if something goes wrong


def generate_demo_data(
    profile: str | DemoProfile = DemoProfile.GROWING,
    organization: str | None = None,
    days: int = 30,
    platforms: list[str] | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Generate demo data with a single function call.

    Args:
        profile: Demo profile ("startup", "growing", "mature") or DemoProfile enum.
        organization: Organization name. Defaults based on profile.
        days: Days of historical data to generate.
        platforms: Platforms to include. Defaults to all.
        data_dir: Data directory. Defaults to ~/.nisify/data.

    Returns:
        Summary of generated data.

    Example:
        # Generate data for a growing company
        summary = generate_demo_data(profile="growing", days=30)

        # Generate data for a startup
        summary = generate_demo_data(profile="startup", organization="My Startup")
    """
    # Convert string profile to enum
    if isinstance(profile, str):
        profile = DemoProfile(profile.lower())

    # Set organization name if not provided
    if organization is None:
        organization = ORG_NAMES[profile]

    config = DemoConfig(
        profile=profile,
        organization=organization,
        days_of_history=days,
        platforms=platforms,
    )

    generator = DemoGenerator(data_dir=data_dir, config=config)
    return generator.generate()
