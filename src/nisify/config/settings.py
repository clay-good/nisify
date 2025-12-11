"""
Configuration settings management for Nisify.

This module handles loading, validating, and saving configuration settings
from YAML files with support for environment variable overrides.

Configuration is loaded from ~/.nisify/config.yaml by default, with the
path overridable via the NISIFY_CONFIG environment variable.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Default configuration directory
DEFAULT_CONFIG_DIR = Path.home() / ".nisify"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"


@dataclass
class PlatformConfig:
    """Configuration for a single platform."""

    enabled: bool = False
    # Platform-specific settings are stored as arbitrary dict
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass
class AwsConfig(PlatformConfig):
    """AWS-specific configuration."""

    profile: str = "default"
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])


@dataclass
class OktaConfig(PlatformConfig):
    """Okta-specific configuration."""

    domain: str = ""


@dataclass
class JamfConfig(PlatformConfig):
    """Jamf Pro-specific configuration."""

    url: str = ""


@dataclass
class GoogleConfig(PlatformConfig):
    """Google Workspace-specific configuration."""

    customer_id: str = ""
    service_account_path: str = ""


@dataclass
class SnowflakeConfig(PlatformConfig):
    """Snowflake-specific configuration."""

    account: str = ""
    warehouse: str = ""


@dataclass
class DatadogConfig(PlatformConfig):
    """Datadog-specific configuration."""

    site: str = "datadoghq.com"


@dataclass
class GitLabConfig(PlatformConfig):
    """GitLab-specific configuration."""

    url: str = "https://gitlab.com"


@dataclass
class JiraConfig(PlatformConfig):
    """Jira-specific configuration."""

    url: str = ""


@dataclass
class ZendeskConfig(PlatformConfig):
    """Zendesk-specific configuration."""

    subdomain: str = ""


@dataclass
class ZoomConfig(PlatformConfig):
    """Zoom-specific configuration."""

    pass


@dataclass
class NotionConfig(PlatformConfig):
    """Notion-specific configuration."""

    pass


@dataclass
class SlabConfig(PlatformConfig):
    """Slab-specific configuration."""

    pass


@dataclass
class SpotDraftConfig(PlatformConfig):
    """SpotDraft-specific configuration."""

    subdomain: str = ""


@dataclass
class CollectionConfig:
    """Evidence collection settings."""

    schedule: str = "daily"
    retention_days: int = 365


@dataclass
class ReportingConfig:
    """Reporting settings."""

    company_name: str = ""
    output_dir: str = str(DEFAULT_CONFIG_DIR / "reports")


@dataclass
class Settings:
    """
    Complete Nisify configuration settings.

    This dataclass represents all configuration options available in Nisify.
    Settings are loaded from a YAML configuration file and can be overridden
    by environment variables prefixed with NISIFY_.

    Attributes:
        data_dir: Directory for storing evidence and database files.
        log_level: Logging verbosity (DEBUG, INFO, WARNING, ERROR).
        aws: AWS platform configuration.
        okta: Okta platform configuration.
        jamf: Jamf Pro platform configuration.
        google: Google Workspace platform configuration.
        snowflake: Snowflake platform configuration.
        datadog: Datadog platform configuration.
        collection: Evidence collection settings.
        reporting: Report generation settings.
    """

    data_dir: str = str(DEFAULT_CONFIG_DIR / "data")
    log_level: str = "INFO"

    aws: AwsConfig = field(default_factory=AwsConfig)
    okta: OktaConfig = field(default_factory=OktaConfig)
    jamf: JamfConfig = field(default_factory=JamfConfig)
    google: GoogleConfig = field(default_factory=GoogleConfig)
    snowflake: SnowflakeConfig = field(default_factory=SnowflakeConfig)
    datadog: DatadogConfig = field(default_factory=DatadogConfig)
    gitlab: GitLabConfig = field(default_factory=GitLabConfig)
    jira: JiraConfig = field(default_factory=JiraConfig)
    zendesk: ZendeskConfig = field(default_factory=ZendeskConfig)
    zoom: ZoomConfig = field(default_factory=ZoomConfig)
    notion: NotionConfig = field(default_factory=NotionConfig)
    slab: SlabConfig = field(default_factory=SlabConfig)
    spotdraft: SpotDraftConfig = field(default_factory=SpotDraftConfig)

    collection: CollectionConfig = field(default_factory=CollectionConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)


class ConfigurationError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""

    pass


def get_config_path() -> Path:
    """
    Get the configuration file path.

    Returns the path from NISIFY_CONFIG environment variable if set,
    otherwise returns the default path (~/.nisify/config.yaml).

    Returns:
        Path to the configuration file.
    """
    env_path = os.environ.get("NISIFY_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_FILE


def load_config(config_path: Path | None = None) -> Settings:
    """
    Load configuration from YAML file.

    Reads configuration from the specified path (or default if not provided),
    applies environment variable overrides, and validates the configuration.

    Args:
        config_path: Optional path to configuration file. If not provided,
                    uses NISIFY_CONFIG environment variable or default path.

    Returns:
        Validated Settings instance.

    Raises:
        ConfigurationError: If the configuration file cannot be read or
                          contains invalid settings.
    """
    if config_path is None:
        config_path = get_config_path()

    settings = Settings()

    if config_path.exists():
        try:
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}") from e
        except OSError as e:
            raise ConfigurationError(f"Cannot read config file: {e}") from e

        settings = _apply_config_data(settings, config_data)

    settings = _apply_environment_overrides(settings)

    _validate_config(settings)

    return settings


def save_config(settings: Settings, config_path: Path | None = None) -> None:
    """
    Save configuration to YAML file.

    Args:
        settings: Settings instance to save.
        config_path: Optional path to configuration file.

    Raises:
        ConfigurationError: If the configuration cannot be written.
    """
    if config_path is None:
        config_path = get_config_path()

    config_path.parent.mkdir(parents=True, exist_ok=True)

    config_data = _settings_to_dict(settings)

    try:
        with open(config_path, "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False, sort_keys=False)
    except OSError as e:
        raise ConfigurationError(f"Cannot write config file: {e}") from e


def _apply_config_data(settings: Settings, data: dict[str, Any]) -> Settings:
    """Apply configuration data from parsed YAML to settings."""
    nisify_data = data.get("nisify", {})

    if "data_dir" in nisify_data:
        settings.data_dir = str(nisify_data["data_dir"])
    if "log_level" in nisify_data:
        settings.log_level = str(nisify_data["log_level"]).upper()

    platforms = data.get("platforms", {})

    if "aws" in platforms:
        aws = platforms["aws"]
        settings.aws.enabled = aws.get("enabled", False)
        settings.aws.profile = aws.get("profile", "default")
        settings.aws.regions = aws.get("regions", ["us-east-1"])

    if "okta" in platforms:
        okta = platforms["okta"]
        settings.okta.enabled = okta.get("enabled", False)
        settings.okta.domain = okta.get("domain", "")

    if "jamf" in platforms:
        jamf = platforms["jamf"]
        settings.jamf.enabled = jamf.get("enabled", False)
        settings.jamf.url = jamf.get("url", "")

    if "google" in platforms:
        google = platforms["google"]
        settings.google.enabled = google.get("enabled", False)
        settings.google.customer_id = google.get("customer_id", "")
        settings.google.service_account_path = google.get("service_account_path", "")

    if "snowflake" in platforms:
        snowflake = platforms["snowflake"]
        settings.snowflake.enabled = snowflake.get("enabled", False)
        settings.snowflake.account = snowflake.get("account", "")
        settings.snowflake.warehouse = snowflake.get("warehouse", "")

    if "datadog" in platforms:
        datadog = platforms["datadog"]
        settings.datadog.enabled = datadog.get("enabled", False)
        settings.datadog.site = datadog.get("site", "datadoghq.com")

    if "gitlab" in platforms:
        gitlab = platforms["gitlab"]
        settings.gitlab.enabled = gitlab.get("enabled", False)
        settings.gitlab.url = gitlab.get("url", "https://gitlab.com")

    if "jira" in platforms:
        jira = platforms["jira"]
        settings.jira.enabled = jira.get("enabled", False)
        settings.jira.url = jira.get("url", "")

    if "zendesk" in platforms:
        zendesk = platforms["zendesk"]
        settings.zendesk.enabled = zendesk.get("enabled", False)
        settings.zendesk.subdomain = zendesk.get("subdomain", "")

    if "zoom" in platforms:
        zoom = platforms["zoom"]
        settings.zoom.enabled = zoom.get("enabled", False)

    if "notion" in platforms:
        notion = platforms["notion"]
        settings.notion.enabled = notion.get("enabled", False)

    if "slab" in platforms:
        slab = platforms["slab"]
        settings.slab.enabled = slab.get("enabled", False)

    if "spotdraft" in platforms:
        spotdraft = platforms["spotdraft"]
        settings.spotdraft.enabled = spotdraft.get("enabled", False)
        settings.spotdraft.subdomain = spotdraft.get("subdomain", "")

    collection = data.get("collection", {})
    if "schedule" in collection:
        settings.collection.schedule = collection["schedule"]
    if "retention_days" in collection:
        settings.collection.retention_days = int(collection["retention_days"])

    reporting = data.get("reporting", {})
    if "company_name" in reporting:
        settings.reporting.company_name = reporting["company_name"]
    if "output_dir" in reporting:
        settings.reporting.output_dir = reporting["output_dir"]

    return settings


def _apply_environment_overrides(settings: Settings) -> Settings:
    """Apply environment variable overrides to settings."""
    env_map: dict[str, tuple[str, Callable[[str], Any]]] = {
        "NISIFY_DATA_DIR": ("data_dir", str),
        "NISIFY_LOG_LEVEL": ("log_level", str),
        "NISIFY_AWS_PROFILE": ("aws.profile", str),
        "NISIFY_AWS_REGIONS": ("aws.regions", lambda x: x.split(",")),
        "NISIFY_OKTA_DOMAIN": ("okta.domain", str),
        "NISIFY_JAMF_URL": ("jamf.url", str),
        "NISIFY_GOOGLE_CUSTOMER_ID": ("google.customer_id", str),
        "NISIFY_SNOWFLAKE_ACCOUNT": ("snowflake.account", str),
        "NISIFY_DATADOG_SITE": ("datadog.site", str),
    }

    for env_var, (attr_path, converter) in env_map.items():
        value = os.environ.get(env_var)
        if value is not None:
            _set_nested_attr(settings, attr_path, converter(value))

    return settings


def _set_nested_attr(obj: Any, path: str, value: Any) -> None:
    """Set a nested attribute on an object using dot notation."""
    parts = path.split(".")
    for part in parts[:-1]:
        obj = getattr(obj, part)
    setattr(obj, parts[-1], value)


def _validate_config(settings: Settings) -> None:
    """
    Validate configuration settings.

    Raises:
        ConfigurationError: If configuration is invalid.
    """
    valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if settings.log_level not in valid_log_levels:
        raise ConfigurationError(
            f"Invalid log_level: {settings.log_level}. "
            f"Must be one of: {', '.join(valid_log_levels)}"
        )

    if settings.collection.retention_days < 1:
        raise ConfigurationError("retention_days must be at least 1")

    valid_schedules = {"hourly", "daily", "weekly"}
    if settings.collection.schedule not in valid_schedules:
        raise ConfigurationError(
            f"Invalid schedule: {settings.collection.schedule}. "
            f"Must be one of: {', '.join(valid_schedules)}"
        )


def _settings_to_dict(settings: Settings) -> dict[str, Any]:
    """Convert Settings instance to dictionary for YAML serialization."""
    return {
        "nisify": {
            "data_dir": settings.data_dir,
            "log_level": settings.log_level,
        },
        "platforms": {
            "aws": {
                "enabled": settings.aws.enabled,
                "profile": settings.aws.profile,
                "regions": settings.aws.regions,
            },
            "okta": {
                "enabled": settings.okta.enabled,
                "domain": settings.okta.domain,
            },
            "jamf": {
                "enabled": settings.jamf.enabled,
                "url": settings.jamf.url,
            },
            "google": {
                "enabled": settings.google.enabled,
                "customer_id": settings.google.customer_id,
                "service_account_path": settings.google.service_account_path,
            },
            "snowflake": {
                "enabled": settings.snowflake.enabled,
                "account": settings.snowflake.account,
                "warehouse": settings.snowflake.warehouse,
            },
            "datadog": {
                "enabled": settings.datadog.enabled,
                "site": settings.datadog.site,
            },
            "gitlab": {
                "enabled": settings.gitlab.enabled,
                "url": settings.gitlab.url,
            },
            "jira": {
                "enabled": settings.jira.enabled,
                "url": settings.jira.url,
            },
            "zendesk": {
                "enabled": settings.zendesk.enabled,
                "subdomain": settings.zendesk.subdomain,
            },
            "zoom": {
                "enabled": settings.zoom.enabled,
            },
            "notion": {
                "enabled": settings.notion.enabled,
            },
            "slab": {
                "enabled": settings.slab.enabled,
            },
            "spotdraft": {
                "enabled": settings.spotdraft.enabled,
                "subdomain": settings.spotdraft.subdomain,
            },
        },
        "collection": {
            "schedule": settings.collection.schedule,
            "retention_days": settings.collection.retention_days,
        },
        "reporting": {
            "company_name": settings.reporting.company_name,
            "output_dir": settings.reporting.output_dir,
        },
    }
