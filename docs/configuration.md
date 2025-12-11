# Nisify Configuration Reference

This document provides a complete reference for configuring Nisify, including YAML configuration options, environment variable overrides, and platform-specific credential setup.

## Configuration File Location

Nisify looks for configuration in the following locations (in order of precedence):

1. Path specified by `NISIFY_CONFIG` environment variable
2. `~/.nisify/config.yaml` (default location)

The configuration directory (`~/.nisify/`) is created automatically when you run `nisify init`.

## Directory Structure

After initialization, the Nisify directory contains:

```
~/.nisify/
    config.yaml          # Main configuration file
    credentials.enc      # Encrypted credentials (Fernet)
    credentials.salt     # Salt for key derivation
    data/
        nisify.db        # SQLite database
        evidence/        # Raw evidence files (JSON)
            aws/
            okta/
            jamf/
            google/
            snowflake/
            datadog/
    logs/
        scheduler.log    # Scheduler activity log
    reports/             # Generated reports
    scheduler/
        state.json       # Scheduler state
        scheduler.pid    # Daemon PID file
```

## Configuration File Format

The configuration file uses YAML format with the following structure:

```yaml
# Nisify configuration file

nisify:
  data_dir: ~/.nisify/data
  log_level: INFO

platforms:
  aws:
    enabled: false
    profile: default
    regions:
      - us-east-1

  okta:
    enabled: false
    domain: ""

  jamf:
    enabled: false
    url: ""

  google:
    enabled: false
    customer_id: ""
    service_account_path: ""

  snowflake:
    enabled: false
    account: ""
    warehouse: ""

  datadog:
    enabled: false
    site: datadoghq.com

collection:
  schedule: daily
  retention_days: 365

reporting:
  company_name: ""
  output_dir: ~/.nisify/reports
```

## Configuration Options

### Global Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `nisify.data_dir` | string | `~/.nisify/data` | Directory for evidence storage and database |
| `nisify.log_level` | string | `INFO` | Logging verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL |

### AWS Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.aws.enabled` | boolean | `false` | Enable AWS evidence collection |
| `platforms.aws.profile` | string | `default` | AWS CLI profile name |
| `platforms.aws.regions` | list | `[us-east-1]` | AWS regions to collect from |

**Required Credentials:**
- `aws_access_key_id` - AWS access key
- `aws_secret_access_key` - AWS secret key
- `aws_session_token` (optional) - Temporary session token

### Okta Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.okta.enabled` | boolean | `false` | Enable Okta evidence collection |
| `platforms.okta.domain` | string | `""` | Okta organization domain (e.g., `yourorg.okta.com`) |

**Required Credentials:**
- `api_token` - Okta API token with read permissions

### Jamf Pro Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.jamf.enabled` | boolean | `false` | Enable Jamf Pro evidence collection |
| `platforms.jamf.url` | string | `""` | Jamf Pro server URL (e.g., `https://yourorg.jamfcloud.com`) |

**Required Credentials:**
- `client_id` - Jamf Pro API client ID
- `client_secret` - Jamf Pro API client secret

### Google Workspace Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.google.enabled` | boolean | `false` | Enable Google Workspace evidence collection |
| `platforms.google.customer_id` | string | `""` | Google Workspace customer ID (e.g., `C12345678`) |
| `platforms.google.service_account_path` | string | `""` | Path to service account JSON key file |

**Required Setup:**
1. Create a service account in Google Cloud Console
2. Enable Admin SDK API
3. Grant domain-wide delegation to the service account
4. Download the JSON key file
5. Set the path in configuration

### Snowflake Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.snowflake.enabled` | boolean | `false` | Enable Snowflake evidence collection |
| `platforms.snowflake.account` | string | `""` | Snowflake account identifier |
| `platforms.snowflake.warehouse` | string | `""` | Warehouse to use for queries |

**Required Credentials:**
- `username` - Snowflake username
- `password` - Snowflake password

**Note:** Snowflake queries consume compute credits. The collector queries ACCOUNT_USAGE views which are available only to ACCOUNTADMIN role or users with SELECT privileges on these views.

### Datadog Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.datadog.enabled` | boolean | `false` | Enable Datadog evidence collection |
| `platforms.datadog.site` | string | `datadoghq.com` | Datadog site: datadoghq.com, datadoghq.eu, us3.datadoghq.com, etc. |

**Required Credentials:**
- `api_key` - Datadog API key
- `app_key` - Datadog application key (with read permissions)

### Collection Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `collection.schedule` | string | `daily` | Collection frequency: hourly, daily, weekly |
| `collection.retention_days` | integer | `365` | Days to retain evidence before cleanup |

### Reporting Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `reporting.company_name` | string | `""` | Organization name for reports |
| `reporting.output_dir` | string | `~/.nisify/reports` | Directory for generated reports |

## Environment Variable Overrides

Configuration values can be overridden using environment variables. The following variables are supported:

| Environment Variable | Overrides |
|---------------------|-----------|
| `NISIFY_CONFIG` | Configuration file path |
| `NISIFY_DATA_DIR` | `nisify.data_dir` |
| `NISIFY_LOG_LEVEL` | `nisify.log_level` |
| `NISIFY_AWS_PROFILE` | `platforms.aws.profile` |
| `NISIFY_AWS_REGIONS` | `platforms.aws.regions` (comma-separated) |
| `NISIFY_OKTA_DOMAIN` | `platforms.okta.domain` |
| `NISIFY_JAMF_URL` | `platforms.jamf.url` |
| `NISIFY_GOOGLE_CUSTOMER_ID` | `platforms.google.customer_id` |
| `NISIFY_SNOWFLAKE_ACCOUNT` | `platforms.snowflake.account` |
| `NISIFY_DATADOG_SITE` | `platforms.datadog.site` |
| `NISIFY_PASSPHRASE` | Passphrase for credential decryption (scheduler) |

Environment variables take precedence over configuration file values.

## Credential Management

Credentials are stored separately from the configuration file and encrypted at rest using Fernet symmetric encryption with PBKDF2 key derivation.

### Setting Up Credentials

Use the interactive configuration command:

```bash
# Configure all platforms interactively
nisify configure

# Configure a specific platform
nisify configure set aws
nisify configure set okta
nisify configure set jamf
nisify configure set google
nisify configure set snowflake
nisify configure set datadog
```

### Credential Storage Security

- Credentials are encrypted using Fernet (AES-128-CBC with HMAC)
- Encryption key is derived from your passphrase using PBKDF2 (100,000 iterations)
- Salt is stored separately and regenerated on each initialization
- Credentials file is never written in plaintext

### Unlocking and Locking

For CLI operations that require credentials:

```bash
# Unlock the credential store (starts a session)
nisify configure unlock

# Lock the credential store (ends the session)
nisify configure lock
```

The unlock command prompts for your passphrase and keeps credentials accessible for subsequent commands in the same session.

## Example Configurations

### Minimal Configuration (AWS only)

```yaml
nisify:
  log_level: INFO

platforms:
  aws:
    enabled: true
    regions:
      - us-east-1
      - us-west-2
```

### Multi-Platform Configuration

```yaml
nisify:
  data_dir: /var/lib/nisify/data
  log_level: INFO

platforms:
  aws:
    enabled: true
    profile: security-audit
    regions:
      - us-east-1
      - eu-west-1
      - ap-southeast-1

  okta:
    enabled: true
    domain: acmecorp.okta.com

  jamf:
    enabled: true
    url: https://acmecorp.jamfcloud.com

  google:
    enabled: true
    customer_id: C0123456789
    service_account_path: /etc/nisify/google-sa.json

  datadog:
    enabled: true
    site: datadoghq.com

collection:
  schedule: daily
  retention_days: 730

reporting:
  company_name: Acme Corporation
  output_dir: /var/lib/nisify/reports
```

### Development Configuration

```yaml
nisify:
  data_dir: ./test-data
  log_level: DEBUG

platforms:
  aws:
    enabled: true
    profile: dev
    regions:
      - us-east-1

collection:
  schedule: hourly
  retention_days: 30
```

## Validation

Configuration is validated on load. Invalid configurations will produce clear error messages:

```
Error: Invalid log_level: VERBOSE. Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL
Error: Invalid schedule: monthly. Must be one of: hourly, daily, weekly
Error: retention_days must be at least 1
```

## Troubleshooting

### Configuration Not Found

```
Error: Configuration file not found at ~/.nisify/config.yaml
Run 'nisify init' to create the initial configuration.
```

### Invalid YAML Syntax

```
Error: Invalid YAML in config file: ...
Check your configuration file for syntax errors.
```

### Permission Denied

```
Error: Cannot read config file: Permission denied
Ensure the configuration file is readable by your user.
```

### Platform Not Enabled

If you receive "platform not enabled" errors during collection, verify:

1. The platform is set to `enabled: true` in the configuration
2. Credentials have been configured with `nisify configure set <platform>`
3. The credential store is unlocked
