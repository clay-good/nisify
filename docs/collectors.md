# Platform Collectors

This document provides detailed documentation for each platform collector, including required permissions, setup instructions, evidence types collected, and troubleshooting guidance.

## Overview

Nisify collectors are modular components that connect to external platforms via read-only API calls. Each collector:

- Implements the `BaseCollector` interface
- Uses platform-specific authentication
- Normalizes data to a common evidence schema
- Handles rate limiting and retry logic independently
- Can fail without blocking other collectors

## AWS Collector

The AWS collector gathers security evidence from AWS services including Security Hub, IAM, CloudTrail, AWS Config, and S3.

### Required Permissions

Create an IAM policy with these permissions (SecurityAudit managed policy covers most):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:GetFindings",
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
                "s3:GetBucketVersioning"
            ],
            "Resource": "*"
        }
    ]
}
```

### Setup Instructions

1. **Create IAM User or Role**

   For an IAM user:
   ```bash
   aws iam create-user --user-name nisify-collector
   aws iam attach-user-policy --user-name nisify-collector --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   aws iam create-access-key --user-name nisify-collector
   ```

   For an IAM role (recommended for EC2):
   Create a role with the SecurityAudit policy and assign to your instance.

2. **Configure Nisify**

   ```bash
   nisify configure set aws
   # Enter AWS access key ID
   # Enter AWS secret access key
   ```

3. **Configure Regions**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     aws:
       enabled: true
       regions:
         - us-east-1
         - us-west-2
         - eu-west-1
   ```

4. **Test Connection**

   ```bash
   nisify test-connection aws
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `security_findings` | Security Hub | Security findings with severity and compliance status |
| `password_policy` | IAM | Account password policy configuration |
| `mfa_status` | IAM | MFA enrollment status for all IAM users |
| `access_keys` | IAM | Access key age and last usage |
| `audit_logging` | CloudTrail | Trail configuration and status |
| `config_compliance` | AWS Config | Config rule compliance status |
| `data_protection` | S3 | Bucket encryption, public access, versioning |

### Troubleshooting

**Error: AccessDenied**
- Verify the IAM user/role has the SecurityAudit policy attached
- Check that the credentials are for the correct AWS account

**Error: Security Hub not enabled**
- Security Hub must be enabled in each region you want to collect from
- Enable via AWS Console or: `aws securityhub enable-security-hub`

**Error: AWS Config not enabled**
- AWS Config must be enabled to collect compliance data
- Evidence will be empty but collection will succeed

**Slow collection**
- Multi-region collection queries each region sequentially
- Consider reducing the number of regions or using parallel collection

---

## Okta Collector

The Okta collector gathers identity and access management evidence from Okta.

### Required Permissions

Create an API token with read-only access. The token needs these OAuth scopes:

- `okta.users.read`
- `okta.logs.read`
- `okta.policies.read`
- `okta.groups.read`
- `okta.apps.read`

### Setup Instructions

1. **Create API Token**

   - Log in to Okta Admin Console
   - Navigate to Security > API > Tokens
   - Click "Create Token"
   - Name it "Nisify Collector" and copy the token value

2. **Configure Nisify**

   ```bash
   nisify configure set okta
   # Enter your Okta domain (e.g., yourorg.okta.com)
   # Enter the API token
   ```

3. **Enable Platform**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     okta:
       enabled: true
       domain: yourorg.okta.com
   ```

4. **Test Connection**

   ```bash
   nisify test-connection okta
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `user_inventory` | Users API | All users with status and profile |
| `mfa_status` | Factors API | MFA enrollment per user |
| `access_logs` | System Log | Authentication and security events |
| `security_policies` | Policies API | Sign-on and MFA policies |
| `access_assignments` | Apps/Groups API | Application and group assignments |

### Troubleshooting

**Error: 401 Unauthorized**
- API token may be expired or revoked
- Create a new token and update credentials

**Error: 403 Forbidden**
- Token lacks required scopes
- Create a new token with appropriate permissions

**Rate limiting (429)**
- Okta has strict rate limits (varies by org tier)
- The collector implements automatic backoff
- Consider running collection during off-peak hours

---

## Jamf Pro Collector

The Jamf Pro collector gathers endpoint management evidence from Jamf Pro.

### Required Permissions

Create an API client with these permissions:

- Computers: Read
- Mobile Devices: Read
- Computer Extension Attributes: Read
- Configuration Profiles: Read

### Setup Instructions

1. **Create API Client**

   - Log in to Jamf Pro
   - Navigate to Settings > System > API Roles and Clients
   - Create a new API Role with read permissions
   - Create a new API Client and assign the role
   - Note the Client ID and generate a Client Secret

2. **Configure Nisify**

   ```bash
   nisify configure set jamf
   # Enter Jamf Pro URL (e.g., https://yourorg.jamfcloud.com)
   # Enter Client ID
   # Enter Client Secret
   ```

3. **Enable Platform**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     jamf:
       enabled: true
       url: https://yourorg.jamfcloud.com
   ```

4. **Test Connection**

   ```bash
   nisify test-connection jamf
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `device_inventory` | Computers/Mobile Devices | All managed devices |
| `encryption_status` | Computer inventory | FileVault/BitLocker status |
| `endpoint_compliance` | Extension Attributes | Custom compliance checks |
| `software_inventory` | Application inventory | Installed software |
| `security_configurations` | Configuration Profiles | Applied security profiles |

### Troubleshooting

**Error: 401 Unauthorized**
- Client credentials may be invalid
- Verify Client ID and Secret are correct
- Check that the API client is not disabled

**Error: 403 Forbidden**
- API role may lack required permissions
- Add read permissions for all required resources

**Empty encryption_status**
- FileVault status requires macOS inventory collection
- Ensure inventory is being collected on endpoints

---

## Google Workspace Collector

The Google Workspace collector gathers identity and audit evidence from Google Workspace Admin SDK.

### Required Setup

Google Workspace collection requires a service account with domain-wide delegation.

### Setup Instructions

1. **Create Google Cloud Project**

   - Go to Google Cloud Console
   - Create a new project or select existing
   - Note the project ID

2. **Enable Admin SDK API**

   ```bash
   gcloud services enable admin.googleapis.com
   ```

3. **Create Service Account**

   - Navigate to IAM & Admin > Service Accounts
   - Create a new service account
   - Grant no project-level roles (delegation handles permissions)
   - Create and download a JSON key file

4. **Enable Domain-Wide Delegation**

   - Edit the service account
   - Enable "Domain-wide delegation"
   - Note the OAuth Client ID

5. **Authorize in Google Admin**

   - Go to Google Admin Console
   - Navigate to Security > API Controls > Domain-wide Delegation
   - Add a new API client with:
     - Client ID: (from service account)
     - OAuth Scopes:
       ```
       https://www.googleapis.com/auth/admin.directory.user.readonly
       https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
       https://www.googleapis.com/auth/admin.reports.audit.readonly
       ```

6. **Configure Nisify**

   ```bash
   nisify configure set google
   # Enter Customer ID (find in Admin Console > Account > Account Settings)
   # Enter path to service account JSON key
   ```

7. **Enable Platform**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     google:
       enabled: true
       customer_id: C0123456789
       service_account_path: /path/to/service-account.json
   ```

8. **Test Connection**

   ```bash
   nisify test-connection google
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `user_inventory` | Directory API | All users in the domain |
| `mfa_status` | Directory API | 2-Step Verification status |
| `access_logs` | Reports API | Admin audit logs |
| `device_inventory` | Directory API | ChromeOS and mobile devices |

### Troubleshooting

**Error: Domain-wide delegation not configured**
- Verify the service account has delegation enabled
- Confirm OAuth scopes are authorized in Admin Console
- Check that Customer ID is correct

**Error: Service account file not found**
- Verify the path to the JSON key file
- Ensure the file is readable by the Nisify process

**Error: 403 Access denied**
- OAuth scopes may not be authorized
- Re-add the API client in Admin Console with all required scopes

---

## Snowflake Collector

The Snowflake collector gathers access and audit evidence from Snowflake ACCOUNT_USAGE views.

### Required Permissions

The Snowflake user needs SELECT access to ACCOUNT_USAGE schema:

```sql
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE your_role;
-- or specifically:
GRANT SELECT ON ALL VIEWS IN SCHEMA SNOWFLAKE.ACCOUNT_USAGE TO ROLE your_role;
```

### Setup Instructions

1. **Create Snowflake User**

   ```sql
   CREATE USER nisify_collector PASSWORD = 'secure_password';
   CREATE ROLE nisify_reader;
   GRANT ROLE nisify_reader TO USER nisify_collector;
   GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE nisify_reader;
   ```

2. **Configure Nisify**

   ```bash
   nisify configure set snowflake
   # Enter account identifier (e.g., xy12345.us-east-1)
   # Enter username
   # Enter password
   ```

3. **Enable Platform**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     snowflake:
       enabled: true
       account: xy12345.us-east-1
       warehouse: COMPUTE_WH
   ```

4. **Test Connection**

   ```bash
   nisify test-connection snowflake
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `user_inventory` | USERS view | All Snowflake users |
| `access_policies` | GRANTS_TO_USERS | Role and privilege grants |
| `authentication_logs` | LOGIN_HISTORY | Login attempts and failures |
| `access_logs` | QUERY_HISTORY | Query execution history |
| `data_access_logs` | ACCESS_HISTORY | Data access patterns |
| `identity_federation` | USERS view | SSO and federation status |

### Troubleshooting

**Error: Object does not exist**
- ACCOUNT_USAGE views require ACCOUNTADMIN or granted privileges
- Verify privileges are correctly assigned

**Cost Warning**
- Snowflake queries consume compute credits
- Collection activates the configured warehouse
- Consider collection frequency vs. credit cost

**Error: Warehouse suspended**
- The collector attempts to resume the warehouse
- Ensure auto-resume is enabled or warehouse is running

---

## Datadog Collector

The Datadog collector gathers security monitoring evidence from Datadog.

### Required Permissions

Create API and Application keys with read-only access:

- API Key: Any valid API key
- Application Key: Requires these scopes:
  - `security_monitoring_signals_read`
  - `security_monitoring_rules_read`
  - `monitors_read`
  - `audit_logs_read`

### Setup Instructions

1. **Create API Key**

   - Go to Organization Settings > API Keys
   - Create a new API key named "Nisify"

2. **Create Application Key**

   - Go to Organization Settings > Application Keys
   - Create a new application key
   - Grant required scopes

3. **Configure Nisify**

   ```bash
   nisify configure set datadog
   # Enter API key
   # Enter Application key
   ```

4. **Enable Platform**

   Edit `~/.nisify/config.yaml`:
   ```yaml
   platforms:
     datadog:
       enabled: true
       site: datadoghq.com  # or datadoghq.eu, us3.datadoghq.com, etc.
   ```

5. **Test Connection**

   ```bash
   nisify test-connection datadog
   ```

### Evidence Types Collected

| Evidence Type | Source | Description |
|--------------|--------|-------------|
| `security_findings` | Security Signals API | Security signals and threats |
| `detection_rules` | Security Rules API | Active detection rules |
| `monitoring_coverage` | Monitors API | Configured monitors |
| `audit_logs` | Audit Trail API | Platform audit events |
| `log_retention` | Logs API | Log retention configuration |

### Troubleshooting

**Error: 403 Forbidden**
- Application key may lack required scopes
- Create a new application key with all read scopes

**Wrong site**
- Ensure the Datadog site matches your organization
- Common sites: datadoghq.com, datadoghq.eu, us3.datadoghq.com

**Empty security_findings**
- Security monitoring may not be enabled
- Only Cloud Security Management generates security signals

---

## Adding Custom Collectors

You can create custom collectors by extending the `BaseCollector` class.

### Collector Interface

```python
from nisify.collectors.base import BaseCollector, CollectionResult, Evidence

class MyCollector(BaseCollector):
    platform = "myplatform"

    def collect(self) -> CollectionResult:
        """Collect evidence from the platform."""
        # Implementation
        pass

    def test_connection(self) -> bool:
        """Test connectivity to the platform."""
        # Implementation
        pass

    def get_required_permissions(self) -> list[str]:
        """Return list of required permissions."""
        return ["read:data"]
```

### Registration

Collectors are registered automatically when the module is imported:

```python
from nisify.collectors.base import CollectorRegistry

@CollectorRegistry.register
class MyCollector(BaseCollector):
    platform = "myplatform"
    # ...
```

### Best Practices

1. **Use rate limiting**: Call `self._rate_limit()` before each API call
2. **Handle errors gracefully**: Use try/except and return partial results
3. **Normalize evidence**: Use `self.normalize_evidence()` for consistent schema
4. **Log API calls**: Use `self._log_api_call()` for audit trail
5. **Implement retry logic**: Use `self._with_retry()` for transient failures
