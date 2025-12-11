# Sample Evidence Files

This directory contains example evidence files demonstrating the format that Nisify collectors produce. These files can be used for:

- Understanding the evidence schema
- Testing the mapping engine without live API connections
- Developing custom collectors
- Documentation and training

## Evidence Format

Each evidence file is a JSON document with the following structure:

```json
{
    "id": "unique-evidence-identifier",
    "platform": "platform-name",
    "evidence_type": "type-matching-nist-mapping",
    "collected_at": "ISO-8601-timestamp",
    "raw_data": {
        // Platform-specific data
    },
    "metadata": {
        "collector_version": "1.0.0",
        // Additional context
    }
}
```

## Sample Files

| File | Platform | Evidence Type | Description |
|------|----------|---------------|-------------|
| aws_mfa_status.json | AWS | mfa_status | IAM user MFA enrollment status |
| aws_security_findings.json | AWS | security_findings | Security Hub findings |
| okta_user_inventory.json | Okta | user_inventory | User directory with status |
| jamf_device_inventory.json | Jamf | device_inventory | Managed device inventory |

## Using Sample Evidence

To test the mapping engine with sample evidence:

```python
from nisify.nist import MappingEngine
from nisify.collectors.base import Evidence
import json

# Load sample evidence
with open('examples/sample_evidence/aws_mfa_status.json') as f:
    data = json.load(f)

# Create Evidence object
evidence = Evidence(
    id=data['id'],
    platform=data['platform'],
    evidence_type=data['evidence_type'],
    collected_at=data['collected_at'],
    raw_data=data['raw_data'],
    metadata=data['metadata']
)

# Map to NIST controls
engine = MappingEngine()
results = engine.map_evidence([evidence])
```

## Evidence Types Reference

### AWS Evidence Types

- `mfa_status` - MFA enrollment per IAM user
- `security_findings` - Security Hub findings
- `password_policy` - Account password policy
- `access_keys` - IAM access key inventory
- `audit_logging` - CloudTrail configuration
- `config_compliance` - AWS Config rule status
- `data_protection` - S3 bucket security settings

### Okta Evidence Types

- `user_inventory` - User directory
- `mfa_status` - MFA factors per user
- `access_logs` - System log events
- `security_policies` - Sign-on and MFA policies
- `access_assignments` - App and group assignments

### Jamf Evidence Types

- `device_inventory` - Managed computers and devices
- `encryption_status` - FileVault status
- `endpoint_compliance` - Compliance EA values
- `software_inventory` - Installed applications
- `security_configurations` - Configuration profiles

### Google Workspace Evidence Types

- `user_inventory` - Directory users
- `mfa_status` - 2-Step Verification status
- `access_logs` - Admin audit logs
- `device_inventory` - ChromeOS and mobile devices

### Snowflake Evidence Types

- `user_inventory` - Snowflake users
- `access_policies` - Role grants
- `authentication_logs` - Login history
- `access_logs` - Query history
- `data_access_logs` - Access history
- `identity_federation` - SSO configuration

### Datadog Evidence Types

- `security_findings` - Security signals
- `detection_rules` - Security rules
- `monitoring_coverage` - Monitors
- `audit_logs` - Audit trail
- `log_retention` - Log retention settings
