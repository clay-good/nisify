# NIST CSF 2.0 Evidence Mapping

This document explains how Nisify maps collected evidence to NIST Cybersecurity Framework 2.0 controls, the scoring algorithm, and how to customize mappings for your organization.

## Overview

Nisify uses deterministic, rule-based logic to map evidence to NIST CSF 2.0 controls. There is no machine learning or probabilistic inference - every mapping decision can be traced to explicit rules and evidence.

## NIST CSF 2.0 Structure

The NIST Cybersecurity Framework 2.0 is organized hierarchically:

```
Functions (6)
    Categories (22)
        Subcategories (106)
```

### Functions

| ID | Function | Description |
|----|----------|-------------|
| GV | Govern | Organizational context, risk management strategy, policies |
| ID | Identify | Asset management, risk assessment, improvement |
| PR | Protect | Access control, awareness, data security, platform security |
| DE | Detect | Continuous monitoring, adverse event analysis |
| RS | Respond | Incident management, analysis, mitigation, reporting |
| RC | Recover | Recovery planning, execution, communication |

### Coverage Statistics

- **Total Subcategories**: 106
- **API-Collectible**: 38 subcategories (36%)
- **Manual Evidence Required**: 68 subcategories (64%)
- **Mapped Controls**: 51 subcategories with evidence mapping configurations

## Mapping Process

### 1. Evidence Collection

Evidence is collected from platform APIs and normalized to a common schema:

```json
{
    "id": "uuid",
    "platform": "aws",
    "evidence_type": "mfa_status",
    "collected_at": "2024-01-15T12:00:00Z",
    "raw_data": { ... },
    "metadata": { ... }
}
```

### 2. Evidence-to-Control Mapping

The mapping engine loads configurations from `data/control_evidence_mappings.json` that define which evidence types satisfy which controls:

```json
{
    "control_id": "PR.AC-01",
    "required_evidence_types": ["mfa_status", "user_inventory"],
    "optional_evidence_types": ["access_policies"],
    "platforms": ["aws", "okta", "google"],
    "logic": "all_required",
    "freshness_days": 30,
    "description": "Identities and credentials are managed"
}
```

### 3. Status Determination

For each control, the engine determines a mapping status:

| Status | Description |
|--------|-------------|
| `satisfied` | All required evidence is present and fresh |
| `partial` | Some but not all required evidence is present |
| `unsatisfied` | No matching evidence found |
| `not_applicable` | Control marked as N/A for this organization |

### 4. Confidence Calculation

Confidence scores (0.0 - 1.0) are calculated based on:

- **Evidence completeness**: Percentage of required evidence types present
- **Evidence freshness**: Age of evidence relative to freshness threshold
- **Optional evidence**: Presence of optional evidence types increases confidence

## Mapping Logic Types

### ALL_REQUIRED

All specified evidence types must be present for the control to be satisfied.

```json
{
    "control_id": "PR.AC-01",
    "required_evidence_types": ["mfa_status", "user_inventory"],
    "logic": "all_required"
}
```

- If both `mfa_status` AND `user_inventory` present: `satisfied`
- If only one present: `partial`
- If neither present: `unsatisfied`

### ANY_REQUIRED

At least one specified evidence type must be present.

```json
{
    "control_id": "PR.DS-01",
    "required_evidence_types": ["data_protection", "encryption_status"],
    "logic": "any_required"
}
```

- If `data_protection` OR `encryption_status` present: `satisfied`
- If neither present: `unsatisfied`

### WEIGHTED

Evidence types have configurable weights for partial satisfaction scoring.

```json
{
    "control_id": "DE.CM-01",
    "required_evidence_types": ["security_findings", "monitoring_coverage"],
    "logic": "weighted",
    "weights": {
        "security_findings": 0.6,
        "monitoring_coverage": 0.4
    }
}
```

- Confidence = sum of weights for present evidence types
- If `security_findings` only: confidence = 0.6, status = `partial`
- If both present: confidence = 1.0, status = `satisfied`

## Freshness Calculation

Evidence freshness affects confidence scores:

| Age vs. Threshold | Confidence Modifier |
|-------------------|---------------------|
| Within threshold | No penalty (1.0x) |
| 1x - 2x threshold | Linear decay (1.0 to 0.5) |
| Beyond 2x threshold | Maximum penalty (0.2x minimum) |

Example with 30-day freshness threshold:

- Evidence 10 days old: No penalty
- Evidence 45 days old: ~0.75x confidence
- Evidence 90 days old: ~0.2x confidence (stale)

## Maturity Scoring

### Maturity Levels

Nisify uses a 0-4 maturity scale aligned with NIST implementation tiers:

| Level | Name | Description |
|-------|------|-------------|
| 0 | None | No evidence, control not addressed |
| 1 | Initial | Partial evidence, informal/ad-hoc processes |
| 2 | Developing | Documented processes, some automation |
| 3 | Defined | Consistent evidence, automated controls, measured |
| 4 | Optimized | Continuous improvement, advanced automation |

### Score Thresholds

Default thresholds for maturity levels:

| Level | Minimum Score |
|-------|---------------|
| 0 | 0.0 |
| 1 | 0.5 |
| 2 | 1.5 |
| 3 | 2.5 |
| 4 | 3.5 |

### Base Scores

| Mapping Status | Base Score |
|----------------|------------|
| Satisfied (fresh) | 3.0 |
| Satisfied (stale) | 2.0 |
| Partial | 1.5 |
| Unsatisfied | 0.0 |

### Score Modifiers

| Modifier | Effect | Trigger |
|----------|--------|---------|
| Automation bonus | +0.5 | Evidence collected via automated API |
| Improvement bonus | +0.5 | Score improved from previous period |
| Coverage gap penalty | -0.5 | Missing required evidence types |

### Hierarchical Roll-up

Scores roll up from subcategories to categories to functions to overall:

1. **Subcategory Score**: Based on evidence mapping result
2. **Category Score**: Average of subcategory scores within the category
3. **Function Score**: Average of category scores within the function
4. **Overall Score**: Average of all function scores

## Evidence Type Reference

### Identity and Access

| Evidence Type | Description | Platforms |
|--------------|-------------|-----------|
| `user_inventory` | User accounts and attributes | AWS, Okta, Google, Snowflake |
| `mfa_status` | MFA enrollment status | AWS, Okta, Google |
| `access_policies` | Access control policies | AWS, Okta, Snowflake |
| `access_assignments` | User-to-resource assignments | Okta, Jamf |
| `access_keys` | API key inventory and age | AWS |

### Security Monitoring

| Evidence Type | Description | Platforms |
|--------------|-------------|-----------|
| `security_findings` | Security alerts and findings | AWS, Datadog |
| `audit_logging` | Audit log configuration | AWS |
| `access_logs` | Authentication events | Okta, Google, Snowflake |
| `detection_rules` | Active detection rules | Datadog |
| `monitoring_coverage` | Monitoring scope | Datadog |

### Endpoint Security

| Evidence Type | Description | Platforms |
|--------------|-------------|-----------|
| `device_inventory` | Managed devices | Jamf, Google |
| `encryption_status` | Disk encryption status | Jamf |
| `endpoint_compliance` | Endpoint compliance checks | Jamf |
| `security_configurations` | Security profiles | Jamf |
| `software_inventory` | Installed software | Jamf |

### Data Protection

| Evidence Type | Description | Platforms |
|--------------|-------------|-----------|
| `data_protection` | Data protection controls | AWS |
| `config_compliance` | Configuration compliance | AWS |
| `password_policy` | Password requirements | AWS |

## Customizing Mappings

### Mapping Configuration File

Mappings are defined in `data/control_evidence_mappings.json`:

```json
{
    "version": "1.0",
    "mappings": [
        {
            "control_id": "PR.AC-01",
            "required_evidence_types": ["mfa_status", "user_inventory"],
            "optional_evidence_types": ["access_policies"],
            "platforms": ["aws", "okta"],
            "logic": "all_required",
            "freshness_days": 30,
            "description": "Identities and credentials are managed"
        }
    ]
}
```

### Adding a New Mapping

1. Identify the NIST control ID (e.g., `PR.AC-01`)
2. Determine which evidence types satisfy the control
3. Choose the appropriate logic type
4. Add the mapping to the configuration file
5. Restart Nisify to load the new mapping

### Modifying Existing Mappings

```json
{
    "control_id": "PR.AC-01",
    "required_evidence_types": ["mfa_status", "user_inventory", "access_logs"],
    "logic": "all_required",
    "freshness_days": 14
}
```

Changes take effect on the next maturity calculation.

### Custom Evidence Types

If you add a custom collector that produces new evidence types:

1. Create the collector producing evidence with your custom type
2. Add mappings referencing your evidence type
3. The mapping engine will automatically include your evidence

## Controls Requiring Manual Evidence

Many NIST controls require evidence that cannot be collected via API:

- Policy documents (GV.PO, GV.RR)
- Risk assessments (ID.RA)
- Training records (PR.AT)
- Incident response plans (RS.AN, RS.MI)
- Recovery plans (RC.RP)

These controls will show as `unsatisfied` until manual evidence is provided.

### Planned Features (Not Yet Implemented)

- Manual evidence upload via dashboard
- Document attachment to controls
- Policy document parsing

## Understanding Maturity Reports

### Score Interpretation

| Score Range | Interpretation |
|-------------|----------------|
| 0.0 - 0.5 | Critical gaps, no effective controls |
| 0.5 - 1.5 | Basic controls, significant gaps |
| 1.5 - 2.5 | Developing program, consistent coverage |
| 2.5 - 3.5 | Mature program, well-documented |
| 3.5 - 4.0 | Optimized, continuous improvement |

### Common Gaps

| Gap Type | Cause | Resolution |
|----------|-------|------------|
| `no_evidence` | No matching evidence collected | Enable platform, configure credentials |
| `stale_evidence` | Evidence older than freshness threshold | Run collection, verify platform access |
| `partial_evidence` | Missing some required evidence types | Enable additional platforms or collectors |
| `low_maturity` | Evidence present but score below target | Review evidence quality, add controls |

## Auditor Considerations

When presenting Nisify maturity scores to auditors:

1. **Scores are approximations**: Based on evidence presence and freshness, not effectiveness
2. **Mappings are interpretive**: The evidence-to-control mappings are reasonable but not officially validated
3. **Manual evidence gaps**: ~64% of controls require manual evidence not collected by Nisify
4. **Export raw evidence**: Auditors may want to review raw evidence files
5. **Explain methodology**: Provide this documentation for transparency

## API Reference

### Python API

```python
from nisify.nist import MappingEngine, MaturityCalculator

# Map evidence to controls
engine = MappingEngine()
results = engine.map_evidence(evidence_items)

# Calculate maturity scores
calculator = MaturityCalculator()
breakdown = calculator.calculate_all(results)

# Access scores
print(f"Overall: Level {breakdown.overall.level} ({breakdown.overall.score:.2f})")
for func_id, score in breakdown.by_function.items():
    print(f"  {func_id}: Level {score.level}")
```

### CLI

```bash
# View maturity scores
nisify maturity

# Detailed breakdown
nisify maturity --detailed

# Filter by function
nisify maturity --function PR

# JSON output
nisify maturity --json > maturity.json
```
