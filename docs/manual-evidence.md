# Manual Evidence Collection Guide

Nisify automates evidence collection from 14 SaaS platforms, covering approximately 36% of NIST CSF 2.0 controls. The remaining 64% of controls require manual evidence submission because they involve documentation, governance processes, and organizational policies that cannot be pulled from APIs.

**This is by design.** NIST CSF 2.0 includes controls for governance, risk management, and organizational processes that are inherently document-based. No tool can fully automate compliance.

## How Manual Evidence Works

When you submit manual evidence using `nisify submit`, it:

1. **Stores the evidence** in your data directory alongside automated collections
2. **Maps to the specified control** during maturity calculations
3. **Reflects in your dashboard** with updated maturity scores
4. **Ages like any other evidence** - you should refresh manual evidence periodically

## Submitting Manual Evidence

```bash
# Basic submission with a file
nisify submit --control GV.PO-01 --type security_policy --file security-policy.pdf

# Submission with a URL reference
nisify submit --control GV.RR-01 --type board_minutes --url https://docs.company.com/board/2024-q4

# Submission with description
nisify submit --control GV.RM-03 --type risk_register \
  --file risk-register.xlsx \
  --description "Q4 2024 enterprise risk register"

# List available evidence types
nisify submit --list-types
```

## Controls Requiring Manual Evidence

The following controls typically require manual evidence because they involve governance, policies, and organizational processes.

### Governance (GV) - 31 controls

| Control | Name | Evidence Types |
|---------|------|----------------|
| GV.OC-03 | Legal/regulatory requirements | `compliance_register`, `policy_document` |
| GV.OC-04 | Critical objectives understood | `business_impact_analysis`, `service_catalog` |
| GV.OC-05 | Dependencies understood | `dependency_mapping`, `vendor_inventory` |
| GV.OV-01 | Risk strategy outcomes reviewed | `risk_review_minutes`, `kri_dashboard` |
| GV.OV-02 | Risk strategy adjusted | `strategy_document`, `review_minutes` |
| GV.PO-01 | Cybersecurity policy established | `security_policy`, `policy_document` |
| GV.PO-02 | Policy reviewed and enforced | `policy_review_log`, `policy_document` |
| GV.RM-03 | Risk in enterprise management | `risk_register`, `erm_integration` |
| GV.RM-04 | Risk response direction | `risk_response_strategy`, `policy_document` |
| GV.RM-05 | Communication lines established | `communication_plan`, `org_chart` |
| GV.RM-06 | Risk calculation standardized | `risk_methodology`, `risk_register` |
| GV.RM-07 | Strategic opportunities included | `opportunity_register`, `strategic_plan` |
| GV.RR-01 | Leadership accountability | `governance_charter`, `board_minutes` |
| GV.RR-02 | Roles/responsibilities defined | `raci_matrix`, `job_descriptions` |
| GV.RR-03 | Resources allocated | `budget_allocation`, `resource_plan` |
| GV.RR-04 | HR practices include security | `hr_policy`, `performance_criteria` |
| GV.SC-02 | Supplier roles defined | `vendor_agreements`, `raci_matrix` |
| GV.SC-04 | Suppliers prioritized | `vendor_inventory`, `criticality_assessment` |
| GV.SC-06 | Due diligence performed | `due_diligence_reports`, `vendor_assessments` |
| GV.SC-07 | Supplier risks monitored | `vendor_risk_assessments`, `risk_register` |
| GV.SC-08 | Suppliers in incident planning | `incident_plan`, `vendor_contacts` |
| GV.SC-09 | Supply chain in risk management | `scrm_metrics`, `lifecycle_management` |
| GV.SC-10 | Post-agreement provisions | `offboarding_procedures`, `data_return_policy` |

### Identify (ID) - 12 controls

| Control | Name | Evidence Types |
|---------|------|----------------|
| ID.AM-04 | Supplier services inventoried | `vendor_inventory`, `service_catalog` |
| ID.IM-03 | Improvements via exercises | `exercise_results`, `lessons_learned` |
| ID.IM-04 | IR plans established | `incident_response_plan`, `plan_review_log` |
| ID.RA-03 | Threats identified | `threat_register`, `threat_assessment` |
| ID.RA-04 | Impacts/likelihoods identified | `risk_assessment`, `impact_analysis` |
| ID.RA-06 | Risk responses tracked | `risk_treatment_plan`, `risk_register` |
| ID.RA-08 | Vuln disclosure established | `vulnerability_disclosure_policy` |
| ID.RA-09 | HW/SW authenticity verified | `procurement_policy`, `integrity_verification` |
| ID.RA-10 | Critical suppliers assessed | `vendor_assessment`, `due_diligence_reports` |

### Protect (PR) - 3 controls

| Control | Name | Evidence Types |
|---------|------|----------------|
| PR.IR-03 | Resilience for availability | `ha_config`, `dr_plan` |
| PR.IR-04 | Capacity maintained | `capacity_monitoring`, `resource_planning` |
| PR.PS-03 | Hardware maintained | `hardware_lifecycle`, `maintenance_records` |

### Respond (RS) - 5 controls

| Control | Name | Evidence Types |
|---------|------|----------------|
| RS.MA-01 | IR plan executed | `incident_response_plan`, `ir_execution_logs` |
| RS.MA-02 | Incidents triaged | `incident_triage_process`, `incident_log` |
| RS.MA-03 | Incidents categorized | `incident_classification`, `priority_matrix` |
| RS.MA-04 | Incidents escalated | `escalation_procedures`, `escalation_logs` |
| RS.MA-05 | Forensics capability | `forensics_capability`, `evidence_collection` |

### Recover (RC) - 2 controls

| Control | Name | Evidence Types |
|---------|------|----------------|
| RC.CO-04 | Public updates shared | `public_communication_plan`, `press_releases` |
| RC.RP-04 | Critical functions considered | `business_continuity_plan`, `operational_norms` |

## Evidence Types Reference

### Policy & Governance Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `security_policy` | Information security policy | Your InfoSec policy PDF |
| `policy_document` | General policy documentation | HR, IT, Legal policies |
| `governance_charter` | Security governance charter | Board-approved charter |
| `board_minutes` | Board meeting minutes | Quarterly board meetings |
| `raci_matrix` | Roles/responsibilities matrix | Your RACI spreadsheet |
| `job_descriptions` | Security role descriptions | HR job descriptions |
| `org_chart` | Organizational structure | Your org chart |

### Risk Management Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `risk_register` | Enterprise risk register | GRC tool export, Excel |
| `risk_assessment` | Risk assessment report | Annual risk assessment |
| `risk_methodology` | Risk calculation method | Your risk framework doc |
| `risk_treatment_plan` | Risk response plans | Treatment decisions |
| `risk_response_strategy` | Strategic risk responses | Board-approved strategy |
| `threat_register` | Identified threats | Threat modeling output |
| `threat_assessment` | Threat analysis | Security team assessment |
| `impact_analysis` | Business impact analysis | BIA document |

### Compliance & Audit Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `compliance_register` | Regulatory requirements | Compliance tracking sheet |
| `audit_report` | Internal/external audits | SOC 2, ISO 27001 reports |
| `penetration_test` | Pentest results | Annual pentest report |
| `vulnerability_scan` | Vuln scan reports | Nessus, Qualys exports |

### Vendor & Supply Chain Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `vendor_inventory` | Third-party vendors | Vendor management tool |
| `vendor_assessment` | Vendor security reviews | Security questionnaires |
| `vendor_agreements` | Supplier contracts | Legal/procurement |
| `due_diligence_reports` | Pre-contract assessments | Security team reviews |
| `criticality_assessment` | Vendor criticality ratings | Risk-based ratings |

### Business Continuity Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `business_continuity_plan` | BC/DR plan | Your BCP document |
| `incident_response_plan` | IR procedures | Your IRP document |
| `dr_plan` | Disaster recovery plan | DR runbooks |
| `business_impact_analysis` | BIA results | BIA spreadsheet |

### HR & Training Documents

| Type | Description | Suggested Sources |
|------|-------------|-------------------|
| `hr_policy` | HR security policies | HR policy documents |
| `training_records` | Training completion | LMS exports |
| `performance_criteria` | Security in reviews | HR evaluation forms |
| `budget_allocation` | Security budget | Finance reports |
| `resource_plan` | Resource allocation | Staffing plans |

## Best Practices

### 1. Start with High-Impact Controls

Focus first on governance controls that cascade to others:

```bash
# Essential governance documents
nisify submit --control GV.PO-01 --type security_policy --file infosec-policy.pdf
nisify submit --control GV.RR-01 --type governance_charter --file security-charter.pdf
nisify submit --control GV.RM-03 --type risk_register --file risk-register.xlsx
```

### 2. Refresh Evidence Periodically

Manual evidence ages just like automated evidence. Set reminders to update:

- **Quarterly**: Board minutes, KPI reports, risk reviews
- **Annually**: Policies, risk registers, BCP/DR plans
- **After events**: Incident reports, lessons learned

### 3. Use URLs for Living Documents

For documents in SharePoint, Confluence, or Notion:

```bash
nisify submit --control GV.PO-01 \
  --type security_policy \
  --url https://company.sharepoint.com/sites/security/policy.pdf \
  --description "Latest approved version in SharePoint"
```

### 4. Track Evidence in Your Workflow

Many of these evidence types come from existing processes:

- **GRC Tools**: Export risk registers, compliance tracking
- **Ticketing Systems**: Export incident response records
- **Document Management**: Link to policy repositories
- **Meeting Notes**: Board minutes, review meeting notes

### 5. Automate Where Possible

Some "manual" evidence can be scripted:

```bash
# Export from your GRC tool
./export-risk-register.sh > risk-register-$(date +%Y%m%d).xlsx
nisify submit --control GV.RM-03 --type risk_register --file risk-register-*.xlsx

# Schedule monthly updates
0 0 1 * * /path/to/update-manual-evidence.sh
```

## Viewing Manual Evidence in Dashboard

After submitting manual evidence, run the dashboard to see updated scores:

```bash
nisify dashboard
# Open http://127.0.0.1:8080 in your browser
```

The dashboard shows:

- **Maturity scores** that include both automated and manual evidence
- **Evidence explorer** filtering by `platform=manual`
- **Gap analysis** highlighting controls still missing evidence
- **Historical trends** showing improvement over time

## FAQ

### Why can't these controls be automated?

NIST CSF 2.0 includes controls for:

- **Governance processes** (board accountability, budget allocation)
- **Documentation requirements** (policies, procedures, plans)
- **Human activities** (training, awareness, HR practices)
- **Strategic decisions** (risk appetite, resource priorities)

These are organizational capabilities that exist in documents and processes, not in API-accessible systems.

### Is 36% automation actually useful?

Yes. The automated 36% covers:

- **Continuous monitoring** of technical controls
- **Real-time visibility** into access, assets, and security findings
- **Freshness tracking** that alerts when evidence ages
- **Trend analysis** showing improvement over time

The manual 64% changes infrequently (policies update annually, board meets quarterly). Automating the frequently-changing technical controls provides the most value.

### How often should I update manual evidence?

| Evidence Type | Typical Refresh |
|--------------|-----------------|
| Board minutes | Quarterly |
| Risk register | Quarterly |
| Policies | Annually |
| Training records | After each training cycle |
| Vendor assessments | Annually per vendor |
| Audit reports | After each audit |
| Incident reports | After each incident |

### Can I bulk-import manual evidence?

Yes, you can script submissions:

```bash
#!/bin/bash
# bulk-submit.sh
nisify submit --control GV.PO-01 --type security_policy --file policies/infosec.pdf
nisify submit --control GV.PO-02 --type policy_review_log --file policies/review-log.xlsx
nisify submit --control GV.RR-01 --type governance_charter --file governance/charter.pdf
nisify submit --control GV.RR-02 --type raci_matrix --file governance/raci.xlsx
# ... continue for all manual evidence
```

### What file formats are supported?

- **JSON**: Parsed and stored with full content
- **Text files** (.txt, .md, .yaml, .yml): Content stored as text
- **Binary files** (PDF, Excel, etc.): SHA-256 hash stored, file referenced

For binary files, the evidence record includes the file path and hash for audit purposes.
