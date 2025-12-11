# Nisify 

**Testify to your NIST maturity with evidence to prove it.**

Nisify is a NIST CSF 2.0 compliance evidence aggregation tool that connects to your cloud platforms, collects evidence artifacts, and maps them to NIST controls to demonstrate your compliance maturity. Automate what changes frequently, document what changes rarely, and track both in one dashboard.

## The Problem

Organizations pursuing NIST CSF 2.0 compliance face a painful reality:

**Manual evidence gathering is time-consuming and error-prone.** Security teams spend weeks compiling screenshots, exporting logs, and filling spreadsheets before each audit. Evidence becomes stale the moment it is collected.

**Expensive GRC platforms do too much.** Enterprise compliance tools cost six figures annually, require dedicated administrators, and bundle features most organizations never use. They often support dozens of frameworks when you only need one.

**No visibility into actual compliance posture.** Without continuous evidence collection, organizations cannot answer basic questions: "Are we compliant today?" "Where are our gaps?" "Are we improving or regressing?"

---

## The Solution

Nisify does one thing well: aggregate evidence from your existing cloud platforms and map it to NIST CSF 2.0 controls.

**NIST-first design.** Built exclusively for NIST CSF 2.0. Not SOC 2 with NIST bolted on. Every feature serves NIST compliance.

**Evidence aggregation focus.** Connects to 13 platforms you already use (AWS, Okta, Jamf, Google, Snowflake, Datadog, GitLab, Jira, Zendesk, Zoom, Notion, Slab, SpotDraft) and pulls evidence via read-only APIs.

**Transparent, deterministic scoring.** No machine learning. No black boxes. Every maturity score can be traced to specific evidence and explicit rules. Auditors can understand exactly why a control received its score.

**Zero vendor lock-in.** Export everything. JSON, PDF, raw evidence files. Your data is yours. Migrate away anytime.

**Read-only, secure by design.** Nisify never modifies your infrastructure. All API calls are read-only. Credentials are encrypted at rest. No telemetry, no phone home.

---

## Understanding NIST CSF 2.0 Coverage

NIST CSF 2.0 has **106 subcategories** (controls) across 6 functions. Nisify provides **100% mapping coverage** - every control has defined evidence requirements. However, not all evidence can be collected automatically.

### Why Only 36% Can Be Automated

| Category | Controls | Examples | Why |
|----------|----------|----------|-----|
| **API-Collectible (36%)** | 38 | MFA status, device inventory, access logs, security findings | Data exists in platforms with APIs |
| **Manual Evidence (64%)** | 68 | Board minutes, risk registers, policies, training records | Governance and organizational processes exist in documents, not APIs |

**This is inherent to NIST CSF 2.0, not a tool limitation.** The framework covers:

- **Technical controls** (Protect, Detect) - Often automatable
- **Governance controls** (Govern) - Require board decisions, policies, budgets
- **Process controls** (Identify, Respond, Recover) - Require documented procedures

No compliance tool can fully automate NIST CSF 2.0 because the framework intentionally covers organizational governance that exists outside of technical systems.

### Evidence Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NIST CSF 2.0 (106 Controls)                     │
├───────────────────────────────────┬─────────────────────────────────────┤
│     API-COLLECTIBLE (38)          │        MANUAL EVIDENCE (68)         │
│                                   │                                     │
│  nisify collect --all             │  nisify submit --control GV.PO-01   │
│         │                         │         │                           │
│         ▼                         │         ▼                           │
│  ┌─────────────────┐              │  ┌─────────────────┐                │
│  │ AWS, Okta, Jamf │              │  │ Policy docs,    │                │
│  │ Google, GitLab  │              │  │ Board minutes,  │                │
│  │ Jira, Datadog.. │              │  │ Risk registers  │                │
│  └────────┬────────┘              │  └────────┬────────┘                │
│           │                       │           │                         │
│           └───────────┬───────────┴───────────┘                         │
│                       ▼                                                 │
│              ┌────────────────┐                                         │
│              │ Evidence Store │  ← All evidence stored together        │
│              └────────┬───────┘                                         │
│                       ▼                                                 │
│              ┌────────────────┐                                         │
│              │ Mapping Engine │  ← Maps to controls by evidence type   │
│              └────────┬───────┘                                         │
│                       ▼                                                 │
│              ┌────────────────┐                                         │
│              │   Dashboard    │  ← Shows unified maturity score        │
│              └────────────────┘                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### What Nisify Automates vs What You Provide

| Nisify Automates | You Provide |
|------------------|-------------|
| Collecting from 13 platforms | Policy documents (PDF, Word) |
| Mapping evidence to controls | Board/committee meeting minutes |
| Calculating maturity scores | Risk registers and assessments |
| Tracking trends over time | Training completion records |
| Identifying gaps | Incident response plans |
| Generating reports | Vendor assessment reports |
| Freshness tracking | HR security policies |

### The Value Proposition

**Without Nisify:**
- Manual screenshot collection before audits
- No visibility between audit cycles
- Stale evidence by the time audits happen
- No trend tracking
- 100% manual effort for all 106 controls

**With Nisify:**
- 36% fully automated with continuous collection
- Real-time visibility into technical controls
- Automatic freshness tracking and alerts
- Historical trends show improvement/regression
- 64% still manual, but tracked in same dashboard

The automated portion covers the **high-change** evidence (access logs, MFA status, device inventory) that would otherwise require constant manual collection. The manual portion covers **low-change** evidence (policies, governance docs) that typically updates quarterly or annually.

---

## How It Works

```
Cloud Platforms (AWS, Okta, Jamf, Google, Snowflake, Datadog, GitLab, Jira, Zendesk, Zoom, Notion, Slab, SpotDraft)
                            |
                  Read-Only API Calls
                            |
                            v
                   +----------------+
                   |   Collectors   |
                   | (per platform) |
                   +----------------+
                            |
                  Normalized Evidence
                            |
                            v
                   +----------------+
                   | Evidence Store |
                   | (SQLite + JSON)|
                   +----------------+
                            |
                            v
                   +----------------+
                   | Mapping Engine |
                   | (Evidence ->   |
                   |  NIST Controls)|
                   +----------------+
                            |
                            v
                   +----------------+
                   |   Maturity     |
                   |  Calculator    |
                   +----------------+
                            |
                            v
              +-------------+-------------+
              |             |             |
              v             v             v
         +--------+   +---------+   +----------+
         |  CLI   |   |Dashboard|   | Reports  |
         +--------+   +---------+   +----------+
```

1. **Configure** platforms with read-only credentials
2. **Collect** evidence on a schedule (hourly, daily, weekly)
3. **Map** evidence to NIST CSF 2.0 controls automatically
4. **Score** maturity levels (0-4) per control, category, and function
5. **Identify** gaps with actionable recommendations
6. **Report** to stakeholders and auditors

---

## Quick Demo (No Credentials Required)

Try Nisify immediately with realistic sample data:

```bash
# Install from source
git clone https://github.com/clay-good/nisify.git
cd nisify
pip install -e .

# Generate demo data and start dashboard in one command
nisify demo --dashboard
```

This creates 30 days of sample evidence from AWS, Okta, Jamf, and Google Workspace, then opens the dashboard at http://127.0.0.1:8080.

**Demo Profiles:**
- `--profile startup` - Small company with basic security (many gaps)
- `--profile growing` - Mid-size company with moderate security (default)
- `--profile mature` - Large enterprise with strong security (few gaps)

```bash
# Example: Demo a startup's compliance posture
nisify demo --profile startup --organization "My Startup Inc." --dashboard
```

---

## Quick Start (Production Use)

```bash
# Install from PyPI (not yet published)
pip install nisify

# Or install from source
git clone https://github.com/clay-good/nisify.git
cd nisify
pip install -e .

# Initialize configuration
nisify init

# Configure a platform (interactive)
nisify configure

# Test connectivity
nisify test-connection aws

# Run evidence collection
nisify collect --all

# View maturity scores
nisify maturity

# View gaps
nisify gaps

# Generate report
nisify report --format pdf --output compliance-report.pdf

# Start dashboard
nisify dashboard
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `nisify info` | Show system information and diagnostics |
| `nisify init` | Initialize configuration directory and settings |
| `nisify configure` | Interactive configuration and credential setup |
| `nisify status` | Show configuration status and last collection times |
| `nisify collect` | Run evidence collection from configured platforms |
| `nisify maturity` | Calculate and display NIST CSF 2.0 maturity scores |
| `nisify gaps` | Show gap analysis with prioritized recommendations |
| `nisify report` | Generate compliance reports (PDF, JSON, HTML) |
| `nisify export` | Export evidence and analysis data |
| `nisify dashboard` | Start local web dashboard |
| `nisify dashboard --background` | Start dashboard in background |
| `nisify dashboard --stop` | Stop background dashboard |
| `nisify dashboard --status` | Check if dashboard is running |
| `nisify schedule` | Configure automated evidence collection |
| `nisify schedule --enable` | Enable scheduled collection |
| `nisify schedule --disable` | Disable scheduled collection |
| `nisify schedule --start-daemon` | Start the built-in scheduler daemon |
| `nisify schedule --stop-daemon` | Stop the built-in scheduler daemon |
| `nisify schedule --logs` | Show recent scheduler logs |
| `nisify test-connection` | Test connectivity to a specific platform |
| `nisify cleanup` | Clean up old evidence based on retention policy |
| `nisify cleanup --dry-run` | Preview what would be cleaned up |
| `nisify demo` | Generate demo data for quick evaluation |
| `nisify demo --dashboard` | Generate demo data and start dashboard |
| `nisify submit --control ID --type TYPE --url URL` | Submit manual evidence with URL reference |
| `nisify submit --control ID --type TYPE --file PATH` | Submit manual evidence file |
| `nisify submit --list-types` | List available evidence types for manual submission |
| `nisify backup` | Create a backup archive of all Nisify data |
| `nisify restore` | Restore from a backup archive |

Global options:
- `--config PATH` - Override configuration file location
- `-v, --verbose` - Increase output verbosity
- `-q, --quiet` - Suppress non-essential output
- `--version` - Show version number

Output formatting (available on `status`, `maturity`, and `gaps` commands):
- `--format table` - Human-readable table output (default)
- `--format json` - JSON output for scripting/automation
- `--format csv` - CSV output for spreadsheets/analysis

---

## Supported Platforms

Nisify supports 13 cloud platforms for automated evidence collection:

### Core Platforms
| Platform | Evidence Types | Required Permissions |
|----------|---------------|---------------------|
| AWS | Security Hub findings, IAM configuration, CloudTrail status, Config rules, S3 encryption | SecurityAudit managed policy |
| Okta | User directory, MFA status, system logs, security policies | okta.users.read, okta.logs.read, okta.policies.read |
| Jamf Pro | Device inventory, FileVault status, compliance EA, configuration profiles | Auditor role |
| Google Workspace | Admin audit logs, directory users, 2SV status, security settings | Admin SDK (read-only) |
| Snowflake | Access history, query history, login history, user/role configuration | SELECT on ACCOUNT_USAGE |
| Datadog | Security signals, monitoring rules, monitors, audit trail | Read-only API key |

### Development & Collaboration Platforms
| Platform | Evidence Types | Required Permissions |
|----------|---------------|---------------------|
| GitLab | Projects, users, audit events, MR approvals, protected branches, access tokens | api or read_api, read_user, read_repository |
| Jira | Projects, users, audit logs, permission schemes, security issues | Browse Projects, Administer Jira |
| Notion | Users, databases, pages, access permissions, audit logs (Enterprise) | Internal integration token |
| Slab | Users, posts, topics, access/sharing permissions | API token |

### Communication & Support Platforms
| Platform | Evidence Types | Required Permissions |
|----------|---------------|---------------------|
| Zoom | Users, meeting security, recording settings, security config, access logs | Server-to-Server OAuth: user:read:admin, meeting:read:admin |
| Zendesk | Users, audit logs, security settings, tickets, groups/roles | Admin access |

### Contract Management
| Platform | Evidence Types | Required Permissions |
|----------|---------------|---------------------|
| SpotDraft | Users, contracts, templates, audit logs | API access (contact SpotDraft) |

---

## Deterministic Logic

Nisify uses **no machine learning or LLMs** for scoring or analysis.

Every maturity score is calculated using explicit, documented rules:
- Evidence type X maps to NIST control Y (defined in configuration)
- Evidence freshness affects confidence (configurable thresholds)
- Maturity levels (0-4) are assigned based on evidence presence, completeness, and age

You can trace any score back to:
1. The specific evidence items that contributed
2. The mapping rules that connected evidence to controls
3. The scoring algorithm that calculated the maturity level

This transparency is essential for auditor acceptance and organizational trust.

---

## Extending Mappings

Nisify maps all 106 NIST CSF 2.0 subcategories with configurable evidence-to-control mappings. You can customize these mappings by editing `data/control_evidence_mappings.json`.

### Mapping Configuration Format

Each mapping specifies which evidence types satisfy a control:

```json
{
  "control_id": "PR.AC-01",
  "required_evidence_types": ["user_inventory", "mfa_status"],
  "optional_evidence_types": ["access_logs"],
  "platforms": ["okta", "aws", "google"],
  "logic": "all_required",
  "freshness_days": 30,
  "description": "Identity management requires user inventory and MFA configuration"
}
```

### Mapping Fields

| Field | Description | Required |
|-------|-------------|----------|
| `control_id` | NIST CSF 2.0 subcategory ID (e.g., "PR.AC-01") | Yes |
| `required_evidence_types` | Evidence types that must be present | Yes |
| `optional_evidence_types` | Evidence that improves confidence score | No |
| `platforms` | Which platforms can provide this evidence | No |
| `logic` | How to combine evidence (see below) | No (default: all_required) |
| `freshness_days` | Days before evidence is stale | No (default: 30) |
| `description` | Human-readable explanation | No |

### Logic Types

- **`all_required`**: All evidence types in `required_evidence_types` must be present
- **`any_required`**: At least one evidence type from `required_evidence_types` must be present
- **`weighted`**: Evidence contributes proportionally based on configured weights

### Example: Adding a New Mapping

To map control `GV.OC-03` (Legal, regulatory, and contractual requirements understood):

```json
{
  "control_id": "GV.OC-03",
  "required_evidence_types": ["contract_inventory"],
  "optional_evidence_types": ["audit_logs", "security_policies"],
  "platforms": ["spotdraft"],
  "logic": "all_required",
  "freshness_days": 90,
  "description": "Legal/regulatory requirements tracked via contract management"
}
```

### Available Evidence Types

Evidence types collected by each platform:

| Platform | Evidence Types |
|----------|---------------|
| AWS | security_findings, password_policy, mfa_status, access_keys, audit_logging, config_compliance, data_protection, detection_rules, ha_config |
| Okta | user_inventory, mfa_status, access_logs, security_policies, access_assignments |
| Jamf | device_inventory, encryption_status, endpoint_compliance, software_inventory, security_configurations, hardware_lifecycle, maintenance_records |
| Google | user_inventory, mfa_status, access_logs, device_inventory |
| GitLab | project_inventory, user_inventory, audit_logs, change_management, branch_protection, access_tokens |
| Jira | project_inventory, user_inventory, audit_logs, access_control, incident_tracking, improvement_plan, remediation_tracking |
| Zendesk | user_inventory, audit_logs, security_config, incident_tracking, access_control |
| Zoom | user_inventory, meeting_security, data_protection, security_config, access_logs |
| Notion | user_inventory, data_inventory, access_control, audit_logs |
| Slab | user_inventory, data_inventory, topic_structure, access_control |
| SpotDraft | user_inventory, contract_inventory, template_inventory, audit_logs |
| Snowflake | user_inventory, access_policies, authentication_logs, access_logs, data_access_logs |
| Datadog | security_findings, detection_rules, monitoring_coverage, audit_logs, log_retention, threat_register, capacity_monitoring |

### Manual Evidence Controls

All 106 NIST CSF 2.0 subcategories have mapping configurations. 38 controls (36%) can be satisfied via automated API collection. 68 controls (64%) require manual evidence submission for governance, policies, and organizational processes that cannot be pulled from APIs.

**This is by design.** NIST CSF 2.0 includes controls for board accountability, risk registers, HR practices, and incident response plans - these exist in documents, not APIs.

Manual evidence submitted via `nisify submit`:
- **Stores in the same evidence system** as automated collections
- **Maps to controls** during maturity calculations
- **Reflects in dashboard scores** alongside API-collected evidence
- **Ages like any evidence** - refresh periodically

```bash
nisify submit --control GV.PO-01 --type security_policy --file security-policy.pdf
nisify submit --control GV.RR-01 --type board_minutes --url https://docs.company.com/board/2024-q4
nisify submit --list-types  # View all supported evidence types
```

See **[Manual Evidence Guide](docs/manual-evidence.md)** for the complete list of controls requiring manual evidence and best practices for collection.

---

## Safety Guarantees

**Read-only operations only.** Nisify never modifies your infrastructure. All platform API calls are GET/LIST operations.

**Credentials encrypted at rest.** API tokens and passwords are encrypted using Fernet with PBKDF2-SHA256 key derivation (600,000 iterations per OWASP 2023 recommendations). Minimum 12-character passphrase required. Credential files have 0600 permissions (owner-only).

**No external network calls.** Nisify contacts only the platform APIs you configure. No telemetry, no update checks, no analytics.

**Local dashboard.** The web dashboard binds to localhost by default. No external access.

**Audit trail.** Every collection run and action is logged with timestamps for your own audit needs.

---

## Running Tests

The test suite uses Python's built-in unittest module (no pytest required).

```bash
# Run all tests
python -m unittest discover tests/

# Run specific test file
python -m unittest tests/test_collectors.py

# Run with verbose output
python -m unittest discover tests/ -v
```

**Test Files:**
| File | Description |
|------|-------------|
| tests/test_collectors.py | Platform collector tests with mocked API responses |
| tests/test_mapping.py | Evidence-to-control mapping tests |
| tests/test_scoring.py | Maturity level calculation tests |
| tests/test_cli.py | CLI argument parsing and command tests |
| tests/test_storage.py | Evidence persistence and integrity tests |

---

## Installation

**Requirements:**
- Python 3.11 or higher
- pip

**From PyPI (not yet available):**
```bash
pip install nisify
```

**From source:**
```bash
git clone https://github.com/clay-good/nisify.git
cd nisify
pip install -e .
```

**Optional dependencies:**
```bash
# PDF report generation
pip install nisify[pdf]

# Snowflake collector
pip install nisify[snowflake]

# Google Workspace collector
pip install nisify[google]

# All optional features
pip install nisify[all]
```

---

## Limitations

This section describes the limitations of Nisify with complete honesty. Read this carefully before adopting the tool.

### Framework Limitations

- **NIST CSF 2.0 only.** Nisify does not support SOC 2, ISO 27001, HIPAA, PCI-DSS, FedRAMP, or any other compliance framework. There are no plans to add multi-framework support. If you need other frameworks, use a different tool.

- **No crosswalks.** Nisify does not map NIST controls to other framework controls. It does not help you satisfy multiple frameworks simultaneously.

### Platform Limitations

- **13 platforms supported.** Nisify supports AWS, Okta, Jamf Pro, Google Workspace, Snowflake, Datadog, GitLab, Jira, Zendesk, Zoom, Notion, Slab, and SpotDraft. Other platforms may be added in future releases.

- **No custom platform integrations.** Adding a new platform requires writing Python code. There is no plugin system or configuration-based connector framework.

- **No on-premises infrastructure support.** Nisify cannot collect evidence from servers, network devices, or applications that lack cloud APIs.

- **Platform API changes may break collectors.** If AWS, Okta, or other platforms change their APIs, collectors may stop working until updated.

### Evidence Limitations

- **Approximately 40% of NIST CSF 2.0 controls require manual evidence.** Many controls (especially in Govern, Identify, and Recover functions) require policy documents, training records, or other evidence that cannot be collected via API. Nisify will identify these gaps but cannot fill them automatically.

- **Evidence presence does not equal compliance.** Having an MFA policy does not mean MFA is enforced effectively. Having audit logs does not mean anyone reviews them. Nisify reports what exists, not whether it works.

- **Evidence quality is not assessed.** Nisify checks if evidence exists and how recent it is. It does not analyze whether the evidence demonstrates effective controls. A weak password policy and a strong password policy both count as "password policy evidence."

- **Point-in-time collection.** Evidence reflects the state at collection time. Changes between collections are not captured. Real-time monitoring is not supported.

### Scoring Limitations

- **Maturity scores are approximations.** The scoring algorithm uses heuristics based on evidence presence and freshness. Your auditor may disagree with the scores.

- **Scores may not match auditor expectations.** Different auditors apply different standards. Nisify's scores are internally consistent but may not align with external assessments.

- **No industry benchmarking.** Nisify cannot tell you how your scores compare to similar organizations. There is no anonymized data collection or benchmarking database.

- **Weighting is simplified.** All subcategories within a category are weighted equally by default. The actual importance of controls varies by organization and risk profile.

- **Level 4 (Optimized) is rarely achievable via automated evidence alone.** The highest maturity level requires demonstrated continuous improvement, which typically requires manual evidence and human judgment.

### Technical Limitations

- **Single-user, single-organization.** Nisify has no multi-tenant support. It runs on one machine for one organization. There is no shared dashboard, no role-based access control, no team features.

- **Dashboard is local-only.** The web dashboard runs on localhost. There is no option for remote access, authentication, or deployment as a web service.

- **No real-time monitoring.** Evidence is collected on a schedule (hourly at most frequent). There is no streaming, no webhooks, no immediate alerting.

- **Large environments may have slow collection.** Organizations with thousands of users, devices, or resources may experience long collection times. There is limited parallelization.

- **Snowflake queries consume compute credits.** Collecting evidence from Snowflake executes queries against ACCOUNT_USAGE views, which consume warehouse credits. Frequent collection increases costs.

- **SQLite scalability limits.** The evidence database uses SQLite, which is not designed for very large datasets. Multi-year evidence retention for large organizations may cause performance degradation.

### Operational Limitations

- **No auto-remediation.** Nisify identifies gaps but does not fix them. It will never modify your infrastructure, even to improve compliance.

- **No ticketing integration.** Gap recommendations are displayed in reports and the dashboard. There is no integration with Jira, ServiceNow, or other ticketing systems.

- **No notification system.** Nisify is designed as a local-only tool. There are no external notifications (Slack, email, SMS, PagerDuty). Check collection status via CLI or dashboard.

- **CLI-first design.** While there is a dashboard, most operations are performed via command line. There is no GUI for configuration.

### Compliance Limitations

- **Nisify does not make you compliant.** Using Nisify does not mean you pass an audit. Compliance requires implementing controls, not just collecting evidence.

- **Reports may not satisfy auditors.** Auditors may require evidence formats or details that Nisify does not provide. The PDF reports are informational, not audit artifacts.

- **No legal or certification value.** Nisify is not certified, validated, or approved by NIST or any certification body. Using it provides no legal protection.

- **No guarantee of audit success.** Organizations have failed audits despite using compliance tools. Evidence collection is necessary but not sufficient.

### Support Limitations

- **Open source with no SLA.** There is no guaranteed response time for issues. Support is community-based.

- **No professional services.** There is no consulting team to help with implementation, customization, or audit preparation.

### Current Development Limitations

- **Not production ready.** This is alpha software. All components are integrated but have not been tested against live APIs. There may be bugs in edge cases.

- **Tests use mocks only.** The test suite tests with mocked API responses, not real platform APIs. Tests verify internal logic but cannot catch issues with actual API integrations.

- **API may change.** Configuration file format, CLI arguments, and internal APIs may change without notice before 1.0.

- **Dependencies not vendored.** Relies on external packages (boto3, cryptography, requests, snowflake-connector-python) that may have their own security issues.

- **Limited error handling.** Edge cases and error conditions may not be handled gracefully.

- **No migration path.** If the database schema or configuration format changes, there is no automated migration tool.

- **Collectors not tested against live APIs.** The collector code is written according to API documentation but has not been tested against real platform APIs. There may be bugs in pagination, error handling, or data parsing.

- **Google Workspace requires service account setup.** The Google collector requires creating a service account with domain-wide delegation, which is a complex manual process.

- **Snowflake collector may incur costs.** Queries against ACCOUNT_USAGE views consume warehouse compute credits. Cost impact depends on warehouse size and collection frequency.

- **SQLite single-writer limitation.** The evidence storage uses SQLite which only allows one writer at a time. Concurrent collection runs from multiple processes may fail or block.

- **Storage not tested with large datasets.** The storage engine has not been tested with large evidence volumes. Performance may degrade with thousands of evidence files or millions of database rows.

- **Basic backup mechanism.** Built-in `nisify backup` and `nisify restore` commands create tar.gz archives with checksums. There is no automated backup scheduling, cloud sync, or incremental backups.

- **Mapping configurations not validated by auditors.** The evidence-to-control mappings are based on reasonable interpretation of NIST requirements. Auditors may disagree with specific mappings.

- **Maturity scores are heuristic approximations.** The MaturityCalculator uses configurable thresholds and modifiers (automation bonus, improvement bonus, coverage penalty) that are reasonable defaults but may not match your auditor's expectations.

- **Equal weighting by default.** All subcategories within a category, and all categories within a function, are weighted equally unless custom weights are provided. This may not reflect actual organizational risk priorities.

- **Improvement detection is simplistic.** The improvement bonus is awarded when current score exceeds previous score. This does not account for score volatility, temporary regressions, or measurement noise.

- **Freshness thresholds are arbitrary.** The default 30-day freshness threshold for stale evidence was chosen as a reasonable default. Your organization or auditor may have different expectations.

- **Level 4 requires near-perfect scores.** The default threshold for Level 4 (Optimized) is 3.5 out of 4.0, which is difficult to achieve via automated evidence alone. This is intentional but may frustrate users expecting achievable Level 4 scores.

- **Gap recommendations are generic.** Built-in recommendations cover common scenarios but may not match your specific environment or constraints. Custom recommendations require code changes.

- **Priority classification is heuristic.** Gap priorities are based on NIST function (Protect and Detect are critical by default) and maturity level. Your organization may have different risk priorities.

- **Trend analysis requires historical data.** Meaningful trends require at least 2 maturity snapshots. New deployments will show "insufficient data" until collection history accumulates.

- **Volatility detection is simplistic.** Controls are marked volatile if scores fluctuate significantly between snapshots. This may be normal behavior for some evidence types or may indicate data quality issues.

- **Quick wins may not be quick.** Gaps classified as "low effort" are based on typical scenarios. Actual effort depends on your environment, team expertise, and existing infrastructure.

- **PDF generation requires weasyprint.** PDF reports require the weasyprint library, which has system dependencies (cairo, pango, etc.). Without weasyprint, only HTML reports are generated.

- **Report styling is fixed.** PDF reports use a monochrome design that cannot be customized without code changes. Colors, fonts, and layout are hardcoded in CSS.

- **Executive summaries are templated.** Generated summaries use fixed templates and phrasing. The language may not match your organization's communication style.

- **No custom report templates.** Report structure is fixed (cover, executive summary, maturity, gaps, evidence). Adding or removing sections requires code changes.

- **JSON schemas are basic.** Export schemas provide structural validation only. They do not validate data correctness or completeness.

- **Large reports may fail.** Reports with thousands of gaps or evidence items may exceed memory limits or generate very large files. There is no pagination or chunking for large datasets.

### Dashboard Limitations

- **Local-only by design.** The dashboard binds to 127.0.0.1 by default. There is no authentication, HTTPS, or multi-user support. Exposing it to a network is insecure.

- **Auto-refresh, not real-time.** The dashboard supports auto-refresh (default 60 seconds) but does not have WebSocket-based real-time updates. Data updates require polling the API.

- **Vanilla JavaScript only.** The dashboard uses no frameworks (React, Vue, etc.) for simplicity. This limits interactivity and may feel dated compared to modern dashboards.

- **Canvas charts are basic.** Trend charts use the HTML5 Canvas API directly. There is no zoom, pan, or interactive features. Chart quality is limited compared to dedicated charting libraries.

- **No chart library.** To avoid external dependencies, charts are rendered with raw Canvas API. Complex visualizations (pie charts, stacked bars) are not implemented.

- **Mobile support is limited.** The responsive CSS handles basic mobile layouts but the experience is optimized for desktop browsers.

- **Evidence detail view is limited.** The evidence browser shows metadata but does not display full evidence content. Large evidence payloads are truncated.

- **Basic search functionality.** Global search (Ctrl+K) searches across controls, gaps, and evidence by ID and name. Full-text search of evidence content, advanced filters, and saved searches are not supported.

- **Single concurrent request handling.** The Python http.server is single-threaded. Simultaneous requests from multiple browser tabs may queue.

- **No caching headers for data.** API responses do not include cache headers. Browser caching behavior is undefined.

- **Template rendering is basic.** HTML templates use simple string replacement (`{{variable}}`). There is no conditional logic, loops, or escaping in templates. All dynamic content is handled via JavaScript.

### Scheduler Limitations

- **Requires passphrase for automated collection.** The scheduler needs access to encrypted credentials. For system cron, you must set the NISIFY_PASSPHRASE environment variable in your cron environment. For built-in daemon, you must start it with the passphrase or set the environment variable.

- **Passphrase storage is a security concern.** Storing the passphrase in an environment variable or passing it on the command line may expose it in process listings or shell history. There is no integration with system keyrings for scheduled execution.

- **System cron requires Unix-like system.** The cron integration only works on Linux, macOS, and other Unix-like systems with crontab command available. Windows users must use the built-in scheduler.

- **Built-in scheduler requires a running daemon.** The built-in scheduler runs as a daemon process. If the process dies, scheduled collection stops. There is no automatic restart, service management, or watchdog. Consider using systemd, launchd, or supervisord to manage the daemon.

- **Daemon runs in the same process.** The scheduler daemon runs collection in-process. If collection hangs or crashes, the daemon must be manually restarted.

- **Hourly collection may be too frequent.** Hourly collection from all platforms may hit API rate limits, incur costs (Snowflake), or generate excessive log data. Daily or weekly is recommended for most use cases.

- **Collection times are fixed.** Daily collection runs at 2:00 AM UTC, weekly on Sunday at 2:00 AM UTC. These times cannot be configured without modifying code.

- **No timezone support.** Schedule times are in UTC only. There is no configuration for local timezone.

- **No failure alerting.** When scheduled collection fails, errors are logged to the scheduler log file. Check logs with `nisify schedule --logs`. There are no external notification integrations.

- **Log rotation is basic.** Logs rotate when the file exceeds 5 MB, keeping 3 backups. There is no log compression, no time-based rotation, and no integration with system logging (journald, syslog).

- **State file is not encrypted.** The scheduler state file (~/.nisify/scheduler/state.json) contains schedule configuration and run history but not credentials. It is stored in plaintext.

- **PID file may become stale.** If the daemon process crashes without cleanup, the PID file may contain a stale PID. The scheduler attempts to detect and clean up stale PIDs but race conditions are possible.

- **No collection locking.** If you manually run `nisify collect` while the scheduler is running, both may try to write to the evidence store simultaneously. SQLite handles this but one may block or fail.

- **No retry on failure.** If a scheduled collection fails (platform API error, network issue), the scheduler does not retry. It waits for the next scheduled run.

- **Windows support untested.** The built-in scheduler should work on Windows but has not been tested. Signal handling and PID management may behave differently.

### Service File Examples

The following service files enable the Nisify scheduler daemon to run as a system service that starts automatically on boot and restarts on failure.

#### systemd (Linux)

Create `/etc/systemd/system/nisify-scheduler.service`:

```ini
[Unit]
Description=Nisify Evidence Collection Scheduler
After=network.target

[Service]
Type=simple
User=your-username
Environment="NISIFY_PASSPHRASE=your-secure-passphrase"
Environment="HOME=/home/your-username"
ExecStart=/usr/local/bin/nisify schedule --start-daemon --foreground
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable nisify-scheduler

# Start the service
sudo systemctl start nisify-scheduler

# Check status
sudo systemctl status nisify-scheduler

# View logs
sudo journalctl -u nisify-scheduler -f
```

#### launchd (macOS)

Create `~/Library/LaunchAgents/com.nisify.scheduler.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nisify.scheduler</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/nisify</string>
        <string>schedule</string>
        <string>--start-daemon</string>
        <string>--foreground</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NISIFY_PASSPHRASE</key>
        <string>your-secure-passphrase</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/nisify-scheduler.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/nisify-scheduler.err</string>
</dict>
</plist>
```

Load and start the service:

```bash
# Load the service (starts immediately and on login)
launchctl load ~/Library/LaunchAgents/com.nisify.scheduler.plist

# Unload the service
launchctl unload ~/Library/LaunchAgents/com.nisify.scheduler.plist

# Check if running
launchctl list | grep nisify

# View logs
tail -f /tmp/nisify-scheduler.log
```

**Security Note:** Storing the passphrase in service files is a security tradeoff. The passphrase is needed for automated credential decryption. Alternatives include:
- Using environment files with restricted permissions (systemd: `EnvironmentFile=/etc/nisify/env`)
- Using macOS Keychain with a helper script
- Accepting the risk for scheduled collection convenience

---

## Documentation

- [Architecture](docs/architecture.md) - System design and component overview
- [Configuration](docs/configuration.md) - Configuration file reference
- [Collectors](docs/collectors.md) - Platform-specific setup guides
- [Manual Evidence](docs/manual-evidence.md) - Guide for submitting evidence for the 68 controls requiring manual input
- [NIST Mapping](docs/nist-mapping.md) - Evidence-to-control mapping reference
- [CLI Reference](docs/cli-reference.md) - Complete command documentation
- [API Reference](docs/api-reference.md) - Dashboard API documentation
