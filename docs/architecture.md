# Nisify Architecture

This document describes the system architecture of Nisify, a NIST CSF 2.0 compliance evidence aggregation tool.

## High-Level System Overview

Nisify follows a modular, pipeline architecture where data flows from cloud platforms through collection, storage, analysis, and presentation layers. Each component is independent and can be tested or replaced without affecting others.

```
                                    NISIFY ARCHITECTURE
    
    +------------------------------------------------------------------+
    |                        EXTERNAL PLATFORMS                         |
    |  +--------+  +-------+  +------+  +--------+  +-----------+      |
    |  |  AWS   |  | Okta  |  | Jamf |  | Google |  | Snowflake |      |
    |  +---+----+  +---+---+  +--+---+  +---+----+  +-----+-----+      |
    |      |           |         |          |             |             |
    +------------------------------------------------------------------+
           |           |         |          |             |
           +-----------+---------+----------+-------------+
                                 |
                    Read-Only API Calls (HTTPS)
                                 |
                                 v
    +------------------------------------------------------------------+
    |                      COLLECTION LAYER                             |
    |  +------------------------------------------------------------+  |
    |  |                    Collector Registry                       |  |
    |  |  +------------+ +------------+ +------------+ +----------+  |  |
    |  |  |   AWS      | |   Okta     | |   Jamf     | | Datadog  |  |  |
    |  |  | Collector  | | Collector  | | Collector  | | Collector|  |  |
    |  |  +-----+------+ +-----+------+ +-----+------+ +----+-----+  |  |
    |  +------------------------------------------------------------+  |
    |                            |                                      |
    |              Normalized Evidence (JSON)                           |
    +------------------------------------------------------------------+
                                 |
                                 v
    +------------------------------------------------------------------+
    |                       STORAGE LAYER                               |
    |  +---------------------------+  +-----------------------------+   |
    |  |     SQLite Database       |  |    File Storage             |   |
    |  |  - collection_runs        |  |  - Raw evidence (JSON)      |   |
    |  |  - evidence_items         |  |  - Organized by date/type   |   |
    |  |  - control_mappings       |  |  - SHA-256 integrity hashes |   |
    |  |  - maturity_snapshots     |  |                             |   |
    |  +---------------------------+  +-----------------------------+   |
    +------------------------------------------------------------------+
                                 |
                                 v
    +------------------------------------------------------------------+
    |                      ANALYSIS LAYER                               |
    |  +-------------------+  +------------------+  +----------------+  |
    |  |  Mapping Engine   |  |    Maturity      |  |     Gap        |  |
    |  |  Evidence -> NIST |  |   Calculator     |  |   Analyzer     |  |
    |  |  Control Mapping  |  |  Score (0-4)     |  |  Recommendations|  |
    |  +-------------------+  +------------------+  +----------------+  |
    +------------------------------------------------------------------+
                                 |
                                 v
    +------------------------------------------------------------------+
    |                    PRESENTATION LAYER                             |
    |  +----------------+  +----------------+  +--------------------+   |
    |  |      CLI       |  |   Dashboard    |  |     Reports        |   |
    |  | (All commands) |  | (localhost)    |  | (PDF, JSON, HTML)  |   |
    |  +----------------+  +----------------+  +--------------------+   |
    +------------------------------------------------------------------+
```

## Component Descriptions

### Collection Layer

The collection layer is responsible for authenticating with external platforms and gathering evidence artifacts. Each collector is a self-contained module that implements the `BaseCollector` interface.

**Base Collector Interface:**
- `collect()` - Execute evidence collection and return normalized results
- `test_connection()` - Verify credentials and connectivity
- `get_required_permissions()` - Document minimum required permissions
- `normalize_evidence()` - Convert platform-specific data to common schema

**Collector Registry:**
The registry maintains a list of available collectors and handles discovery, instantiation, and parallel execution. Collectors can fail independently without blocking others.

**Rate Limiting and Retry:**
Each collector implements platform-specific rate limiting with exponential backoff retry logic. API calls are throttled to respect platform limits.

### Storage Layer

The storage layer provides persistent storage for collected evidence and computed results.

**SQLite Database Schema:**

```
+-------------------+     +------------------+     +-------------------+
| collection_runs   |     | evidence_items   |     | control_mappings  |
+-------------------+     +------------------+     +-------------------+
| id (PK)           |<-+  | id (PK)          |<-+  | id (PK)           |
| timestamp         |  |  | collection_run_id|--+  | evidence_id (FK)  |
| platform          |  +--| evidence_type    |     | control_id        |
| success           |     | platform         |     | confidence        |
| duration          |     | collected_at     |     | status            |
| error_count       |     | file_path        |     | explanation       |
+-------------------+     | metadata_json    |     +-------------------+
                          | hash             |
                          +------------------+
                                   |
                                   v
                          +-------------------+
                          | maturity_snapshots|
                          +-------------------+
                          | id (PK)           |
                          | timestamp         |
                          | entity_id         |
                          | entity_type       |
                          | maturity_level    |
                          | score             |
                          | evidence_count    |
                          +-------------------+
```

**File Storage Structure:**

```
~/.nisify/
    config.yaml
    credentials.enc
    salt
    data/
        evidence/
            aws/
                2024-01-15/
                    security_findings.json
                    mfa_status.json
                    access_keys.json
                2024-01-16/
                    ...
            okta/
                2024-01-15/
                    access_logs.json
                    user_inventory.json
                    ...
        nisify.db
    logs/
        nisify.log
        scheduler.log
    reports/
        ...
```

### Analysis Layer

The analysis layer processes stored evidence to produce actionable compliance insights.

**Mapping Engine:**
Applies deterministic rules to map evidence types to NIST CSF 2.0 controls. Mappings are defined in configuration files and are fully auditable. No machine learning or probabilistic inference is used.

**Maturity Calculator:**
Computes maturity levels (0-4) based on evidence presence, freshness, and completeness. The algorithm is documented and reproducible.

**Gap Analyzer:**
Identifies controls lacking sufficient evidence and generates prioritized recommendations. Gaps are categorized by severity and effort required to close.

### Presentation Layer

The presentation layer provides interfaces for users to interact with Nisify.

**CLI:**
Command-line interface for all operations including collection, analysis, and reporting. Uses Python argparse with no external dependencies.

**Dashboard:**
Local web interface served on localhost. Built with Python's http.server module and vanilla JavaScript. Provides visualizations of maturity scores, gaps, and trends.

**Reports:**
Generates exportable reports in PDF (board-ready), JSON (machine-readable), and HTML formats.

## Data Flow

### Evidence Collection Flow

```
1. User runs: nisify collect --all
                    |
                    v
2. CLI loads configuration and credentials
                    |
                    v
3. Collector Registry instantiates enabled collectors
                    |
                    v
4. Each collector executes in sequence:
   a. Authenticate with platform API
   b. Execute read-only API calls
   c. Parse and normalize responses
   d. Return CollectionResult
                    |
                    v
5. Evidence Store persists results:
   a. Save collection run metadata to SQLite
   b. Write raw evidence to JSON files
   c. Calculate and store integrity hashes
                    |
                    v
6. CLI outputs collection summary
```

### Analysis Flow

```
1. User runs: nisify maturity
                    |
                    v
2. Evidence Store retrieves latest evidence
                    |
                    v
3. Mapping Engine processes evidence:
   a. Load mapping rules from configuration
   b. Match evidence types to NIST controls
   c. Calculate mapping confidence
   d. Generate ControlMapping results
                    |
                    v
4. Maturity Calculator computes scores:
   a. Calculate subcategory scores
   b. Roll up to category scores
   c. Roll up to function scores
   d. Calculate overall score
                    |
                    v
5. Store maturity snapshot for trend tracking
                    |
                    v
6. Output results (table or JSON)
```

### Report Generation Flow

```
1. User runs: nisify report --format pdf
                    |
                    v
2. Load current maturity scores
                    |
                    v
3. Run gap analysis
                    |
                    v
4. Load historical trends
                    |
                    v
5. PDF Generator builds report:
   a. Render cover page
   b. Render executive summary
   c. Render maturity details
   d. Render gap analysis
   e. Render evidence appendix
                    |
                    v
6. Save PDF to output path
```

## Security Architecture

### Credential Protection

```
+------------------+     +-------------------+     +------------------+
|  User Passphrase |---->|  PBKDF2 Key       |---->|  Fernet Key      |
|                  |     |  Derivation       |     |                  |
+------------------+     |  (100k iterations)|     +------------------+
                         +-------------------+              |
                                                           v
                                                  +------------------+
                                                  | Encrypt/Decrypt  |
                                                  | Credentials      |
                                                  +------------------+
                                                           |
                                                           v
                                                  +------------------+
                                                  | credentials.enc  |
                                                  | (encrypted file) |
                                                  +------------------+
```

### API Permission Model

All platform integrations use the minimum required read-only permissions:

| Platform   | Permission Scope                          | Access Level |
|------------|-------------------------------------------|--------------|
| AWS        | SecurityAudit managed policy              | Read-only    |
| Okta       | okta.users.read, okta.logs.read           | Read-only    |
| Jamf Pro   | Auditor role                              | Read-only    |
| Google     | Reports API, Directory API (read)         | Read-only    |
| Snowflake  | SELECT on ACCOUNT_USAGE                   | Read-only    |
| Datadog    | Read-only API key                         | Read-only    |

### Network Security

```
+------------------+                              +------------------+
|     Nisify       |------- HTTPS Only --------->|  Platform APIs   |
|  (local machine) |                              |  (AWS, Okta...)  |
+------------------+                              +------------------+
        |
        | localhost only (default)
        v
+------------------+
|    Dashboard     |
|  (port 8080)     |
+------------------+
```

No outbound connections except to configured platform APIs. No telemetry, no update checks, no external services.

## NIST CSF 2.0 Mapping Model

### Control Hierarchy

```
NIST CSF 2.0 Structure:

Functions (6)
    |
    +-- Categories (22)
            |
            +-- Subcategories (106)

Example:
PROTECT (PR)
    |
    +-- Access Control (PR.AC)
            |
            +-- PR.AC-01: Identities and credentials managed
            +-- PR.AC-02: Physical access managed
            +-- PR.AC-03: Remote access managed
            +-- PR.AC-04: Access permissions managed
            +-- PR.AC-05: Network integrity protected
```

### Evidence to Control Mapping

```
Evidence Type             NIST Controls
-----------------         ------------------------
mfa_status        ------> PR.AC-01, PR.AC-03
access_logs       ------> DE.CM-01, DE.CM-03
user_inventory    ------> ID.AM-01, PR.AC-01
security_findings ------> DE.AE-02, RS.AN-01
encryption_status ------> PR.DS-01, PR.DS-02
```

### Maturity Scoring Algorithm

```
Level 0: score = 0.0
    No evidence collected for this control

Level 1: score = 1.0 - 1.9
    Partial evidence OR evidence older than 2x freshness threshold
    
Level 2: score = 2.0 - 2.9
    Full evidence with some staleness OR manual evidence only

Level 3: score = 3.0 - 3.9
    Automated evidence collection, fresh, complete coverage

Level 4: score = 4.0
    Level 3 + demonstrated improvement over time + advanced automation
```

## Deployment Model

Nisify is designed for single-machine deployment:

```
+--------------------------------------------------+
|                 User Workstation                  |
|                                                   |
|  +--------------------------------------------+  |
|  |               Nisify Process               |  |
|  |                                            |  |
|  |  +----------+  +----------+  +----------+  |  |
|  |  |   CLI    |  | Dashboard|  | Scheduler|  |  |
|  |  +----------+  +----------+  +----------+  |  |
|  |                                            |  |
|  +--------------------------------------------+  |
|                       |                          |
|  +--------------------------------------------+  |
|  |              Local Storage                 |  |
|  |  ~/.nisify/                                |  |
|  |    config.yaml, credentials.enc,           |  |
|  |    data/, logs/, reports/                  |  |
|  +--------------------------------------------+  |
+--------------------------------------------------+
```

No server infrastructure required. No database server. No container orchestration. Just Python and a filesystem.

## Design Decisions

### Why SQLite?

SQLite provides ACID transactions, SQL querying, and zero configuration. It is embedded in Python and requires no external database server. For single-tenant compliance tooling, SQLite offers the right balance of capability and simplicity.

### Why No Framework for Dashboard?

Using Python's built-in http.server eliminates external dependencies, reduces attack surface, and makes the codebase easier to audit. The dashboard is intentionally simple and does not require the complexity of Flask, Django, or FastAPI.

### Why Deterministic Scoring?

Compliance decisions must be explainable and reproducible. Auditors expect to understand exactly why a control received its maturity score. Machine learning models, while potentially more sophisticated, would make this explanation impossible.

### Why Read-Only?

Nisify collects evidence. It does not remediate issues. This separation of concerns reduces risk, simplifies permissions, and makes the tool safe to run in any environment.
