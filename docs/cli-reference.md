# CLI Reference

Complete command reference for the Nisify command-line interface.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `--config PATH` | Override configuration file location |
| `-v, --verbose` | Increase output verbosity (can be repeated: -vv, -vvv) |
| `-q, --quiet` | Suppress non-essential output |
| `--version` | Show version number and exit |
| `--help` | Show help message and exit |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (general failure) |
| 2 | Invalid arguments |

---

## Commands

### nisify info

Show system information and diagnostics.

```bash
nisify info [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

**What it shows:**
- Nisify version and Python version
- Configuration and data directory paths
- Initialization and credential store status
- Enabled platforms
- Optional dependency status (weasyprint)
- Storage statistics (evidence counts, sizes)

**Example:**
```bash
$ nisify info
Nisify System Information
============================================================

Version: 0.1.0
Python: 3.11.5
Platform: macOS-14.2-arm64-arm-64bit

Paths:
  Config directory: /Users/user/.nisify
  Data directory: /Users/user/.nisify/data

Status:
  Initialized: Yes
  Credential store: locked
  Platforms enabled: aws, okta

Optional Dependencies:
  weasyprint: installed

Storage Statistics:
  Total evidence items: 1,234
  Collection runs: 45
  Maturity snapshots: 180
  Database size: 2.45 MB
  Evidence files: 45.67 MB
  Evidence by platform:
    aws: 678
    okta: 556
  Last collection:
    aws: 2024-01-15T02:00:00
    okta: 2024-01-15T02:00:00
```

**JSON Output:**
```bash
$ nisify info --json
{
  "version": "0.1.0",
  "python_version": "3.11.5",
  "platform": "macOS-14.2-arm64-arm-64bit",
  "config_dir": "/Users/user/.nisify",
  "initialized": true,
  "credential_store": "locked",
  "data_dir": "/Users/user/.nisify/data",
  "platforms_configured": ["aws", "okta"],
  "optional_dependencies": {
    "weasyprint": true
  },
  "storage": {
    "total_evidence": 1234,
    "total_runs": 45,
    "total_snapshots": 180,
    "database_size_mb": 2.45,
    "evidence_size_mb": 45.67
  }
}
```

---

### nisify init

Initialize Nisify configuration directory and credential store.

```bash
nisify init
```

**What it does:**
- Creates `~/.nisify/` directory structure
- Creates default `config.yaml`
- Initializes encrypted credential store
- Prompts for passphrase

**Example:**
```bash
$ nisify init
Initializing Nisify...
Enter a passphrase for credential encryption:
Confirm passphrase:
Configuration initialized at ~/.nisify/
```

---

### nisify configure

Configure platform credentials and settings.

#### nisify configure

Interactive configuration wizard.

```bash
nisify configure
```

**What it does:**
- Guides through platform configuration
- Prompts for credentials
- Tests connectivity
- Saves encrypted credentials

#### nisify configure set \<platform\>

Configure a specific platform.

```bash
nisify configure set <platform>
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `platform` | Platform to configure: aws, okta, jamf, google, snowflake, datadog |

**Example:**
```bash
$ nisify configure set aws
Configuring AWS credentials...
AWS Access Key ID: AKIA...
AWS Secret Access Key: ****
Testing connection...
AWS credentials configured successfully.
```

#### nisify configure unlock

Unlock the credential store for the current session.

```bash
nisify configure unlock
```

**What it does:**
- Prompts for passphrase
- Decrypts credentials
- Keeps credentials accessible for subsequent commands

#### nisify configure lock

Lock the credential store.

```bash
nisify configure lock
```

**What it does:**
- Clears decrypted credentials from memory
- Requires unlock for subsequent credential access

---

### nisify status

Show current configuration and collection status.

```bash
nisify status
```

**Output includes:**
- Configuration file location
- Enabled platforms
- Last collection times per platform
- Evidence counts
- Credential store status

**Example:**
```bash
$ nisify status
Nisify Status
==================================================

Configuration: ~/.nisify/config.yaml
Data Directory: ~/.nisify/data
Credential Store: Locked

Platforms:
  AWS: Enabled (last collection: 2024-01-15 02:00:00 UTC)
  Okta: Enabled (last collection: 2024-01-15 02:00:00 UTC)
  Jamf: Disabled
  Google: Disabled
  Snowflake: Disabled
  Datadog: Disabled

Evidence:
  Total items: 1,234
  Total size: 45.6 MB
```

---

### nisify collect

Collect evidence from configured platforms.

```bash
nisify collect [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--all` | Collect from all enabled platforms |
| `--platform PLATFORM` | Collect from specific platform |

`--all` and `--platform` are mutually exclusive.

**Examples:**
```bash
# Collect from all enabled platforms
$ nisify collect --all

# Collect from AWS only
$ nisify collect --platform aws

# Collect with verbose output
$ nisify collect --all -v
```

**Output:**
```bash
$ nisify collect --all
Collecting evidence...

AWS:
  security_findings: 45 items
  password_policy: 1 item
  mfa_status: 12 items
  access_keys: 24 items
  audit_logging: 3 items
  Collection time: 15.2s

Okta:
  user_inventory: 156 items
  mfa_status: 156 items
  access_logs: 1,000 items
  Collection time: 8.5s

Collection complete.
Total: 1,397 items from 2 platforms
```

---

### nisify maturity

Calculate and display NIST CSF 2.0 maturity scores.

```bash
nisify maturity [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--detailed` | Show subcategory-level breakdown |
| `--function FUNC` | Filter by function (GV, ID, PR, DE, RS, RC) |
| `--json` | Output as JSON |

**Examples:**
```bash
# Show summary
$ nisify maturity

# Show detailed breakdown
$ nisify maturity --detailed

# Filter to Protect function
$ nisify maturity --function PR

# JSON output
$ nisify maturity --json > maturity.json
```

**Output:**
```bash
$ nisify maturity
NIST CSF 2.0 Maturity Assessment
==================================================

Overall Maturity: Level 2 (2.35)

By Function:
  GV (Govern):   Level 1 (1.20)
  ID (Identify): Level 2 (1.80)
  PR (Protect):  Level 3 (2.95)
  DE (Detect):   Level 2 (2.45)
  RS (Respond):  Level 1 (1.15)
  RC (Recover):  Level 1 (0.85)

Evidence: 1,234 items from 2 platforms
Last collection: 2024-01-15 02:00:00 UTC
```

---

### nisify gaps

Show gap analysis with prioritized recommendations.

```bash
nisify gaps [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--priority LEVEL` | Filter by priority: critical, high, medium, low |
| `--function FUNC` | Filter by function |
| `--quick-wins` | Show only quick wins (low effort, high impact) |
| `--json` | Output as JSON |

**Examples:**
```bash
# Show all gaps
$ nisify gaps

# Show critical gaps only
$ nisify gaps --priority critical

# Show quick wins
$ nisify gaps --quick-wins

# Filter to Detect function
$ nisify gaps --function DE
```

**Output:**
```bash
$ nisify gaps --priority critical
Critical Gaps
==================================================

PR.AC-01: Identities and credentials are managed
  Priority: Critical
  Current Level: 1
  Target Level: 3
  Gap Type: partial_evidence
  Recommendation: Enable MFA enforcement across all platforms

DE.CM-01: Networks are monitored for potential adverse events
  Priority: Critical
  Current Level: 0
  Target Level: 3
  Gap Type: no_evidence
  Recommendation: Deploy network monitoring solution

Total: 2 critical gaps
```

---

### nisify report

Generate compliance reports.

```bash
nisify report [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--format FORMAT` | Output format: pdf, html, json (default: pdf) |
| `--output PATH` | Output file path |
| `--company NAME` | Company name for report header |

**Examples:**
```bash
# Generate PDF report
$ nisify report --format pdf --output report.pdf

# Generate HTML report
$ nisify report --format html --output report.html

# Generate JSON report
$ nisify report --format json --output report.json

# With company name
$ nisify report --format pdf --company "Acme Corp" --output acme-report.pdf
```

**Output:**
```bash
$ nisify report --format pdf --output compliance-report.pdf
Generating PDF report...
Report saved to: compliance-report.pdf
```

**Report Contents:**
- Cover page with organization and date
- Executive summary
- Overall maturity score
- Function-by-function breakdown
- Gap analysis
- Evidence summary
- Recommendations

---

### nisify export

Export evidence and analysis data.

```bash
nisify export [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--type TYPE` | Export type: full, evidence, maturity, gaps (default: full) |
| `--output PATH` | Output file path |
| `--compress` | Compress output with gzip |
| `--start-date DATE` | Filter evidence from date (YYYY-MM-DD) |
| `--end-date DATE` | Filter evidence to date (YYYY-MM-DD) |

**Examples:**
```bash
# Full export
$ nisify export --type full --output export.json

# Evidence only
$ nisify export --type evidence --output evidence.json

# Compressed export
$ nisify export --type full --output export.json.gz --compress

# Date-filtered export
$ nisify export --type evidence --start-date 2024-01-01 --output jan-evidence.json
```

---

### nisify dashboard

Start the local web dashboard.

```bash
nisify dashboard [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--port PORT` | Server port (default: 8080) |
| `--host HOST` | Server host (default: 127.0.0.1) |

**Examples:**
```bash
# Start dashboard on default port
$ nisify dashboard

# Start on custom port
$ nisify dashboard --port 9000
```

**Output:**
```bash
$ nisify dashboard
Starting dashboard server...
Dashboard available at: http://127.0.0.1:8080
Press Ctrl+C to stop.
```

**Notes:**
- Dashboard binds to localhost only by default (security)
- Terminal is blocked while dashboard runs
- Data is loaded at startup; restart to see new data

---

### nisify schedule

Configure automated evidence collection.

```bash
nisify schedule [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--interval INTERVAL` | Collection interval: hourly, daily, weekly |
| `--enable` | Enable scheduled collection |
| `--disable` | Disable scheduled collection |
| `--start-daemon` | Start the built-in scheduler daemon |
| `--stop-daemon` | Stop the scheduler daemon |
| `--foreground` | Run daemon in foreground (with --start-daemon) |
| `--logs` | Show recent scheduler logs |
| `--cron-help` | Show cron schedule syntax help |

**Examples:**
```bash
# Show current schedule status
$ nisify schedule

# Enable daily collection
$ nisify schedule --interval daily --enable

# Start scheduler daemon
$ nisify schedule --start-daemon

# Stop scheduler daemon
$ nisify schedule --stop-daemon

# View scheduler logs
$ nisify schedule --logs

# Disable scheduling
$ nisify schedule --disable
```

**Output:**
```bash
$ nisify schedule
Scheduler Status
==================================================

Status: ENABLED
Interval: daily
Mode: built_in

Next run: 2024-01-16 02:00:00 UTC
Last run: 2024-01-15 02:00:00 UTC
Last result: SUCCESS
```

**Schedule Times:**
- Hourly: Every hour at minute 0
- Daily: 2:00 AM UTC
- Weekly: Sunday at 2:00 AM UTC

---

### nisify test-connection

Test connectivity to a specific platform.

```bash
nisify test-connection <platform>
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `platform` | Platform to test: aws, okta, jamf, google, snowflake, datadog |

**Examples:**
```bash
$ nisify test-connection aws
Testing AWS connection...
AWS connection successful.
  Account: 123456789012
  Regions: us-east-1, us-west-2

$ nisify test-connection okta
Testing Okta connection...
Okta connection successful.
  Organization: acmecorp
  Domain: acmecorp.okta.com
```

**Exit Codes:**
- 0: Connection successful
- 1: Connection failed

---

### nisify cleanup

Clean up old evidence based on retention policy.

```bash
nisify cleanup [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--days N` | Override retention days (default: from config) |
| `--dry-run` | Show what would be deleted without deleting |
| `--force` | Skip confirmation prompt |

**What it does:**
- Identifies evidence older than retention period
- Archives old evidence to compressed files (optional)
- Deletes old evidence files and database records
- Never deletes maturity snapshots (needed for trends)

**Examples:**
```bash
# Preview cleanup with default retention (365 days)
$ nisify cleanup --dry-run

# Clean up with confirmation
$ nisify cleanup

# Clean up evidence older than 90 days
$ nisify cleanup --days 90

# Clean up without confirmation prompt
$ nisify cleanup --force
```

**Output:**
```bash
$ nisify cleanup --dry-run
Evidence Cleanup
==================================================

Retention period: 365 days
Data directory: ~/.nisify/data

Analyzing evidence for cleanup...

Files to remove: 45
Total size: 12,345,678 bytes (11.77 MB)

Dry run - no files will be deleted.

Files that would be removed:
  /home/user/.nisify/data/evidence/aws/2023-01-15/mfa_status_abc123.json (365 days old)
  ...
```

---

## Common Workflows

### Initial Setup

```bash
# Initialize configuration
nisify init

# Configure platforms
nisify configure set aws
nisify configure set okta

# Test connections
nisify test-connection aws
nisify test-connection okta

# Run first collection
nisify collect --all

# View maturity
nisify maturity
```

### Daily Operations

```bash
# Check status
nisify status

# Run collection
nisify collect --all

# View gaps
nisify gaps --priority critical

# Generate report
nisify report --format pdf --output weekly-report.pdf
```

### Scheduled Collection

```bash
# Enable daily schedule
nisify schedule --interval daily --enable

# Set passphrase environment variable
export NISIFY_PASSPHRASE="your-passphrase"

# Start daemon
nisify schedule --start-daemon

# Check status
nisify schedule

# View logs
nisify schedule --logs
```

### Audit Preparation

```bash
# Full export for auditor
nisify export --type full --output audit-export.json

# Generate PDF report
nisify report --format pdf --company "Acme Corp" --output audit-report.pdf

# Detailed maturity breakdown
nisify maturity --detailed --json > maturity-detail.json
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NISIFY_CONFIG` | Configuration file path |
| `NISIFY_DATA_DIR` | Data directory path |
| `NISIFY_LOG_LEVEL` | Logging verbosity |
| `NISIFY_PASSPHRASE` | Passphrase for credential decryption |

---

## Troubleshooting

### Credential Store Locked

```
Error: Credential store is locked. Run 'nisify configure unlock' first.
```

Solution: Run `nisify configure unlock` and enter your passphrase.

### Platform Not Configured

```
Error: Platform 'aws' is not configured.
```

Solution: Run `nisify configure set aws` to configure credentials.

### No Evidence Collected

```
Warning: No evidence collected from AWS.
```

Possible causes:
- Platform not enabled in config.yaml
- Invalid credentials
- Insufficient permissions

### Connection Timeout

```
Error: Connection timeout for Okta.
```

Possible causes:
- Network connectivity issues
- Firewall blocking API access
- Incorrect domain configured
