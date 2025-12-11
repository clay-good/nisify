# Dashboard API Reference

This document describes the REST API endpoints provided by the Nisify dashboard server.

## Overview

The dashboard server provides a JSON API for accessing maturity scores, gaps, evidence, and trends. All endpoints return JSON responses.

**Base URL**: `http://127.0.0.1:8080` (default)

## Starting the Server

```bash
nisify dashboard [--port PORT] [--host HOST]
```

The server binds to localhost by default for security.

## Authentication

The dashboard API has no authentication. It is designed for local access only.

**Security Note**: Do not expose the dashboard to a network. The API provides read access to all evidence and maturity data.

## Response Format

All successful responses return JSON:

```json
{
    "status": "success",
    "data": { ... }
}
```

Error responses:

```json
{
    "status": "error",
    "error": "Error message"
}
```

## Endpoints

### Health Check

Check if the server is running.

```
GET /api/health
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "healthy": true,
        "timestamp": "2024-01-15T12:00:00Z"
    }
}
```

---

### Summary

Get high-level summary statistics.

```
GET /api/summary
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "overall_maturity": {
            "level": 2,
            "score": 2.35
        },
        "evidence_count": 1234,
        "platforms_enabled": 3,
        "last_collection": "2024-01-15T02:00:00Z",
        "critical_gaps": 5,
        "functions": {
            "GV": {"level": 1, "score": 1.2},
            "ID": {"level": 2, "score": 1.8},
            "PR": {"level": 3, "score": 2.95},
            "DE": {"level": 2, "score": 2.45},
            "RS": {"level": 1, "score": 1.15},
            "RC": {"level": 1, "score": 0.85}
        }
    }
}
```

---

### Maturity Scores

Get detailed maturity scores.

```
GET /api/maturity
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `function` | string | Filter by function ID (GV, ID, PR, DE, RS, RC) |
| `level` | string | Filter by level (category, subcategory) |

**Response:**
```json
{
    "status": "success",
    "data": {
        "timestamp": "2024-01-15T12:00:00Z",
        "overall": {
            "entity_id": "overall",
            "entity_type": "overall",
            "level": 2,
            "score": 2.35,
            "evidence_count": 1234,
            "confidence": 0.85
        },
        "by_function": {
            "GV": {
                "entity_id": "GV",
                "entity_type": "function",
                "level": 1,
                "score": 1.2,
                "evidence_count": 45,
                "confidence": 0.7
            }
        },
        "by_category": {
            "GV.OC": {
                "entity_id": "GV.OC",
                "entity_type": "category",
                "level": 2,
                "score": 1.5,
                "evidence_count": 15,
                "confidence": 0.75
            }
        },
        "by_subcategory": {
            "GV.OC-01": {
                "entity_id": "GV.OC-01",
                "entity_type": "subcategory",
                "level": 2,
                "score": 2.0,
                "evidence_count": 5,
                "confidence": 0.8
            }
        }
    }
}
```

**Examples:**
```bash
# All maturity data
curl http://127.0.0.1:8080/api/maturity

# Filter by function
curl http://127.0.0.1:8080/api/maturity?function=PR

# Get categories only
curl http://127.0.0.1:8080/api/maturity?level=category
```

---

### Gap Analysis

Get gap analysis with recommendations.

```
GET /api/gaps
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `priority` | string | Filter by priority: critical, high, medium, low |
| `function` | string | Filter by function ID |
| `type` | string | Filter by gap type: no_evidence, stale_evidence, partial_evidence, low_maturity |
| `limit` | integer | Maximum number of gaps to return |

**Response:**
```json
{
    "status": "success",
    "data": {
        "total_gaps": 45,
        "by_priority": {
            "critical": 5,
            "high": 12,
            "medium": 18,
            "low": 10
        },
        "gaps": [
            {
                "control_id": "PR.AC-01",
                "control_name": "Identities and credentials are managed",
                "function_id": "PR",
                "category_id": "PR.AC",
                "current_level": 1,
                "target_level": 3,
                "gap_type": "partial_evidence",
                "priority": "critical",
                "recommendation": "Enable MFA enforcement across all platforms",
                "evidence_found": ["user_inventory"],
                "evidence_missing": ["mfa_status"]
            }
        ]
    }
}
```

**Examples:**
```bash
# All gaps
curl http://127.0.0.1:8080/api/gaps

# Critical gaps only
curl http://127.0.0.1:8080/api/gaps?priority=critical

# Gaps in Protect function
curl http://127.0.0.1:8080/api/gaps?function=PR

# Top 10 gaps
curl http://127.0.0.1:8080/api/gaps?limit=10
```

---

### Evidence

Get collected evidence.

```
GET /api/evidence
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `platform` | string | Filter by platform: aws, okta, jamf, google, snowflake, datadog |
| `type` | string | Filter by evidence type |
| `start_date` | string | Filter from date (ISO 8601) |
| `end_date` | string | Filter to date (ISO 8601) |
| `limit` | integer | Maximum items (default: 100) |
| `offset` | integer | Pagination offset |

**Response:**
```json
{
    "status": "success",
    "data": {
        "total": 1234,
        "items": [
            {
                "id": "abc123",
                "platform": "aws",
                "evidence_type": "mfa_status",
                "collected_at": "2024-01-15T02:00:00Z",
                "item_count": 12,
                "file_hash": "sha256:...",
                "metadata": {
                    "region": "us-east-1"
                }
            }
        ],
        "pagination": {
            "limit": 100,
            "offset": 0,
            "total": 1234
        }
    }
}
```

**Examples:**
```bash
# All evidence
curl http://127.0.0.1:8080/api/evidence

# AWS evidence only
curl http://127.0.0.1:8080/api/evidence?platform=aws

# MFA status evidence
curl http://127.0.0.1:8080/api/evidence?type=mfa_status

# Paginated results
curl http://127.0.0.1:8080/api/evidence?limit=50&offset=100
```

---

### Evidence Detail

Get raw data for a specific evidence item.

```
GET /api/evidence/{id}
```

**Response:**
```json
{
    "status": "success",
    "data": {
        "id": "abc123",
        "platform": "aws",
        "evidence_type": "mfa_status",
        "collected_at": "2024-01-15T02:00:00Z",
        "raw_data": {
            "users": [
                {"id": "user1", "mfa_enabled": true},
                {"id": "user2", "mfa_enabled": false}
            ]
        },
        "metadata": {
            "region": "us-east-1",
            "collector_version": "1.0.0"
        }
    }
}
```

---

### Trends

Get historical maturity trends.

```
GET /api/trends
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `function` | string | Filter by function ID |
| `days` | integer | Number of days of history (default: 30) |

**Response:**
```json
{
    "status": "success",
    "data": {
        "period": {
            "start": "2023-12-15T00:00:00Z",
            "end": "2024-01-15T00:00:00Z"
        },
        "overall": [
            {
                "date": "2023-12-15",
                "level": 2,
                "score": 2.1
            },
            {
                "date": "2024-01-15",
                "level": 2,
                "score": 2.35
            }
        ],
        "by_function": {
            "PR": [
                {
                    "date": "2023-12-15",
                    "level": 2,
                    "score": 2.5
                },
                {
                    "date": "2024-01-15",
                    "level": 3,
                    "score": 2.95
                }
            ]
        },
        "trend_analysis": {
            "overall": "improving",
            "by_function": {
                "GV": "stable",
                "ID": "improving",
                "PR": "improving",
                "DE": "stable",
                "RS": "regressing",
                "RC": "stable"
            }
        }
    }
}
```

**Examples:**
```bash
# 30-day trends
curl http://127.0.0.1:8080/api/trends

# 90-day trends
curl http://127.0.0.1:8080/api/trends?days=90

# Protect function trends
curl http://127.0.0.1:8080/api/trends?function=PR
```

---

### Functions

Get NIST CSF 2.0 function definitions.

```
GET /api/functions
```

**Response:**
```json
{
    "status": "success",
    "data": [
        {
            "id": "GV",
            "name": "Govern",
            "description": "Establish and monitor the organization's cybersecurity risk management strategy...",
            "category_count": 4
        },
        {
            "id": "ID",
            "name": "Identify",
            "description": "Understand the organization's current cybersecurity risk posture...",
            "category_count": 4
        }
    ]
}
```

---

### Categories

Get NIST CSF 2.0 category definitions.

```
GET /api/categories
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `function` | string | Filter by function ID |

**Response:**
```json
{
    "status": "success",
    "data": [
        {
            "id": "PR.AC",
            "function_id": "PR",
            "name": "Identity Management, Authentication, and Access Control",
            "description": "Access to assets and associated facilities is limited...",
            "subcategory_count": 6
        }
    ]
}
```

---

### Subcategories

Get NIST CSF 2.0 subcategory definitions.

```
GET /api/subcategories
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `function` | string | Filter by function ID |
| `category` | string | Filter by category ID |

**Response:**
```json
{
    "status": "success",
    "data": [
        {
            "id": "PR.AC-01",
            "category_id": "PR.AC",
            "function_id": "PR",
            "description": "Identities and credentials are issued, managed, verified...",
            "evidence_types": ["user_inventory", "mfa_status"],
            "requires_manual_evidence": false
        }
    ]
}
```

---

### Controls (Alias)

Alias for subcategories endpoint.

```
GET /api/controls
```

Same parameters and response as `/api/subcategories`.

---

## Error Handling

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 404 | Resource not found |
| 500 | Internal server error |

### Error Response

```json
{
    "status": "error",
    "error": "Evidence item not found: abc123"
}
```

---

## Rate Limits

The dashboard server has no rate limiting. It is designed for local, single-user access.

---

## CORS

The server does not include CORS headers. API is intended for same-origin requests from the dashboard frontend.

---

## Examples

### cURL

```bash
# Get summary
curl http://127.0.0.1:8080/api/summary

# Get maturity scores as JSON
curl http://127.0.0.1:8080/api/maturity | jq

# Get critical gaps
curl "http://127.0.0.1:8080/api/gaps?priority=critical"

# Get AWS evidence
curl "http://127.0.0.1:8080/api/evidence?platform=aws&limit=10"
```

### Python

```python
import requests

BASE_URL = "http://127.0.0.1:8080"

# Get summary
response = requests.get(f"{BASE_URL}/api/summary")
data = response.json()
print(f"Overall maturity: Level {data['data']['overall_maturity']['level']}")

# Get gaps
response = requests.get(f"{BASE_URL}/api/gaps", params={"priority": "critical"})
gaps = response.json()["data"]["gaps"]
for gap in gaps:
    print(f"{gap['control_id']}: {gap['recommendation']}")

# Get evidence
response = requests.get(
    f"{BASE_URL}/api/evidence",
    params={"platform": "aws", "type": "mfa_status"}
)
evidence = response.json()["data"]["items"]
```

### JavaScript

```javascript
const BASE_URL = "http://127.0.0.1:8080";

// Get summary
fetch(`${BASE_URL}/api/summary`)
    .then(response => response.json())
    .then(data => {
        console.log(`Overall: Level ${data.data.overall_maturity.level}`);
    });

// Get gaps
fetch(`${BASE_URL}/api/gaps?priority=critical`)
    .then(response => response.json())
    .then(data => {
        data.data.gaps.forEach(gap => {
            console.log(`${gap.control_id}: ${gap.recommendation}`);
        });
    });
```

---

## Limitations

1. **No authentication**: Anyone with network access can query data
2. **No HTTPS**: Traffic is unencrypted (localhost assumed)
3. **No rate limiting**: No protection against excessive requests
4. **Single-threaded**: Concurrent requests queue sequentially
5. **No caching**: Data loaded fresh on each request
6. **No WebSocket**: No real-time updates
