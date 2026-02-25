---
name: awsspectre
description: AWS resource waste auditor — finds idle, orphaned, and oversized resources costing money for nothing
user-invocable: false
metadata: {"requires":{"bins":["awsspectre"]}}
---

# awsspectre -- AWS Resource Waste Auditor

Scans AWS accounts for idle, orphaned, and oversized resources. Reports estimated monthly waste in USD for each finding.

## Install

```bash
go install github.com/ppiankov/awsspectre/cmd/awsspectre@latest
```

## Commands

### awsspectre scan

Scan AWS resources for waste across all enabled regions.

**Flags:**
- `--regions` -- comma-separated region filter
- `--all-regions` -- scan all enabled regions (default: true)
- `--idle-days` -- lookback window for utilization metrics (default: 7)
- `--stale-days` -- age threshold for snapshots (default: 90)
- `--min-monthly-cost` -- minimum monthly cost to report (default: $1.00)
- `--format` -- output format: text, json, sarif, spectrehub (default: text)
- `-o, --output` -- output file path (default: stdout)
- `--profile` -- AWS profile name
- `--no-progress` -- disable progress output
- `--timeout` -- scan timeout (default: 10m)

**JSON output:**
```json
{
  "$schema": "spectre/v1",
  "tool": "awsspectre",
  "version": "0.1.0",
  "timestamp": "2026-02-25T12:00:00Z",
  "target": {
    "type": "aws-account",
    "uri_hash": "sha256:abc123..."
  },
  "config": {
    "regions": ["us-east-1"],
    "idle_days": 7,
    "stale_days": 90,
    "min_monthly_cost": 1.0
  },
  "findings": [
    {
      "id": "IDLE_EC2",
      "severity": "high",
      "resource_type": "ec2",
      "resource_id": "i-0abc123def456",
      "resource_name": "web-server",
      "region": "us-east-1",
      "message": "CPU 2.3% over 7 days",
      "estimated_monthly_waste": 50.0,
      "metadata": {
        "instance_type": "t3.large",
        "avg_cpu_percent": 2.3,
        "state": "running"
      }
    }
  ],
  "summary": {
    "total_resources_scanned": 150,
    "total_findings": 5,
    "total_monthly_waste": 250.0,
    "by_severity": {"high": 3, "medium": 1, "low": 1},
    "by_resource_type": {"ec2": 2, "rds": 1, "ebs": 1, "eip": 1},
    "regions_scanned": 3
  }
}
```

**Exit codes:**
- 0: scan completed (findings may or may not be present)
- 1: error (credentials, permissions, network)

### awsspectre init

Generate `.awsspectre.yaml` config file and `awsspectre-policy.json` IAM policy.

### awsspectre version

Print version, commit hash, and build date.

## What this does NOT do

- Does not modify or delete AWS resources -- read-only auditing only
- Does not store AWS credentials -- uses standard SDK credential chain
- Does not require admin access -- works with read-only IAM policy
- Does not use ML or probabilistic analysis -- deterministic metric thresholds
- Does not provide rightsizing recommendations -- only flags underutilization
- Does not calculate exact costs -- estimates based on embedded on-demand pricing

## Parsing examples

```bash
# List all findings sorted by waste
awsspectre scan --format json | jq '.findings | sort_by(-.estimated_monthly_waste) | .[] | "\(.resource_id) \(.estimated_monthly_waste)"'

# Total monthly waste
awsspectre scan --format json | jq '.summary.total_monthly_waste'

# Findings by resource type
awsspectre scan --format json | jq '.summary.by_resource_type'

# High-severity findings only
awsspectre scan --format json | jq '[.findings[] | select(.severity == "high")]'

# EC2 instances with CPU below 5%
awsspectre scan --format json | jq '[.findings[] | select(.id == "IDLE_EC2")] | .[] | {id: .resource_id, name: .resource_name, cpu: .metadata.avg_cpu_percent}'
```
