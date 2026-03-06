## Philosophy

*Principiis obsta* -- resist the beginnings.

Compute and storage are 50-70% of every AWS bill, and every account has waste. The longer idle resources sit, the harder they are to identify and the more they cost. AWSSpectre surfaces these conditions early -- in scheduled audits, in CI, in cost reviews -- so they can be addressed before they compound.

The tool presents evidence and lets humans decide. It does not auto-terminate instances, does not guess intent, and does not use ML where deterministic checks suffice.


## Installation

```bash
# Homebrew
brew install ppiankov/tap/awsspectre

# Docker
docker pull ghcr.io/ppiankov/awsspectre:latest

# From source
git clone https://github.com/ppiankov/awsspectre.git
cd awsspectre && make build
```


## Usage

```bash
awsspectre scan [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--regions` | | Comma-separated region filter |
| `--all-regions` | `true` | Scan all enabled regions |
| `--idle-days` | `7` | Lookback window for utilization metrics |
| `--stale-days` | `90` | Age threshold for snapshots |
| `--min-monthly-cost` | `1.0` | Minimum monthly cost to report ($) |
| `--idle-cpu-threshold` | `5.0` | CPU % below which a resource is idle |
| `--high-memory-threshold` | `50.0` | Memory % above which a resource is not idle |
| `--stopped-threshold-days` | `30` | Days stopped before flagging EC2 |
| `--nat-gw-low-traffic-gb` | `1.0` | NAT Gateway monthly GB below which to flag as low traffic |
| `--exclude-tags` | | Exclude resources by tag (`Key=Value` or `Key`, comma-separated) |
| `--format` | `text` | Output format: `text`, `json`, `sarif`, `spectrehub` |
| `-o, --output` | stdout | Output file path |
| `--profile` | | AWS profile name |
| `--no-progress` | `false` | Disable progress output |
| `--timeout` | `10m` | Scan timeout |

**Other commands:**

| Command | Description |
|---------|-------------|
| `awsspectre init` | Generate `.awsspectre.yaml` config and IAM policy |
| `awsspectre version` | Print version, commit, and build date |


## Configuration

AWSSpectre reads `.awsspectre.yaml` from the current directory:

```yaml
regions:
  - us-east-1
  - eu-west-1
idle_days: 14
stale_days: 180
min_monthly_cost: 5.0
format: json
exclude:
  resource_ids:
    - i-0abc123def456
    - vol-0abc123def456
  tags:
    - "Environment=production"
    - "awsspectre:ignore"
```

Generate a sample config with `awsspectre init`.


## IAM permissions

AWSSpectre requires read-only access. Run `awsspectre init` to generate the minimal IAM policy, or attach these permissions:

- `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeSnapshots`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeNatGateways`, `ec2:DescribeImages`, `ec2:DescribeRegions`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`
- `rds:DescribeDBInstances`
- `lambda:ListFunctions`
- `kinesis:ListStreams`, `kinesis:DescribeStreamSummary`
- `firehose:ListDeliveryStreams`
- `sqs:ListQueues`, `sqs:GetQueueAttributes`
- `sns:ListTopics`, `sns:ListSubscriptionsByTopic`
- `cloudwatch:GetMetricData`


## Output formats

**Text** (default): Human-readable table with severity, resource, region, waste, and message.

**JSON** (`--format json`): `spectre/v1` envelope with findings and summary:
```json
{
  "$schema": "spectre/v1",
  "tool": "awsspectre",
  "version": "0.1.0",
  "findings": [...],
  "summary": {
    "total_resources_scanned": 150,
    "total_findings": 5,
    "total_monthly_waste": 250.00
  }
}
```

**SARIF** (`--format sarif`): SARIF v2.1.0 for GitHub Security tab integration.

**SpectreHub** (`--format spectrehub`): `spectre/v1` envelope for SpectreHub ingestion.


## Architecture

```
awsspectre/
├── cmd/awsspectre/main.go         # Entry point (22 lines, LDFLAGS)
├── internal/
│   ├── commands/                  # Cobra CLI: scan, init, version
│   ├── aws/                       # AWS SDK v2 clients + 13 resource scanners
│   │   ├── types.go               # Finding, Severity, ResourceType, ScanConfig
│   │   ├── client.go              # AWS config loader, region discovery
│   │   ├── cloudwatch.go          # Batched GetMetricData (up to 500 queries/call)
│   │   ├── scanner.go             # MultiRegionScanner orchestrator
│   │   ├── ec2.go                 # EC2: idle CPU, stopped instances
│   │   ├── ebs.go                 # EBS: detached volumes
│   │   ├── eip.go                 # EIP: unassociated addresses
│   │   ├── elb.go                 # ALB/NLB: zero targets, zero requests
│   │   ├── natgw.go               # NAT Gateway: zero bytes processed
│   │   ├── rds.go                 # RDS: idle CPU, no connections
│   │   ├── snapshot.go            # Snapshots: old, no AMI reference
│   │   ├── secgroup.go            # Security groups: no attached ENIs
│   │   ├── lambda.go              # Lambda: zero invocations
│   │   ├── kinesis.go             # Kinesis: idle streams, over-provisioned shards, idle Firehose
│   │   ├── sqs.go                 # SQS: idle queues, no-consumer, orphaned DLQs
│   │   └── sns.go                 # SNS: no subscribers, idle topics
│   ├── pricing/                   # Embedded on-demand pricing (go:embed)
│   ├── analyzer/                  # Filter by min cost, compute summary
│   └── report/                    # Text, JSON, SARIF, SpectreHub reporters
├── Makefile
└── go.mod
```

Key design decisions:

- `cmd/awsspectre/main.go` is minimal -- a single `Execute()` call with LDFLAGS version injection.
- All logic lives in `internal/` to prevent external import.
- Each resource type has its own scanner implementing `ResourceScanner` interface.
- CloudWatch uses batched `GetMetricData` API (up to 500 queries per call) for efficiency.
- Two-level bounded concurrency: max 4 regions, max 10 API calls per region.
- Pricing data is embedded via `go:embed` with curated on-demand rates, falling back to us-east-1 for unknown regions.
- Scanner errors are collected, not fatal -- one scanner failure does not abort the whole scan.


## Project Status

**Status: Beta** · **v0.1.0** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| 13 resource scanners (EC2, EBS, EIP, ALB, NLB, NAT GW, RDS, Lambda, Kinesis, Firehose, SQS, SNS, snapshots, security groups) | Complete |
| Multi-region parallel scanning with bounded concurrency | Complete |
| Embedded on-demand pricing with per-finding cost estimates | Complete |
| 4 output formats (text, JSON, SARIF, SpectreHub) | Complete |
| Config file + init command with IAM policy generation | Complete |
| CI pipeline (test/lint/build) | Complete |
| Homebrew + Docker distribution | Complete |
| Test coverage >85% | Complete |
| API stability guarantees | Partial |
| v1.0 release | Planned |

Pre-1.0: CLI flags and config schemas may change between minor versions. JSON output structure (`spectre/v1`) is stable.


## Known limitations

- **Approximate pricing.** Cost estimates use embedded on-demand rates, not your actual pricing (reserved instances, savings plans, spot). Treat estimates as directional, not exact.
- **CloudWatch data lag.** Metrics may take up to 15 minutes to appear. Very recently provisioned resources may not have enough data for idle detection.
- **No cross-account support.** Scans a single AWS account at a time.
- **No rightsizing.** Flags underutilized resources but does not recommend smaller instance types.
- **Security group references.** Only checks ENI attachment and in-rules cross-references. Does not trace through nested group chains.
- **Snapshot AMI check.** Only validates against AMIs owned by the account. Shared AMIs referencing the snapshot will not be detected.
- **Single metric thresholds.** CPU < 5% is a simple heuristic. Some workloads (batch, cron) may appear idle but are not.

