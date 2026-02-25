# AWSSpectre

[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)
[![CI](https://github.com/ppiankov/awsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/awsspectre/actions/workflows/ci.yml)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AWS resource waste auditor. Finds idle, orphaned, and oversized resources costing money for nothing.

Part of the [Spectre family](https://github.com/ppiankov) of infrastructure cleanup tools.

## What it is

AWSSpectre scans your AWS account for resources that are running but not doing useful work. It checks CloudWatch metrics, attachment status, and usage patterns to identify waste across EC2, RDS, EBS, ELB, NAT Gateways, Elastic IPs, snapshots, and security groups. Each finding includes an estimated monthly cost so you can prioritize cleanup by dollar impact.

## What it is NOT

- Not a real-time monitoring tool. AWSSpectre is a point-in-time scanner, not a daemon.
- Not a remediation tool. It reports waste and lets you decide what to do.
- Not a security scanner. It checks for idle resources, not misconfigurations or vulnerabilities.
- Not a billing replacement. Cost estimates are approximations based on embedded on-demand pricing, not your actual discounted rates.
- Not a capacity planner. It flags underutilization, not rightsizing recommendations.

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

## Quick start

```bash
# Scan all enabled regions (default)
awsspectre scan

# Scan specific regions
awsspectre scan --regions us-east-1,eu-west-1

# JSON output for automation
awsspectre scan --format json --output report.json

# SARIF output for GitHub Security tab
awsspectre scan --format sarif --output results.sarif

# Use a specific AWS profile
awsspectre scan --profile production

# Generate config and IAM policy
awsspectre init
```

Requires valid AWS credentials (environment, profile, or IAM role).

## What it audits

| Resource | Finding | Signal | Severity |
|----------|---------|--------|----------|
| EC2 instances | `IDLE_EC2` | CPU < 5% over idle window | high |
| EC2 instances | `STOPPED_EC2` | Stopped > 30 days | high |
| EBS volumes | `DETACHED_EBS` | Detached (available state) | high |
| Elastic IPs | `UNUSED_EIP` | Not associated with running instance | medium |
| ALB | `IDLE_ALB` | Zero healthy targets or zero requests | high |
| NLB | `IDLE_NLB` | Zero healthy targets or zero active flows | high |
| NAT Gateways | `IDLE_NAT_GATEWAY` | Zero bytes processed | high |
| RDS instances | `IDLE_RDS` | CPU < 5% or zero connections | high |
| Snapshots | `STALE_SNAPSHOT` | Older than stale threshold, no AMI reference | medium |
| Security Groups | `UNUSED_SECURITY_GROUP` | No attached ENIs | low |

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
```

Generate a sample config with `awsspectre init`.

## IAM permissions

AWSSpectre requires read-only access. Run `awsspectre init` to generate the minimal IAM policy, or attach these permissions:

- `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeSnapshots`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeNatGateways`, `ec2:DescribeImages`, `ec2:DescribeRegions`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`
- `rds:DescribeDBInstances`
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

**SpectreHub** (`--format spectrehub`): `spectrehub/v1` envelope for SpectreHub ingestion.

## Architecture

```
awsspectre/
├── cmd/awsspectre/main.go         # Entry point (22 lines, LDFLAGS)
├── internal/
│   ├── commands/                  # Cobra CLI: scan, init, version
│   ├── aws/                       # AWS SDK v2 clients + 8 resource scanners
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
│   │   └── secgroup.go            # Security groups: no attached ENIs
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
| 8 resource scanners (EC2, EBS, EIP, ALB, NLB, NAT GW, RDS, snapshots, security groups) | Complete |
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

## License

MIT License -- see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

Part of the Spectre family:
[S3Spectre](https://github.com/ppiankov/s3spectre) |
[VaultSpectre](https://github.com/ppiankov/vaultspectre) |
[ClickSpectre](https://github.com/ppiankov/clickspectre) |
[KafkaSpectre](https://github.com/ppiankov/kafkaspectre)
