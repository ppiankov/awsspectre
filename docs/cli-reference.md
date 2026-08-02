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

**Windows:** download the `awsspectre_<version>_windows_amd64.zip` (or `arm64`) asset from the [releases page](https://github.com/ppiankov/awsspectre/releases), extract it, and add the folder containing `awsspectre.exe` to your `PATH`.


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
| `--high-memory-threshold` | `50.0` | Memory (or, for GPU instances, GPU utilization) % above which a resource is not idle |
| `--stopped-threshold-days` | `30` | Days stopped before flagging EC2 |
| `--nat-gw-low-traffic-gb` | `1.0` | NAT Gateway monthly GB below which to flag as low traffic |
| `--ecr-untagged-threshold` | `20` | Number of untagged images in an ECR repository before flagging as waste |
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
timeout: 20m
exclude:
  resource_ids:
    - i-0abc123def456
    - vol-0abc123def456
  tags:
    - "Environment=production"
    - "awsspectre:ignore"
```

Generate a sample config with `awsspectre init`. An explicit CLI flag always takes precedence over its config-file counterpart, even when the flag's value happens to match its default.


## IAM permissions

AWSSpectre requires read-only access. Run `awsspectre init` to generate the minimal IAM policy, or attach these permissions:

- `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeSnapshots`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeNatGateways`, `ec2:DescribeImages`, `ec2:DescribeRegions`, `ec2:DescribeLaunchTemplateVersions`
- `autoscaling:DescribeAutoScalingGroups`, `autoscaling:DescribeLaunchConfigurations`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`, `elasticloadbalancing:DescribeTags`
- `rds:DescribeDBInstances`
- `lambda:ListFunctions`, `lambda:ListTags`
- `kinesis:ListStreams`, `kinesis:DescribeStreamSummary`, `kinesis:ListTagsForStream`
- `firehose:ListDeliveryStreams`, `firehose:ListTagsForDeliveryStream`, `firehose:DescribeDeliveryStream`
- `sqs:ListQueues`, `sqs:GetQueueAttributes`, `sqs:ListQueueTags`
- `sns:ListTopics`, `sns:ListSubscriptionsByTopic`, `sns:ListTagsForResource`
- `logs:DescribeLogGroups`, `logs:ListTagsForResource`
- `ecr:DescribeRepositories`, `ecr:GetLifecyclePolicy`, `ecr:DescribeImages`
- `cloudfront:ListDistributions`, `cloudfront:ListTagsForResource`
- `cloudwatch:GetMetricData`
- `cloudtrail:LookupEvents` (optional)


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
│   ├── aws/                       # AWS SDK v2 clients + global/regional resource scanners
│   │   ├── types.go               # Finding, Severity, ResourceType, ScanConfig
│   │   ├── client.go              # AWS config loader, region discovery
│   │   ├── cloudwatch.go          # Batched GetMetricData (up to 500 queries/call)
│   │   ├── idlewindow.go          # Shared idle-window confidence helper (data-coverage honesty)
│   │   ├── scanner.go             # MultiRegionScanner orchestrator
│   │   ├── cloudfront.go          # CloudFront: disabled distributions, zero requests
│   │   ├── ec2.go                 # EC2: idle CPU, stopped instances, EKS/ASG node-group awareness
│   │   ├── ebs.go                 # EBS: detached volumes, gp2->gp3 migration candidates
│   │   ├── eip.go                 # EIP: unassociated addresses
│   │   ├── elb.go                 # ALB/NLB: zero targets, zero requests
│   │   ├── natgw.go               # NAT Gateway: zero bytes processed
│   │   ├── rds.go                 # RDS: idle CPU, no connections
│   │   ├── snapshot.go            # Snapshots: old, no AMI reference
│   │   ├── secgroup.go            # Security groups: no attached ENIs or ASG/launch-template references
│   │   ├── lambda.go              # Lambda: zero invocations
│   │   ├── kinesis.go             # Kinesis: idle streams, over-provisioned shards, idle Firehose
│   │   ├── sqs.go                 # SQS: idle queues, no-consumer, orphaned DLQs
│   │   ├── sns.go                 # SNS: no subscribers, idle topics
│   │   ├── logs.go                # CloudWatch Logs: no retention policy
│   │   └── ecr.go                 # ECR: no lifecycle policy, untagged-image sprawl
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
- Every Finding carries a structured `remediation_path` (`direct`, `via_controller`, `needs_review`) -- a machine-readable alternative to string-matching the `message` field to tell "safe to delete directly" apart from "needs indirect action via an owning Kubernetes/ECS/IaC-managed resource" or "ambiguous, needs manual review."


## Project Status

**Status: Beta** · **v0.11.0** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| Resource scanners for EC2, EBS, EIP, ALB, NLB, NAT GW, RDS, Lambda, Kinesis, Firehose, SQS, SNS, CloudFront, CloudWatch Logs, ECR, snapshots, and security groups | Complete |
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
- **Security group references.** Checks ENI attachment, in-rules cross-references, and Auto Scaling Group launch template/launch configuration references (regardless of current desired capacity). Does not trace through nested group chains. If an ASG references a launch template version that no longer exists (e.g. a deleted version left behind after drift), that lookup fails and is skipped — the referenced security group can then be incorrectly re-flagged as unused until the stale reference is cleaned up.
- **Snapshot AMI check.** Only validates against AMIs owned by the account. Shared AMIs referencing the snapshot will not be detected.
- **Single metric thresholds.** CPU < 5% is a simple heuristic. Some workloads (batch, cron) may appear idle but are not.
- **gp2/gp3 pricing coverage.** The gp2→gp3 migration savings estimate is only backed by curated rates for 4 regions; other regions fall back to us-east-1 pricing for both volume types, which may not reflect the real gp2/gp3 delta (or lack thereof) in every region.
- **CloudWatch Agent-dependent overrides.** Memory- and GPU-aware idle detection for EC2 (`--high-memory-threshold`) both require the CloudWatch Agent's respective plugins (`mem_used_percent`, `utilization_gpu`) to be installed and reporting; without them, detection silently falls back to CPU-only. GPU utilization metrics are NVIDIA-agent-based — Inferentia (inf1/inf2) and Trainium (trn1) instances report via separate Neuron metrics not currently read, so GPU-aware detection is inert for those families today.
- **CloudTrail-corrected timestamps are best-effort.** `DETACHED_EBS`/`STOPPED_EC2` day-counts prefer a real CloudTrail `DetachVolume`/`StopInstances` event over the CreateTime/LaunchTime-based estimate, but only when `cloudtrail:LookupEvents` is granted and the event falls within CloudTrail's default ~90-day event history (or longer, if a custom trail with extended retention is configured) — accounts without a trail, or events older than that window, fall back to the less-precise CreateTime/LaunchTime estimate.
- **Firehose metric selection depends on a per-stream describe call.** `KINESIS_FIREHOSE_IDLE` checks a different CloudWatch metric depending on the delivery stream's source type (`IncomingRecords` for DirectPut, `DataReadFromKinesisStream.Records` for a Kinesis-sourced stream), determined via `firehose:DescribeDeliveryStream`. If that call fails for a given stream (e.g. transient throttling — Firehose's control-plane APIs share a low, non-adjustable rate limit), the stream is treated as DirectPut for that scan, which could reproduce a false idle flag on a Kinesis-sourced stream until the next successful scan. That same call also supplies the creation timestamp used to disclose insufficient running history for young streams — on failure, the message defaults to full-window confidence even for a newly created stream.
- **Excluded source queues break DLQ suppression.** `SQS_IDLE` excludes a queue that's the `deadLetterTargetArn` of another live queue's `RedrivePolicy`, since an empty, healthy DLQ is expected, not waste. That exclusion set is built only from queues that survive `--exclude-tags`/`resource_ids` filtering — excluding the source queue while leaving its DLQ unexcluded causes the DLQ to lose this protection and reappear as a `SQS_IDLE` finding.
- **`remediation_path` is only actively classified by a subset of scanners today.** ELB and `IDLE_EC2` set `via_controller` for Kubernetes/EKS/Auto Scaling Group-managed resources; `DETACHED_EBS` sets `needs_review` for volumes carrying AWS EBS CSI driver tags. Every other scanner (and every other finding) defaults to `direct`, which means "not yet classified," not "verified safe to delete directly." Treat `direct` as the absence of a more specific classification, not a positive assertion. `needs_review` classifications are AWS-side tag inspection only — the tool cannot verify against a live Kubernetes cluster whether a PersistentVolume/PVC still exists, so a volume whose owning cluster was torn down long ago (tags persist regardless) can be permanently classified `needs_review` even though it's genuinely orphaned; `kubectl get pv` verification (named in the finding's message) is the only way to confirm current state.
- **`IDLE_EC2` node-group detection is AWS-side tag inspection only**, same caveat as `DETACHED_EBS` above: an instance tagged by a node group whose EKS cluster or Auto Scaling Group has since been deleted (tags persist regardless) stays classified `via_controller` even though direct termination may now be correct.
- **ECR scanner does not check repository tags.** `ECR_NO_LIFECYCLE_POLICY` and `ECR_UNTAGGED_IMAGE_SPRAWL` only support exclusion by resource ID (`--exclude-tags` with resource IDs, or the `resource_ids` config key); tag-based exclusion has no effect on ECR findings, since checking repository tags would require a separate `ecr:ListTagsForResource` call this scanner doesn't make.
- **`--ecr-untagged-threshold=0` is not distinguishable from unset** and silently falls back to the default of 20, the same 0-as-sentinel limitation shared by every other numeric threshold flag (`--idle-cpu-threshold`, `--high-memory-threshold`, `--stopped-threshold-days`, `--nat-gw-low-traffic-gb`) — there is currently no way to request "flag a repository with any untagged image at all."
