# Changelog

All notable changes to AWSSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.4] - 2026-07-27

### Fixed

- The generated IAM policy (`awsspectre init`) and permissions docs now include the 7 tag-fetch actions (`elasticloadbalancing:DescribeTags`, `kinesis:ListTagsForStream`, `firehose:ListTagsForDeliveryStream`, `lambda:ListTags`, `sns:ListTagsForResource`, `sqs:ListQueueTags`, `cloudfront:ListTagsForResource`) that an earlier release added scanner calls for. Applying the previously-generated policy caused `AccessDenied` on every one of these calls and silently no-op'd `--exclude-tags` for those resource types.

## [0.8.3] - 2026-07-27

### Fixed

- `IDLE_EC2` now checks CloudWatch Agent GPU utilization for GPU-family instance types before flagging idle, since a GPU-bound workload commonly runs with low host CPU while the GPU itself is saturated. Falls back to CPU-only detection when no GPU metric data is available.

## [0.8.2] - 2026-07-27

### Fixed

- `IDLE_EC2` no longer overclaims data coverage for instances that haven't been running as long as the configured lookback window. A live dogfood scan found a CI-runner instance running 11 minutes reported as "CPU 1.7% over 7 days" — the finding now discloses insufficient running history instead of claiming full-window confidence it doesn't have.

## [0.8.1] - 2026-07-26

### Fixed

- `IDLE_ALB`/`IDLE_NLB` now also recognizes EKS's native/Auto Mode load-balancing tag convention (`service.eks.amazonaws.com/resource` + `eks:eks-cluster-name`) as Kubernetes-managed, alongside the existing AWS Load Balancer Controller convention. A live dogfood scan found 27% of one account's k8s-managed NLBs were misclassified as ordinary orphaned load balancers because they only used this second convention.

## [0.8.0] - 2026-07-26

### Added

- EBS scanner: `GP2_MIGRATION_CANDIDATE` flags any modifiable (available/in-use) gp2 volume as a candidate for zero-downtime migration to gp3, which offers equivalent baseline performance at lower cost. Always visible regardless of `--min-monthly-cost` — per-volume savings are often small but compound across a fleet.

### Changed

- EBS scanner now lists all volumes (not just detached ones) to support the new gp2 check; detached-volume detection behavior is unchanged.

## [0.7.0] - 2026-07-25

### Added

- CloudWatch Logs scanner: `LOG_GROUP_NO_RETENTION` flags log groups with no retention policy set, since they retain log events indefinitely. Always visible regardless of `--min-monthly-cost` — the risk is unbounded future growth, not today's accumulated storage cost.
- `logs:DescribeLogGroups` and `logs:ListTagsForResource` permissions in the generated IAM policy

## [0.6.0] - 2026-07-25

### Added

- Windows CI build leg (`windows-latest`) and Windows quick-start install instructions in the README

### Changed

- `--exclude-tags` / config `exclude.tags` now apply to all 14 resource types — ELB, Kinesis, Firehose, Lambda, SNS, SQS, and CloudFront previously ignored tag-based exclusion silently
- Text output now sorts findings by severity (high to low) instead of scan order
- Load balancers managed by a Kubernetes controller (AWS Load Balancer Controller / EKS) are down-ranked from high to medium severity, with a message pointing at the owning Service/Ingress instead of the LB itself
- Explicit CLI flags now always take precedence over `.awsspectre.yaml` values, even when the flag's value matches its default
- `timeout` config key now applies to the scan timeout (previously parsed but never used)

## [0.5.0] - 2026-07-04

### Added

- CloudFront scanner: `CLOUDFRONT_DISABLED` (disabled distribution still present) and `CLOUDFRONT_IDLE` (zero requests over the idle window), evaluated once as a global service
- `cloudfront:ListDistributions` permission in the generated IAM policy

### Changed

- Zero-waste hygiene findings (security groups, idle Lambda, Firehose, SQS, SNS, on-demand Kinesis, and CloudFront) now stay visible under the default `--min-monthly-cost` filter via a structural hygiene marker

### Fixed

- SARIF output now declares rules for every emitted finding ID, so results reference valid rule metadata

## [0.4.0] - 2026-03-01

### Added

- Kinesis Data Streams scanner: `KINESIS_STREAM_IDLE` (zero records) and `KINESIS_OVER_PROVISIONED` (shard utilization <10%)
- Firehose scanner: `KINESIS_FIREHOSE_IDLE` (zero incoming records)
- SQS scanner: `SQS_IDLE` (zero messages), `SQS_NO_CONSUMER` (sent but not received), `SQS_DLQ_ORPHANED` (dead-letter queue with no active source)
- SNS scanner: `SNS_NO_SUBSCRIBERS` (zero subscriptions), `SNS_IDLE` (zero published messages)
- Kinesis shard cost estimation for provisioned mode streams
- IAM permissions for Kinesis, Firehose, SQS, and SNS in generated policy

## [0.3.1] - 2026-03-01

### Changed

- `STOPPED_EC2` findings now include attached EBS volume storage cost instead of $0
- Finding message shows volume count and monthly EBS cost breakdown
- Metadata includes `ebs_monthly_cost` and `attached_volumes` with per-volume details

## [0.3.0] - 2026-02-28

### Added

- Lambda idle detection scanner (`IDLE_LAMBDA`) for functions with zero invocations over idle window
- Rich metadata for triage: runtime, code size, memory, timeout, last modified
- `lambda:ListFunctions` IAM permission in generated policy

## [0.2.2] - 2026-02-28

### Added

- `LOW_TRAFFIC_NAT_GATEWAY` finding for NAT Gateways processing below configurable threshold (default 1 GB/month)
- Cost breakdown in finding metadata: gateway hourly cost + per-GB data processing
- `--nat-gw-low-traffic-gb` flag and `nat_gw_low_traffic_gb` config option

## [0.2.1] - 2026-02-28

### Added

- Tag-based resource exclusions via `exclude.tags` in config and `--exclude-tags` CLI flag
- Centralized `ShouldExclude()` method replacing inline exclusion checks across all 8 scanners
- Key=Value exact match and key-only match (any value) for tag exclusions

## [0.2.0] - 2026-02-28

### Added

- Configurable idle thresholds via `.awsspectre.yaml` and CLI flags: `--idle-cpu-threshold`, `--high-memory-threshold`, `--stopped-threshold-days`

## [0.1.2] - 2026-02-27

### Fixed

- RDS idle detection now checks FreeableMemory alongside CPU — memory-heavy databases are no longer falsely flagged
- SpectreHub envelope schema unified to `spectre/v1` with `schema` JSON key

### Changed

- Spectre family list in README replaced with spectrehub.dev link

## [0.1.1] - 2026-02-27

### Fixed

- EC2 idle detection now checks memory utilization (CWAgent) alongside CPU — instances with high memory usage are no longer falsely flagged as idle
- Stopped EC2 instances report $0 estimated waste instead of full compute cost
- Stopped EC2 severity downgraded from high to medium (no active compute spend)
- SARIF default level for STOPPED_EC2 changed from error to warning

## [0.1.0] - 2026-02-25

### Added

- Multi-region scanning with bounded concurrency (max 4 regions, 10 API calls per region)
- 8 resource scanners: EC2 (idle CPU, stopped), EBS (detached), EIP (unassociated), ALB/NLB (zero targets/requests), NAT Gateway (zero bytes), RDS (idle CPU, no connections), Snapshots (stale, no AMI), Security Groups (unused)
- CloudWatch batched `GetMetricData` API for efficient metric collection (up to 500 queries per call)
- Embedded on-demand pricing data via `go:embed` for cost estimation
- Analyzer with minimum cost filtering and summary aggregation
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub (`spectre/v1`)
- Configuration via `.awsspectre.yaml` with `awsspectre init` generator
- IAM policy generator (`awsspectre init`) for minimal read-only permissions
- Enhanced error messages with actionable hints for common AWS failures
- GoReleaser config for multi-platform releases (Linux, macOS, Windows; amd64, arm64)
- Docker images via multi-stage distroless build with multi-arch manifests on ghcr.io
- Homebrew formula via GoReleaser brews section
- CI/CD: GitHub Actions for build, test, lint, and release

[0.8.4]: https://github.com/ppiankov/awsspectre/releases/tag/v0.8.4
[0.8.3]: https://github.com/ppiankov/awsspectre/releases/tag/v0.8.3
[0.8.2]: https://github.com/ppiankov/awsspectre/releases/tag/v0.8.2
[0.8.1]: https://github.com/ppiankov/awsspectre/releases/tag/v0.8.1
[0.8.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.8.0
[0.7.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.7.0
[0.6.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.6.0
[0.5.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.5.0
[0.4.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.4.0
[0.3.1]: https://github.com/ppiankov/awsspectre/releases/tag/v0.3.1
[0.3.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.3.0
[0.2.2]: https://github.com/ppiankov/awsspectre/releases/tag/v0.2.2
[0.2.1]: https://github.com/ppiankov/awsspectre/releases/tag/v0.2.1
[0.2.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.2.0
[0.1.2]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.2
[0.1.1]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.1
[0.1.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.0
