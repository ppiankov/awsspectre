# Changelog

All notable changes to AWSSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub (`spectrehub/v1`)
- Configuration via `.awsspectre.yaml` with `awsspectre init` generator
- IAM policy generator (`awsspectre init`) for minimal read-only permissions
- Enhanced error messages with actionable hints for common AWS failures
- GoReleaser config for multi-platform releases (Linux, macOS, Windows; amd64, arm64)
- Docker images via multi-stage distroless build with multi-arch manifests on ghcr.io
- Homebrew formula via GoReleaser brews section
- CI/CD: GitHub Actions for build, test, lint, and release

[0.2.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.2.0
[0.1.2]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.2
[0.1.1]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.1
[0.1.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.0
