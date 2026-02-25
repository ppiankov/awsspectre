# Changelog

All notable changes to AWSSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/ppiankov/awsspectre/releases/tag/v0.1.0
