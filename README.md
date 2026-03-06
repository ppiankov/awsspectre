# awsspectre

[![CI](https://github.com/ppiankov/awsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/awsspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/awsspectre)](https://goreportcard.com/report/github.com/ppiankov/awsspectre)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**awsspectre** — AWS resource waste auditor with cost estimates. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans EC2, RDS, EBS, ELB, NAT Gateway, EIP, Lambda, Kinesis, SQS, SNS, snapshots, and security groups
- Detects idle, orphaned, and oversized resources using CloudWatch metrics
- Estimates monthly waste in USD per finding
- Supports tag-based exclusions and configurable thresholds
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a real-time monitor — point-in-time scanner
- Not a remediation tool — reports only, never modifies resources
- Not a security scanner — checks utilization, not vulnerabilities
- Not a billing replacement — uses embedded on-demand pricing

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install awsspectre
```

### From source

```sh
git clone https://github.com/ppiankov/awsspectre.git
cd awsspectre
make build
```

### Usage

```sh
awsspectre scan --region us-east-1 --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `awsspectre scan` | Scan AWS account for idle and wasteful resources |
| `awsspectre init` | Generate IAM policy and config file |
| `awsspectre version` | Print version |

## SpectreHub integration

awsspectre feeds AWS resource waste findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool awsspectre
```

## Safety

awsspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your resources.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | Full command reference, flags, and configuration |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
