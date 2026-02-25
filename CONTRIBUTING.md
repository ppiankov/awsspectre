# Contributing to AWSSpectre

Thank you for considering contributing. This document outlines the process.

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/awsspectre`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit and push
7. Create a pull request

## Development setup

### Prerequisites

- Go 1.25 or later
- Make
- golangci-lint

### Building

```bash
make build
```

### Running tests

```bash
make test
```

### Linting

```bash
make lint
```

### Code formatting

```bash
make fmt
```

## Project structure

```
awsspectre/
├── cmd/awsspectre/          # CLI entry point (22 lines)
├── internal/
│   ├── commands/            # Cobra CLI commands
│   ├── aws/                 # AWS SDK clients + resource scanners
│   ├── pricing/             # Embedded pricing data
│   ├── analyzer/            # Finding classification + summary
│   └── report/              # Output formatters
└── docs/                    # Documentation
```

## Contribution areas

### New resource scanners

Add support for additional AWS resources:
1. Create `internal/aws/newresource.go` implementing `ResourceScanner` interface
2. Add the resource type to `types.go`
3. Add pricing lookup to `internal/pricing/`
4. Wire into `buildScanners()` in `scanner.go`
5. Write tests in `internal/aws/newresource_test.go`

### Analysis improvements

Enhance waste detection:
- Better idle heuristics (network I/O, disk I/O)
- Cost-aware severity (high-cost idle > low-cost idle)
- Trend analysis across multiple scans

### Report formats

Add new output formats in `internal/report/`:
- HTML reports
- CSV exports
- Slack/webhook notifications

## Coding guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Pass `golangci-lint` checks
- Write tests for new code (coverage target: >85%)
- Use interface-based mocking for AWS clients
- Check all errors, wrap with context using `fmt.Errorf`
- Comments explain "why" not "what"

## Commit messages

Format: `type: concise imperative statement`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`, `build`

Examples:
- `feat: add Lambda scanner`
- `fix: handle nil tags in EBS scanner`
- `test: add coverage for NAT Gateway exclusions`

## Pull request process

1. Ensure `make test && make lint` pass
2. Update CHANGELOG.md if adding features or fixing bugs
3. Create PR with clear description of what and why
4. Respond to review feedback

## SpectreHub compatibility

When modifying JSON output, ensure compatibility with SpectreHub:
- Maintain `spectre/v1` schema
- Include `tool`, `version`, `timestamp` fields
- Follow Spectre family conventions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
