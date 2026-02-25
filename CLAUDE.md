# awsspectre

AWS resource waste auditor. Finds idle, orphaned, and oversized resources costing money for nothing.

## Commands

- `make build` — Build binary to ./bin/awsspectre
- `make test` — Run tests with -race flag
- `make lint` — Run golangci-lint
- `make fmt` — Format with gofmt/goimports
- `make clean` — Clean build artifacts

## Architecture

- Entry: cmd/awsspectre/main.go — minimal, single Execute() call delegates to internal/commands
- commands — Cobra CLI commands (scan, init, version) and shared helpers
- aws — AWS SDK v2 clients, CloudWatch metrics fetcher, resource scanners (one per type)
- pricing — Embedded on-demand pricing data for cost estimation
- analyzer — Finding classification, cost filtering, summary generation
- report — Text, JSON (spectre/v1), SARIF, SpectreHub output formatters
- config — .awsspectre.yaml config file loading
- logging — slog initialization

## Conventions

- Minimal main.go — single Execute() call
- Internal packages: short single-word names (aws, pricing, analyzer, report, commands)
- Struct-based domain models with json tags
- Interface-based AWS client mocking for tests
- All AWS API calls go through context-aware methods
- CloudWatch uses batched GetMetricData (up to 500 queries/call)
- Bounded concurrency: max 4 regions, max 10 API calls per region

## Anti-Patterns

- NEVER modify or delete AWS resources — read-only auditing only
- NEVER make AWS calls without context
- NEVER skip error handling
- NEVER use init() functions unless absolutely necessary
- NEVER use global mutable state
- NEVER hardcode AWS credentials

## Verification

- Run `make test` after code changes (includes -race)
- Run `make lint` before marking complete
- Run `go vet ./...` for suspicious constructs
