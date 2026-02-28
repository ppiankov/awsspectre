package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ppiankov/awsspectre/internal/analyzer"
	"github.com/ppiankov/awsspectre/internal/aws"
	"github.com/ppiankov/awsspectre/internal/report"
	"github.com/spf13/cobra"
)

var scanFlags struct {
	regions              []string
	allRegions           bool
	idleDays             int
	staleDays            int
	format               string
	outputFile           string
	minMonthlyCost       float64
	idleCPUThreshold     float64
	highMemoryThreshold  float64
	stoppedThresholdDays int
	noProgress           bool
	timeout              time.Duration
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan AWS resources for waste",
	Long: `Scan AWS resources across regions to find idle, orphaned, and oversized
resources. Reports estimated monthly waste in USD for each finding.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanFlags.regions, "regions", nil, "Comma-separated region filter")
	scanCmd.Flags().BoolVar(&scanFlags.allRegions, "all-regions", true, "Scan all enabled regions")
	scanCmd.Flags().IntVar(&scanFlags.idleDays, "idle-days", 7, "Lookback window for utilization metrics (days)")
	scanCmd.Flags().IntVar(&scanFlags.staleDays, "stale-days", 90, "Age threshold for snapshots/volumes (days)")
	scanCmd.Flags().StringVar(&scanFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	scanCmd.Flags().StringVarP(&scanFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().Float64Var(&scanFlags.minMonthlyCost, "min-monthly-cost", 1.0, "Minimum monthly cost to report ($)")
	scanCmd.Flags().Float64Var(&scanFlags.idleCPUThreshold, "idle-cpu-threshold", 0, "CPU % below which a resource is idle (default: 5)")
	scanCmd.Flags().Float64Var(&scanFlags.highMemoryThreshold, "high-memory-threshold", 0, "Memory % above which a resource is not idle (default: 50)")
	scanCmd.Flags().IntVar(&scanFlags.stoppedThresholdDays, "stopped-threshold-days", 0, "Days stopped before flagging EC2 (default: 30)")
	scanCmd.Flags().BoolVar(&scanFlags.noProgress, "no-progress", false, "Disable progress output")
	scanCmd.Flags().DurationVar(&scanFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if scanFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanFlags.timeout)
		defer cancel()
	}

	// Apply config file defaults where flags were not explicitly set
	applyConfigDefaults()

	// Resolve profile from flag or config
	prof := profile
	if prof == "" {
		prof = cfg.Profile
	}

	// Initialize AWS client
	client, err := aws.NewClient(ctx, prof, "")
	if err != nil {
		return enhanceError("initialize AWS client", err)
	}

	// Determine regions to scan
	regions, err := resolveRegions(ctx, client)
	if err != nil {
		return enhanceError("resolve regions", err)
	}
	slog.Info("Scanning regions", "count", len(regions), "regions", regions)

	// Build scan config with defaults for thresholds
	cpuThresh := 5.0
	if scanFlags.idleCPUThreshold > 0 {
		cpuThresh = scanFlags.idleCPUThreshold
	}
	memThresh := 50.0
	if scanFlags.highMemoryThreshold > 0 {
		memThresh = scanFlags.highMemoryThreshold
	}
	stoppedDays := 30
	if scanFlags.stoppedThresholdDays > 0 {
		stoppedDays = scanFlags.stoppedThresholdDays
	}

	scanCfg := aws.ScanConfig{
		IdleDays:             scanFlags.idleDays,
		StaleDays:            scanFlags.staleDays,
		MinMonthlyCost:       scanFlags.minMonthlyCost,
		IdleCPUThreshold:     cpuThresh,
		HighMemoryThreshold:  memThresh,
		StoppedThresholdDays: stoppedDays,
	}

	// Run multi-region scan
	scanner := aws.NewMultiRegionScanner(client, regions, 4, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan resources", err)
	}

	// Analyze results: filter by min cost, compute summary
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		MinMonthlyCost: scanFlags.minMonthlyCost,
	})

	// Build report data
	data := report.Data{
		Tool:      "awsspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "aws-account",
			URIHash: computeTargetHash(prof, regions),
		},
		Config: report.ReportConfig{
			Regions:        regions,
			IdleDays:       scanFlags.idleDays,
			StaleDays:      scanFlags.staleDays,
			MinMonthlyCost: scanFlags.minMonthlyCost,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	// Select and run reporter
	reporter, err := selectReporter(scanFlags.format, scanFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func resolveRegions(ctx context.Context, client *aws.Client) ([]string, error) {
	if len(scanFlags.regions) > 0 {
		return scanFlags.regions, nil
	}

	// Check config file
	if len(cfg.Regions) > 0 {
		return cfg.Regions, nil
	}

	if scanFlags.allRegions {
		return client.ListEnabledRegions(ctx)
	}

	// Fall back to default region from AWS config
	region := client.Config().Region
	if region == "" {
		return nil, fmt.Errorf("no region specified; use --regions, --all-regions, or set AWS_REGION")
	}
	return []string{region}, nil
}

func applyConfigDefaults() {
	if scanFlags.format == "text" && cfg.Format != "" {
		scanFlags.format = cfg.Format
	}
	if scanFlags.idleDays == 7 && cfg.IdleDays > 0 {
		scanFlags.idleDays = cfg.IdleDays
	}
	if scanFlags.staleDays == 90 && cfg.StaleDays > 0 {
		scanFlags.staleDays = cfg.StaleDays
	}
	if scanFlags.minMonthlyCost == 1.0 && cfg.MinMonthlyCost > 0 {
		scanFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
	if scanFlags.idleCPUThreshold == 0 && cfg.IdleCPUThreshold > 0 {
		scanFlags.idleCPUThreshold = cfg.IdleCPUThreshold
	}
	if scanFlags.highMemoryThreshold == 0 && cfg.HighMemoryThreshold > 0 {
		scanFlags.highMemoryThreshold = cfg.HighMemoryThreshold
	}
	if scanFlags.stoppedThresholdDays == 0 && cfg.StoppedThresholdDays > 0 {
		scanFlags.stoppedThresholdDays = cfg.StoppedThresholdDays
	}
}

func selectReporter(format, outputFile string) (report.Reporter, error) {
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}
