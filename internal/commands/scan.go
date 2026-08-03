package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/awsspectre/internal/analyzer"
	"github.com/ppiankov/awsspectre/internal/aws"
	"github.com/ppiankov/awsspectre/internal/report"
	"github.com/spf13/cobra"
)

var scanFlags struct {
	regions               []string
	allRegions            bool
	idleDays              int
	staleDays             int
	format                string
	outputFile            string
	minMonthlyCost        float64
	idleCPUThreshold      float64
	highMemoryThreshold   float64
	idleCPUBurstThreshold float64
	idleEC2NetworkGB      float64
	stoppedThresholdDays  int
	natGWLowTrafficGB     float64
	ecrUntaggedThreshold  int
	excludeTags           []string
	noProgress            bool
	timeout               time.Duration
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
	scanCmd.Flags().Float64Var(&scanFlags.idleCPUBurstThreshold, "idle-cpu-burst-threshold", 0, "Daily CPU max % that counts as a spike day for periodic/burst-workload detection (default: 30)")
	scanCmd.Flags().Float64Var(&scanFlags.idleEC2NetworkGB, "idle-ec2-network-gb", 0, "Total NetworkIn+NetworkOut GB below which a low-CPU EC2 instance is idle (default: 1)")
	scanCmd.Flags().IntVar(&scanFlags.stoppedThresholdDays, "stopped-threshold-days", 0, "Days stopped before flagging EC2 (default: 30)")
	scanCmd.Flags().Float64Var(&scanFlags.natGWLowTrafficGB, "nat-gw-low-traffic-gb", 0, "NAT Gateway monthly GB below which to flag as low traffic (default: 1)")
	scanCmd.Flags().IntVar(&scanFlags.ecrUntaggedThreshold, "ecr-untagged-threshold", 0, "Number of untagged images in an ECR repository before flagging as waste (default: 20)")
	scanCmd.Flags().StringSliceVar(&scanFlags.excludeTags, "exclude-tags", nil, "Exclude resources by tag (Key=Value or Key, comma-separated)")
	scanCmd.Flags().BoolVar(&scanFlags.noProgress, "no-progress", false, "Disable progress output")
	scanCmd.Flags().DurationVar(&scanFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	// Apply config file defaults where flags were not explicitly set. Must
	// run before the timeout context is built below — otherwise a
	// config-only `timeout:` (no --timeout flag) never reaches the deadline.
	applyConfigDefaults(cmd)

	if scanFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanFlags.timeout)
		defer cancel()
	}

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
	burstThresh := 30.0
	if scanFlags.idleCPUBurstThreshold > 0 {
		burstThresh = scanFlags.idleCPUBurstThreshold
	}
	networkGB := 1.0
	if scanFlags.idleEC2NetworkGB > 0 {
		networkGB = scanFlags.idleEC2NetworkGB
	}
	stoppedDays := 30
	if scanFlags.stoppedThresholdDays > 0 {
		stoppedDays = scanFlags.stoppedThresholdDays
	}
	natGWTraffic := 1.0
	if scanFlags.natGWLowTrafficGB > 0 {
		natGWTraffic = scanFlags.natGWLowTrafficGB
	}
	ecrUntaggedThreshold := 20
	if scanFlags.ecrUntaggedThreshold > 0 {
		ecrUntaggedThreshold = scanFlags.ecrUntaggedThreshold
	}

	// Build exclusion rules from config file and CLI flags
	excludeIDs := make(map[string]bool, len(cfg.Exclude.ResourceIDs))
	for _, id := range cfg.Exclude.ResourceIDs {
		excludeIDs[id] = true
	}
	excludeTags := cfg.Exclude.ParseTags()
	for _, s := range scanFlags.excludeTags {
		if excludeTags == nil {
			excludeTags = make(map[string]string)
		}
		if k, v, ok := strings.Cut(s, "="); ok {
			excludeTags[k] = v
		} else {
			excludeTags[s] = ""
		}
	}

	scanCfg := aws.ScanConfig{
		IdleDays:              scanFlags.idleDays,
		StaleDays:             scanFlags.staleDays,
		MinMonthlyCost:        scanFlags.minMonthlyCost,
		IdleCPUThreshold:      cpuThresh,
		HighMemoryThreshold:   memThresh,
		IdleCPUBurstThreshold: burstThresh,
		IdleEC2NetworkGB:      networkGB,
		StoppedThresholdDays:  stoppedDays,
		NATGWLowTrafficGB:     natGWTraffic,
		ECRUntaggedThreshold:  ecrUntaggedThreshold,
		Exclude: aws.ExcludeConfig{
			ResourceIDs: excludeIDs,
			Tags:        excludeTags,
		},
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

// applyConfigDefaults fills in scanFlags from the config file, but only for
// flags the user did not explicitly pass — an explicit flag always wins over
// config, regardless of whether its value happens to equal the flag default.
func applyConfigDefaults(cmd *cobra.Command) {
	changed := cmd.Flags().Changed

	if !changed("format") && cfg.Format != "" {
		scanFlags.format = cfg.Format
	}
	if !changed("idle-days") && cfg.IdleDays > 0 {
		scanFlags.idleDays = cfg.IdleDays
	}
	if !changed("stale-days") && cfg.StaleDays > 0 {
		scanFlags.staleDays = cfg.StaleDays
	}
	if !changed("min-monthly-cost") && cfg.MinMonthlyCost > 0 {
		scanFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
	if !changed("idle-cpu-threshold") && cfg.IdleCPUThreshold > 0 {
		scanFlags.idleCPUThreshold = cfg.IdleCPUThreshold
	}
	if !changed("high-memory-threshold") && cfg.HighMemoryThreshold > 0 {
		scanFlags.highMemoryThreshold = cfg.HighMemoryThreshold
	}
	if !changed("idle-cpu-burst-threshold") && cfg.IdleCPUBurstThreshold > 0 {
		scanFlags.idleCPUBurstThreshold = cfg.IdleCPUBurstThreshold
	}
	if !changed("stopped-threshold-days") && cfg.StoppedThresholdDays > 0 {
		scanFlags.stoppedThresholdDays = cfg.StoppedThresholdDays
	}
	if !changed("nat-gw-low-traffic-gb") && cfg.NATGWLowTrafficGB > 0 {
		scanFlags.natGWLowTrafficGB = cfg.NATGWLowTrafficGB
	}
	if !changed("ecr-untagged-threshold") && cfg.ECRUntaggedThreshold > 0 {
		scanFlags.ecrUntaggedThreshold = cfg.ECRUntaggedThreshold
	}
	if !changed("timeout") {
		if d := cfg.TimeoutDuration(); d > 0 {
			scanFlags.timeout = d
		}
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
