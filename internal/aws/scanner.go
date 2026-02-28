package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"golang.org/x/sync/errgroup"
)

// ResourceScanner is the interface each resource-type scanner implements.
type ResourceScanner interface {
	Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error)
	Type() ResourceType
}

// MultiRegionScanner orchestrates scanning across multiple AWS regions.
type MultiRegionScanner struct {
	client      *Client
	regions     []string
	concurrency int
	scanConfig  ScanConfig
	progressFn  func(ScanProgress)
}

// NewMultiRegionScanner creates a scanner that runs across the specified regions.
func NewMultiRegionScanner(client *Client, regions []string, concurrency int, scanCfg ScanConfig) *MultiRegionScanner {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &MultiRegionScanner{
		client:      client,
		regions:     regions,
		concurrency: concurrency,
		scanConfig:  scanCfg,
	}
}

// SetProgressFn sets a callback for progress updates.
func (s *MultiRegionScanner) SetProgressFn(fn func(ScanProgress)) {
	s.progressFn = fn
}

// ScanAll runs all resource scanners across all configured regions.
func (s *MultiRegionScanner) ScanAll(ctx context.Context) (*ScanResult, error) {
	var (
		mu       sync.Mutex
		combined ScanResult
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(s.concurrency)

	for _, region := range s.regions {
		region := region
		g.Go(func() error {
			slog.Info("Scanning region", "region", region)
			result, err := s.scanRegion(ctx, region)
			if err != nil {
				mu.Lock()
				combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", region, err))
				mu.Unlock()
				slog.Warn("Region scan failed", "region", region, "error", err)
				return nil // don't abort other regions
			}

			mu.Lock()
			combined.Findings = append(combined.Findings, result.Findings...)
			combined.Errors = append(combined.Errors, result.Errors...)
			combined.ResourcesScanned += result.ResourcesScanned
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	combined.RegionsScanned = len(s.regions)
	return &combined, nil
}

// scanRegion runs all resource scanners for a single region.
func (s *MultiRegionScanner) scanRegion(ctx context.Context, region string) (*ScanResult, error) {
	cfg := s.client.ConfigForRegion(region)
	scanners := buildScanners(cfg, region)

	var (
		mu     sync.Mutex
		result ScanResult
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // max concurrent API calls per region

	for _, scanner := range scanners {
		scanner := scanner
		g.Go(func() error {
			slog.Debug("Running scanner", "type", scanner.Type(), "region", region)
			sr, err := scanner.Scan(ctx, s.scanConfig)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %v", region, scanner.Type(), err))
				mu.Unlock()
				slog.Warn("Scanner failed", "type", scanner.Type(), "region", region, "error", err)
				return nil
			}

			mu.Lock()
			result.Findings = append(result.Findings, sr.Findings...)
			result.ResourcesScanned += sr.ResourcesScanned
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &result, nil
}

// buildScanners creates all resource scanners for a given region.
func buildScanners(cfg awssdk.Config, region string) []ResourceScanner {
	ec2Client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	metrics := NewMetricsFetcher(cwClient)

	elbClient := elasticloadbalancingv2.NewFromConfig(cfg)
	rdsClient := rds.NewFromConfig(cfg)
	lambdaClient := lambda.NewFromConfig(cfg)

	return []ResourceScanner{
		NewEC2Scanner(ec2Client, metrics, region),
		NewEBSScanner(ec2Client, region),
		NewEIPScanner(ec2Client, region),
		NewSnapshotScanner(ec2Client, region),
		NewSecurityGroupScanner(ec2Client, region),
		NewELBScanner(elbClient, metrics, region),
		NewNATGatewayScanner(ec2Client, metrics, region),
		NewRDSScanner(rdsClient, metrics, region),
		NewLambdaScanner(lambdaClient, metrics, region),
	}
}
