package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"golang.org/x/sync/errgroup"
)

// ResourceScanner is the interface each resource-type scanner implements.
type ResourceScanner interface {
	Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error)
	Type() ResourceType
}

// MultiRegionScanner orchestrates scanning across multiple AWS regions.
type MultiRegionScanner struct {
	client                 *Client
	regions                []string
	concurrency            int
	scanConfig             ScanConfig
	progressFn             func(ScanProgress)
	configForRegion        func(string) awssdk.Config                    // WO-189: deterministic global-pass tests.
	regionalScannerBuilder func(awssdk.Config, string) []ResourceScanner // WO-189: deterministic global-pass tests.
	globalScannerBuilder   func(awssdk.Config) []ResourceScanner         // WO-189: deterministic global-pass tests.
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

	// WO-189: CloudFront is global, so scan it once outside the per-region loop.
	globalResult, err := s.scanGlobal(ctx)
	if err != nil {
		combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", cloudFrontFindingRegion, err))
		slog.Warn("Global scan failed", "error", err)
	} else {
		combined.Findings = append(combined.Findings, globalResult.Findings...)
		combined.Errors = append(combined.Errors, globalResult.Errors...)
		combined.ResourcesScanned += globalResult.ResourcesScanned
	}

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

// scanGlobal runs scanners for AWS global services from their required control-plane region.
func (s *MultiRegionScanner) scanGlobal(ctx context.Context) (*ScanResult, error) {
	// WO-189: existing scanner tests construct MultiRegionScanner without an AWS client.
	if s.client == nil && s.configForRegion == nil {
		return &ScanResult{}, nil
	}

	cfg := s.awsConfigForRegion(cloudFrontControlPlaneRegion)
	scanners := s.buildGlobalScanners(cfg)

	var (
		mu     sync.Mutex
		result ScanResult
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // max concurrent API calls for global services

	for _, scanner := range scanners {
		scanner := scanner
		g.Go(func() error {
			slog.Debug("Running global scanner", "type", scanner.Type())
			sr, err := scanner.Scan(ctx, s.scanConfig)
			if err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %v", cloudFrontFindingRegion, scanner.Type(), err))
				mu.Unlock()
				slog.Warn("Global scanner failed", "type", scanner.Type(), "error", err)
				return nil
			}

			mu.Lock()
			result.Findings = append(result.Findings, sr.Findings...)
			// WO-191: preserve partial scanner diagnostics alongside successful findings.
			result.Errors = append(result.Errors, sr.Errors...)
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

// scanRegion runs all resource scanners for a single region.
func (s *MultiRegionScanner) scanRegion(ctx context.Context, region string) (*ScanResult, error) {
	cfg := s.awsConfigForRegion(region)
	scanners := s.buildRegionalScanners(cfg, region)

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
			// WO-191: preserve partial scanner diagnostics alongside successful findings.
			result.Errors = append(result.Errors, sr.Errors...)
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

func (s *MultiRegionScanner) awsConfigForRegion(region string) awssdk.Config {
	if s.configForRegion != nil {
		return s.configForRegion(region)
	}
	return s.client.ConfigForRegion(region)
}

func (s *MultiRegionScanner) buildRegionalScanners(cfg awssdk.Config, region string) []ResourceScanner {
	if s.regionalScannerBuilder != nil {
		return s.regionalScannerBuilder(cfg, region)
	}
	return buildScanners(cfg, region)
}

func (s *MultiRegionScanner) buildGlobalScanners(cfg awssdk.Config) []ResourceScanner {
	if s.globalScannerBuilder != nil {
		return s.globalScannerBuilder(cfg)
	}
	return buildGlobalScanners(cfg)
}

// buildScanners creates all resource scanners for a given region.
func buildScanners(cfg awssdk.Config, region string) []ResourceScanner {
	ec2Client := ec2.NewFromConfig(cfg)
	cwClient := cloudwatch.NewFromConfig(cfg)
	metrics := NewMetricsFetcher(cwClient)

	elbClient := elasticloadbalancingv2.NewFromConfig(cfg)
	rdsClient := rds.NewFromConfig(cfg)
	lambdaClient := lambda.NewFromConfig(cfg)
	kinesisClient := kinesis.NewFromConfig(cfg)
	firehoseClient := firehose.NewFromConfig(cfg)
	sqsClient := sqs.NewFromConfig(cfg)
	snsClient := sns.NewFromConfig(cfg)

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
		NewKinesisScanner(kinesisClient, metrics, region),
		NewFirehoseScanner(firehoseClient, metrics, region),
		NewSQSScanner(sqsClient, metrics, region),
		NewSNSScanner(snsClient, metrics, region),
	}
}

func buildGlobalScanners(cfg awssdk.Config) []ResourceScanner {
	cloudFrontClient := cloudfront.NewFromConfig(cfg)
	cloudWatchClient := cloudwatch.NewFromConfig(cfg)
	metrics := NewMetricsFetcher(cloudWatchClient)

	return []ResourceScanner{
		NewCloudFrontScanner(cloudFrontClient, metrics),
	}
}
