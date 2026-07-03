package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

func TestCloudFrontScannerFindsDisabledAndIdleDistributions(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			cloudFrontPage(true,
				cloudFrontDistribution("disabled", false),
				cloudFrontDistribution("idle", true),
			),
			cloudFrontPage(false,
				cloudFrontDistribution("active", true),
				cloudFrontDistribution("excluded", false),
			),
		},
	}
	cw := &fakeCloudWatchClient{
		values: map[string]float64{
			"idle":   0,
			"active": 42,
		},
	}

	scanner := NewCloudFrontScanner(cf, NewMetricsFetcher(cw))
	if scanner.Type() != ResourceCloudFront {
		t.Fatalf("expected scanner type %s, got %s", ResourceCloudFront, scanner.Type())
	}

	result, err := scanner.Scan(context.Background(), ScanConfig{
		IdleDays: 30,
		Exclude: ExcludeConfig{
			ResourceIDs: map[string]bool{"excluded": true},
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if cf.calls != 2 {
		t.Fatalf("expected paginated ListDistributions to run twice, got %d", cf.calls)
	}
	if result.ResourcesScanned != 4 {
		t.Fatalf("expected 4 resources scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(result.Findings), result.Findings)
	}

	findings := findingsByResourceID(result.Findings)
	assertCloudFrontFinding(t, findings["disabled"], FindingCloudFrontDisabled, SeverityLow)
	assertCloudFrontFinding(t, findings["idle"], FindingCloudFrontIdle, SeverityMedium)

	if _, ok := findings["active"]; ok {
		t.Fatalf("active distribution with traffic should not emit a finding")
	}
	if _, ok := findings["excluded"]; ok {
		t.Fatalf("excluded distribution should not emit a finding")
	}

	if len(cw.inputs) != 1 {
		t.Fatalf("expected one CloudWatch request, got %d", len(cw.inputs))
	}
	assertCloudFrontMetricQuery(t, cw.inputs[0], "idle")
	assertCloudFrontMetricQuery(t, cw.inputs[0], "active")
}

func TestCloudFrontScannerDoesNotFetchMetricsWithoutEnabledDistributions(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			cloudFrontPage(false, cloudFrontDistribution("disabled", false)),
		},
	}
	cw := &fakeCloudWatchClient{}

	scanner := NewCloudFrontScanner(cf, NewMetricsFetcher(cw))
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 30})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected disabled finding, got %#v", result.Findings)
	}
	if len(cw.inputs) != 0 {
		t.Fatalf("expected no CloudWatch calls, got %d", len(cw.inputs))
	}
}

func TestCloudFrontScannerValidationAndListErrors(t *testing.T) {
	t.Parallel()

	_, err := NewCloudFrontScanner(nil, nil).Scan(context.Background(), ScanConfig{})
	if err == nil {
		t.Fatalf("expected nil client error")
	}

	wantErr := errors.New("list failed")
	result, err := NewCloudFrontScanner(&fakeCloudFrontClient{err: wantErr}, nil).Scan(context.Background(), ScanConfig{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected list error %v, got %v", wantErr, err)
	}
	if result != nil {
		t.Fatalf("expected no partial result on list error, got %#v", result)
	}
}

func TestCloudFrontScannerHandlesEmptyDistributionPage(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			{},
		},
	}

	result, err := NewCloudFrontScanner(cf, nil).Scan(context.Background(), ScanConfig{IdleDays: 30})
	if err != nil {
		t.Fatalf("scan empty page: %v", err)
	}
	if result.ResourcesScanned != 0 || len(result.Findings) != 0 {
		t.Fatalf("expected empty result, got %#v", result)
	}
}

func TestCloudFrontScannerRequiresMetricsForEnabledDistributions(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			cloudFrontPage(false, cloudFrontDistribution("enabled", true)),
		},
	}

	_, err := NewCloudFrontScanner(cf, nil).Scan(context.Background(), ScanConfig{IdleDays: 30})
	if err == nil {
		t.Fatalf("expected nil metrics error")
	}
}

func TestCloudFrontScannerPreservesDisabledFindingsWhenMetricsFail(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			cloudFrontPage(false,
				cloudFrontDistribution("disabled", false),
				cloudFrontDistribution("enabled", true),
			),
		},
	}
	cw := &fakeCloudWatchClient{err: errors.New("cloudwatch throttled")}

	scanner := NewCloudFrontScanner(cf, NewMetricsFetcher(cw))
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 30})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	findings := findingsByResourceID(result.Findings)
	assertCloudFrontFinding(t, findings["disabled"], FindingCloudFrontDisabled, SeverityLow)
	if _, ok := findings["enabled"]; ok {
		t.Fatalf("enabled distribution should not emit idle finding when metrics fail")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected one metric error, got %#v", result.Errors)
	}
	if !strings.Contains(result.Errors[0], "cloudfront requests metric") {
		t.Fatalf("expected CloudFront metric context, got %q", result.Errors[0])
	}
	if len(cw.inputs) != 1 {
		t.Fatalf("expected one CloudWatch request, got %d", len(cw.inputs))
	}
}

// WO-191: verifies metric diagnostics survive the global scanner aggregation path.
func TestMultiRegionScannerPreservesCloudFrontMetricErrors(t *testing.T) {
	t.Parallel()

	cf := &fakeCloudFrontClient{
		pages: []*cloudfront.ListDistributionsOutput{
			cloudFrontPage(false,
				cloudFrontDistribution("disabled", false),
				cloudFrontDistribution("enabled", true),
			),
		},
	}
	cw := &fakeCloudWatchClient{err: errors.New("cloudwatch throttled")}

	scanner := &MultiRegionScanner{
		configForRegion: func(region string) awssdk.Config {
			return awssdk.Config{Region: region}
		},
		regionalScannerBuilder: func(_ awssdk.Config, _ string) []ResourceScanner {
			return nil
		},
		globalScannerBuilder: func(_ awssdk.Config) []ResourceScanner {
			return []ResourceScanner{NewCloudFrontScanner(cf, NewMetricsFetcher(cw))}
		},
	}

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan all: %v", err)
	}

	findings := findingsByResourceID(result.Findings)
	assertCloudFrontFinding(t, findings["disabled"], FindingCloudFrontDisabled, SeverityLow)
	if _, ok := findings["enabled"]; ok {
		t.Fatalf("enabled distribution should not emit idle finding when metrics fail")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected one propagated metric error, got %#v", result.Errors)
	}
	if !strings.Contains(result.Errors[0], "cloudfront requests metric") {
		t.Fatalf("expected CloudFront metric context, got %q", result.Errors[0])
	}
}

func TestMultiRegionScannerRunsCloudFrontOnce(t *testing.T) {
	t.Parallel()

	var (
		mu                    sync.Mutex
		configRegions         []string
		globalBuilderCalls    int
		globalScannerScanRuns int
	)

	scanner := &MultiRegionScanner{
		regions:     []string{"us-east-1", "us-west-2", "eu-west-1"},
		concurrency: 3,
		configForRegion: func(region string) awssdk.Config {
			mu.Lock()
			configRegions = append(configRegions, region)
			mu.Unlock()
			return awssdk.Config{Region: region}
		},
		regionalScannerBuilder: func(_ awssdk.Config, _ string) []ResourceScanner {
			return nil
		},
		globalScannerBuilder: func(cfg awssdk.Config) []ResourceScanner {
			if cfg.Region != cloudFrontControlPlaneRegion {
				t.Fatalf("expected global scanner config region %q, got %q", cloudFrontControlPlaneRegion, cfg.Region)
			}
			globalBuilderCalls++
			return []ResourceScanner{
				&fakeResourceScanner{
					resourceType:      ResourceCloudFront,
					resourcesScanned:  1,
					scanRuns:          &globalScannerScanRuns,
					findingResourceID: "global-distribution",
				},
			}
		},
	}

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan all: %v", err)
	}

	if globalBuilderCalls != 1 {
		t.Fatalf("expected global scanner builder once, got %d", globalBuilderCalls)
	}
	if globalScannerScanRuns != 1 {
		t.Fatalf("expected CloudFront scanner to run once, got %d", globalScannerScanRuns)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one global finding, got %#v", result.Findings)
	}
	if result.ResourcesScanned != 1 {
		t.Fatalf("expected one global resource scanned, got %d", result.ResourcesScanned)
	}
	if result.RegionsScanned != 3 {
		t.Fatalf("expected 3 regional scans counted, got %d", result.RegionsScanned)
	}

	if len(configRegions) != len(scanner.regions)+1 {
		t.Fatalf("expected one global config request plus regional requests, got %v", configRegions)
	}
}

func cloudFrontDistribution(id string, enabled bool) cftypes.DistributionSummary {
	return cftypes.DistributionSummary{
		Id:         awssdk.String(id),
		ARN:        awssdk.String("arn:aws:cloudfront::123456789012:distribution/" + id),
		DomainName: awssdk.String(id + ".cloudfront.net"),
		Status:     awssdk.String("Deployed"),
		Enabled:    awssdk.Bool(enabled),
		Aliases: &cftypes.Aliases{
			Items: []string{id + ".example.com"},
		},
	}
}

func cloudFrontPage(isTruncated bool, distributions ...cftypes.DistributionSummary) *cloudfront.ListDistributionsOutput {
	page := &cloudfront.ListDistributionsOutput{
		DistributionList: &cftypes.DistributionList{
			Items:       distributions,
			IsTruncated: awssdk.Bool(isTruncated),
		},
	}
	if isTruncated {
		page.DistributionList.NextMarker = awssdk.String("next")
	}
	return page
}

func findingsByResourceID(findings []Finding) map[string]Finding {
	byID := make(map[string]Finding, len(findings))
	for _, finding := range findings {
		byID[finding.ResourceID] = finding
	}
	return byID
}

func assertCloudFrontFinding(t *testing.T, finding Finding, id FindingID, severity Severity) {
	t.Helper()

	if finding.ID != id {
		t.Fatalf("expected finding ID %s, got %s", id, finding.ID)
	}
	if finding.Severity != severity {
		t.Fatalf("expected severity %s, got %s", severity, finding.Severity)
	}
	if finding.ResourceType != ResourceCloudFront {
		t.Fatalf("expected resource type %s, got %s", ResourceCloudFront, finding.ResourceType)
	}
	if finding.Region != cloudFrontFindingRegion {
		t.Fatalf("expected region %s, got %s", cloudFrontFindingRegion, finding.Region)
	}
	if finding.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected zero estimated waste, got %f", finding.EstimatedMonthlyWaste)
	}
	if finding.ResourceName == "" {
		t.Fatalf("expected ARN resource name")
	}
	if finding.Metadata["domain_name"] == "" {
		t.Fatalf("expected domain_name metadata")
	}
	if finding.Metadata["status"] == "" {
		t.Fatalf("expected status metadata")
	}
}

func assertCloudFrontMetricQuery(t *testing.T, input *cloudwatch.GetMetricDataInput, distributionID string) {
	t.Helper()

	for _, query := range input.MetricDataQueries {
		if query.MetricStat == nil || query.MetricStat.Metric == nil {
			continue
		}
		dimensions := query.MetricStat.Metric.Dimensions
		if dimensionValue(dimensions, cloudFrontDistributionDim) != distributionID {
			continue
		}

		if awssdk.ToString(query.MetricStat.Metric.Namespace) != cloudFrontNamespace {
			t.Fatalf("expected namespace %s, got %s", cloudFrontNamespace, awssdk.ToString(query.MetricStat.Metric.Namespace))
		}
		if awssdk.ToString(query.MetricStat.Metric.MetricName) != cloudFrontRequestsMetric {
			t.Fatalf("expected metric %s, got %s", cloudFrontRequestsMetric, awssdk.ToString(query.MetricStat.Metric.MetricName))
		}
		if dimensionValue(dimensions, cloudFrontRegionDim) != cloudFrontMetricRegion {
			t.Fatalf("expected Region=%s dimension, got %#v", cloudFrontMetricRegion, dimensions)
		}
		return
	}

	t.Fatalf("metric query for distribution %s not found: %#v", distributionID, input.MetricDataQueries)
}

func dimensionValue(dimensions []cwtypes.Dimension, name string) string {
	for _, dimension := range dimensions {
		if awssdk.ToString(dimension.Name) == name {
			return awssdk.ToString(dimension.Value)
		}
	}
	return ""
}

type fakeCloudFrontClient struct {
	pages []*cloudfront.ListDistributionsOutput
	err   error
	calls int
}

func (f *fakeCloudFrontClient) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return nil, fmt.Errorf("unexpected ListDistributions call %d", f.calls+1)
	}
	page := f.pages[f.calls]
	f.calls++
	return page, nil
}

type fakeCloudWatchClient struct {
	values map[string]float64
	inputs []*cloudwatch.GetMetricDataInput
	err    error
}

func (f *fakeCloudWatchClient) GetMetricData(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	f.inputs = append(f.inputs, input)
	if f.err != nil {
		return nil, f.err
	}

	results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
	for _, query := range input.MetricDataQueries {
		if query.MetricStat == nil || query.MetricStat.Metric == nil {
			continue
		}
		distributionID := dimensionValue(query.MetricStat.Metric.Dimensions, cloudFrontDistributionDim)
		results = append(results, cwtypes.MetricDataResult{
			Id:     query.Id,
			Values: []float64{f.values[distributionID]},
		})
	}

	return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
}

type fakeResourceScanner struct {
	resourceType      ResourceType
	resourcesScanned  int
	scanRuns          *int
	findingResourceID string
}

func (s *fakeResourceScanner) Scan(context.Context, ScanConfig) (*ScanResult, error) {
	*s.scanRuns++
	return &ScanResult{
		Findings: []Finding{
			{
				ID:           FindingCloudFrontIdle,
				ResourceType: s.resourceType,
				ResourceID:   s.findingResourceID,
				Region:       cloudFrontFindingRegion,
			},
		},
		ResourcesScanned: s.resourcesScanned,
	}, nil
}

func (s *fakeResourceScanner) Type() ResourceType {
	return s.resourceType
}
