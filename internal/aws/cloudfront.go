package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

const (
	cloudFrontControlPlaneRegion = "us-east-1"
	cloudFrontFindingRegion      = "global"
	cloudFrontMetricRegion       = "Global"
	cloudFrontNamespace          = "AWS/CloudFront"
	cloudFrontRequestsMetric     = "Requests"
	cloudFrontDistributionDim    = "DistributionId"
	cloudFrontRegionDim          = "Region"
)

// CloudFrontAPI is the minimal CloudFront surface needed by the scanner.
// WO-189: keeps distribution listing testable without live AWS calls.
type CloudFrontAPI interface {
	ListDistributions(ctx context.Context, input *cloudfront.ListDistributionsInput, opts ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

// CloudFrontScanner detects disabled and zero-traffic CloudFront distributions.
// WO-189: global hygiene scanner for disabled and idle CloudFront distributions.
type CloudFrontScanner struct {
	client  CloudFrontAPI   // WO-189: global CloudFront control-plane client.
	metrics *MetricsFetcher // WO-189: us-east-1 CloudWatch metrics fetcher.
}

// NewCloudFrontScanner creates a CloudFront scanner.
func NewCloudFrontScanner(client CloudFrontAPI, metrics *MetricsFetcher) *CloudFrontScanner {
	return &CloudFrontScanner{client: client, metrics: metrics}
}

func (s *CloudFrontScanner) Type() ResourceType {
	return ResourceCloudFront
}

func (s *CloudFrontScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("cloudfront client is required")
	}

	distributions, err := s.listDistributions(ctx)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		ResourcesScanned: len(distributions),
	}

	enabled := make(map[string]cftypes.DistributionSummary, len(distributions))
	enabledIDs := make([]string, 0, len(distributions))

	for _, distribution := range distributions {
		id := awssdk.ToString(distribution.Id)
		if id == "" {
			continue
		}
		if cfg.Exclude.ShouldExclude(id, nil) {
			continue
		}

		if !awssdk.ToBool(distribution.Enabled) {
			result.Findings = append(result.Findings, cloudFrontFinding(
				FindingCloudFrontDisabled,
				SeverityLow,
				distribution,
				"CloudFront distribution is disabled but still exists",
			))
			continue
		}

		enabled[id] = distribution
		enabledIDs = append(enabledIDs, id)
	}

	if len(enabledIDs) == 0 {
		return result, nil
	}
	if s.metrics == nil {
		return nil, fmt.Errorf("cloudfront metrics fetcher is required")
	}

	requests, err := s.metrics.FetchSumWithStaticDim(
		ctx,
		cloudFrontNamespace,
		cloudFrontRequestsMetric,
		cloudFrontDistributionDim,
		enabledIDs,
		cfg.IdleDays,
		[]cwtypes.Dimension{
			{
				Name:  awssdk.String(cloudFrontRegionDim),
				Value: awssdk.String(cloudFrontMetricRegion),
			},
		},
	)
	if err != nil {
		return nil, err
	}

	for _, id := range enabledIDs {
		if requests[id] > 0 {
			continue
		}
		result.Findings = append(result.Findings, cloudFrontFinding(
			FindingCloudFrontIdle,
			SeverityMedium,
			enabled[id],
			fmt.Sprintf("CloudFront distribution had zero requests over the last %d days", cfg.IdleDays),
		))
	}

	return result, nil
}

func (s *CloudFrontScanner) listDistributions(ctx context.Context) ([]cftypes.DistributionSummary, error) {
	paginator := cloudfront.NewListDistributionsPaginator(s.client, &cloudfront.ListDistributionsInput{})
	var distributions []cftypes.DistributionSummary

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list cloudfront distributions: %w", err)
		}
		if page.DistributionList == nil {
			continue
		}
		distributions = append(distributions, page.DistributionList.Items...)
	}

	return distributions, nil
}

func cloudFrontFinding(id FindingID, severity Severity, distribution cftypes.DistributionSummary, message string) Finding {
	return Finding{
		ID:                    id,
		Severity:              severity,
		ResourceType:          ResourceCloudFront,
		ResourceID:            awssdk.ToString(distribution.Id),
		ResourceName:          awssdk.ToString(distribution.ARN),
		Region:                cloudFrontFindingRegion,
		Message:               message,
		EstimatedMonthlyWaste: 0,
		Metadata:              cloudFrontMetadata(distribution),
	}
}

func cloudFrontMetadata(distribution cftypes.DistributionSummary) map[string]any {
	metadata := map[string]any{
		"domain_name": awssdk.ToString(distribution.DomainName),
		"status":      awssdk.ToString(distribution.Status),
	}
	if distribution.Aliases != nil && len(distribution.Aliases.Items) > 0 {
		metadata["aliases"] = distribution.Aliases.Items
	}
	return metadata
}
