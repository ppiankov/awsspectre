package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// LogsAPI is the minimal interface for CloudWatch Logs operations.
type LogsAPI interface {
	DescribeLogGroups(ctx context.Context, input *cloudwatchlogs.DescribeLogGroupsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	ListTagsForResource(ctx context.Context, input *cloudwatchlogs.ListTagsForResourceInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListTagsForResourceOutput, error)
}

// LogsScanner detects CloudWatch Log Groups with no retention policy set.
type LogsScanner struct {
	client LogsAPI
	region string
}

// NewLogsScanner creates a scanner for CloudWatch Log Groups.
func NewLogsScanner(client LogsAPI, region string) *LogsScanner {
	return &LogsScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *LogsScanner) Type() ResourceType {
	return ResourceLogGroup
}

// Scan examines all log groups for a missing retention policy.
func (s *LogsScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	groups, err := s.listLogGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list log groups: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(groups)}
	if len(groups) == 0 {
		return result, nil
	}

	for _, lg := range groups {
		if lg.RetentionInDays != nil {
			continue
		}

		name := deref(lg.LogGroupName)
		tags, err := s.fetchTags(ctx, deref(lg.LogGroupArn))
		if err != nil {
			slog.Warn("Failed to fetch log group tags", "log_group", name, "error", err)
			tags = nil
		}
		if cfg.Exclude.ShouldExclude(name, tags) {
			continue
		}

		storedBytes := int64(0)
		if lg.StoredBytes != nil {
			storedBytes = *lg.StoredBytes
		}
		cost := pricing.MonthlyCloudWatchLogsStorageCost(storedBytes, s.region)

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingLogGroupNoRetention,
			Severity:              SeverityMedium,
			ResourceType:          ResourceLogGroup,
			ResourceID:            name,
			ResourceName:          deref(lg.Arn),
			Region:                s.region,
			Message:               fmt.Sprintf("No retention policy set — log events are kept indefinitely (%d bytes stored)", storedBytes),
			EstimatedMonthlyWaste: cost,
			// Always visible regardless of --min-monthly-cost: the risk is
			// unbounded FUTURE growth, not today's accumulated storage cost.
			// A log group with $0.02/month stored today is exactly as much a
			// retention-policy gap as one with $0 — gating visibility on the
			// current cost silently hid most real findings in dogfood testing.
			Hygiene: true,
			Metadata: map[string]any{
				"stored_bytes": storedBytes,
				"log_class":    string(lg.LogGroupClass),
			},
		})
	}

	return result, nil
}

func (s *LogsScanner) listLogGroups(ctx context.Context) ([]logstypes.LogGroup, error) {
	var groups []logstypes.LogGroup
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(s.client, &cloudwatchlogs.DescribeLogGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.LogGroups...)
	}
	return groups, nil
}

// fetchTags fetches all tags for a log group (ListTagsForResource has no
// pagination and no bulk/batched variant).
func (s *LogsScanner) fetchTags(ctx context.Context, logGroupArn string) (map[string]string, error) {
	if logGroupArn == "" {
		return nil, nil
	}
	out, err := s.client.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: &logGroupArn})
	if err != nil {
		return nil, err
	}
	return out.Tags, nil
}
