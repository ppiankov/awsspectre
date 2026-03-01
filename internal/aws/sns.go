package aws

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// SNSAPI is the minimal interface for SNS operations.
type SNSAPI interface {
	ListTopics(ctx context.Context, input *sns.ListTopicsInput, opts ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	ListSubscriptionsByTopic(ctx context.Context, input *sns.ListSubscriptionsByTopicInput, opts ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error)
}

// SNSScanner detects SNS topics with no subscribers or zero published messages.
type SNSScanner struct {
	client  SNSAPI
	metrics *MetricsFetcher
	region  string
}

// NewSNSScanner creates a scanner for SNS topics.
func NewSNSScanner(client SNSAPI, metrics *MetricsFetcher, region string) *SNSScanner {
	return &SNSScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *SNSScanner) Type() ResourceType {
	return ResourceSNS
}

// snsTopicInfo holds topic metadata.
type snsTopicInfo struct {
	arn             string
	name            string
	subscriberCount int
}

// Scan examines all SNS topics for no-subscriber and idle conditions.
func (s *SNSScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	topics, err := s.listTopics(ctx)
	if err != nil {
		return nil, fmt.Errorf("list SNS topics: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(topics)}
	if len(topics) == 0 {
		return result, nil
	}

	// Collect topic info with subscriber counts
	var topicInfos []snsTopicInfo
	var namesWithSubs []string
	for _, topic := range topics {
		arn := deref(topic.TopicArn)
		name := topicNameFromARN(arn)

		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}

		subCount, err := s.countSubscriptions(ctx, arn)
		if err != nil {
			slog.Warn("Failed to count SNS subscriptions", "topic", name, "error", err)
			continue
		}

		info := snsTopicInfo{arn: arn, name: name, subscriberCount: subCount}
		topicInfos = append(topicInfos, info)

		// SNS_NO_SUBSCRIBERS: zero subscriptions (structural check, no metrics needed)
		if subCount == 0 {
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingSNSNoSubscribers,
				Severity:              SeverityMedium,
				ResourceType:          ResourceSNS,
				ResourceID:            name,
				ResourceName:          arn,
				Region:                s.region,
				Message:               "Topic has zero subscriptions",
				EstimatedMonthlyWaste: 0,
			})
			continue
		}

		// Has subscribers — check for idle via CloudWatch
		namesWithSubs = append(namesWithSubs, name)
	}

	// Fetch published message counts for topics that have subscribers
	if len(namesWithSubs) > 0 {
		published, err := s.metrics.FetchSum(ctx, "AWS/SNS", "NumberOfMessagesPublished", "TopicName", namesWithSubs, cfg.IdleDays)
		if err != nil {
			slog.Warn("Failed to fetch SNS metrics", "region", s.region, "error", err)
			return result, nil
		}

		// Build lookup for subscriber count
		subMap := make(map[string]int, len(topicInfos))
		arnMap := make(map[string]string, len(topicInfos))
		for _, info := range topicInfos {
			subMap[info.name] = info.subscriberCount
			arnMap[info.name] = info.arn
		}

		for _, name := range namesWithSubs {
			if published[name] > 0 {
				continue
			}

			// SNS_IDLE: has subscribers but zero messages published
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingSNSIdle,
				Severity:              SeverityLow,
				ResourceType:          ResourceSNS,
				ResourceID:            name,
				ResourceName:          arnMap[name],
				Region:                s.region,
				Message:               fmt.Sprintf("Zero messages published over %d days (%d subscribers)", cfg.IdleDays, subMap[name]),
				EstimatedMonthlyWaste: 0,
				Metadata: map[string]any{
					"subscriber_count": subMap[name],
				},
			})
		}
	}

	return result, nil
}

func (s *SNSScanner) listTopics(ctx context.Context) ([]snstypes.Topic, error) {
	var topics []snstypes.Topic
	paginator := sns.NewListTopicsPaginator(s.client, &sns.ListTopicsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		topics = append(topics, page.Topics...)
	}
	return topics, nil
}

func (s *SNSScanner) countSubscriptions(ctx context.Context, topicARN string) (int, error) {
	count := 0
	input := &sns.ListSubscriptionsByTopicInput{TopicArn: &topicARN}

	for {
		out, err := s.client.ListSubscriptionsByTopic(ctx, input)
		if err != nil {
			return 0, err
		}
		count += len(out.Subscriptions)

		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}
	return count, nil
}

// topicNameFromARN extracts the topic name from an SNS topic ARN.
// e.g., "arn:aws:sns:us-east-1:123456789012:my-topic" → "my-topic"
func topicNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}
