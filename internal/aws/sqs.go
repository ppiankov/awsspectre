package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// SQSAPI is the minimal interface for SQS operations.
type SQSAPI interface {
	ListQueues(ctx context.Context, input *sqs.ListQueuesInput, opts ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, input *sqs.GetQueueAttributesInput, opts ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// SQSScanner detects idle SQS queues, no-consumer queues, and orphaned DLQs.
type SQSScanner struct {
	client  SQSAPI
	metrics *MetricsFetcher
	region  string
}

// NewSQSScanner creates a scanner for SQS queues.
func NewSQSScanner(client SQSAPI, metrics *MetricsFetcher, region string) *SQSScanner {
	return &SQSScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *SQSScanner) Type() ResourceType {
	return ResourceSQS
}

// sqsQueueInfo holds metadata from GetQueueAttributes.
type sqsQueueInfo struct {
	url                string
	name               string
	arn                string
	redrivePolicy      string
	redriveAllowPolicy string
}

// Scan examines all SQS queues for idle, no-consumer, and orphaned DLQ conditions.
func (s *SQSScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	queueURLs, err := s.listQueues(ctx)
	if err != nil {
		return nil, fmt.Errorf("list SQS queues: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(queueURLs)}
	if len(queueURLs) == 0 {
		return result, nil
	}

	// Fetch attributes for all queues
	var queues []sqsQueueInfo
	for _, url := range queueURLs {
		name := queueNameFromURL(url)
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}

		info, err := s.getQueueInfo(ctx, url)
		if err != nil {
			slog.Warn("Failed to get SQS queue attributes", "queue", name, "error", err)
			continue
		}
		queues = append(queues, info)
	}

	if len(queues) == 0 {
		return result, nil
	}

	// Build set of DLQ ARNs actively referenced by other queues
	referencedDLQArns := make(map[string]bool)
	for _, q := range queues {
		if q.redrivePolicy == "" {
			continue
		}
		dlqArn := parseDLQArn(q.redrivePolicy)
		if dlqArn != "" {
			referencedDLQArns[dlqArn] = true
		}
	}

	// Collect queue names for CloudWatch lookup
	var names []string
	queueMap := make(map[string]sqsQueueInfo, len(queues))
	for _, q := range queues {
		names = append(names, q.name)
		queueMap[q.name] = q
	}

	// Fetch CloudWatch metrics
	sent, err := s.metrics.FetchSum(ctx, "AWS/SQS", "NumberOfMessagesSent", "QueueName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch SQS sent metrics", "region", s.region, "error", err)
		return result, nil
	}

	received, err := s.metrics.FetchSum(ctx, "AWS/SQS", "NumberOfMessagesReceived", "QueueName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch SQS received metrics", "region", s.region, "error", err)
		return result, nil
	}

	for _, name := range names {
		q := queueMap[name]
		sentCount := sent[name]
		receivedCount := received[name]

		// SQS_IDLE: zero sent and zero received
		if sentCount == 0 && receivedCount == 0 {
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingSQSIdle,
				Severity:              SeverityMedium,
				ResourceType:          ResourceSQS,
				ResourceID:            q.name,
				ResourceName:          q.arn,
				Region:                s.region,
				Message:               fmt.Sprintf("Zero messages sent and received over %d days", cfg.IdleDays),
				EstimatedMonthlyWaste: 0,
			})
			continue
		}

		// SQS_NO_CONSUMER: messages sent but zero received
		if sentCount > 0 && receivedCount == 0 {
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingSQSNoConsumer,
				Severity:              SeverityMedium,
				ResourceType:          ResourceSQS,
				ResourceID:            q.name,
				ResourceName:          q.arn,
				Region:                s.region,
				Message:               fmt.Sprintf("%.0f messages sent but zero received over %d days", sentCount, cfg.IdleDays),
				EstimatedMonthlyWaste: 0,
				Metadata: map[string]any{
					"messages_sent": sentCount,
				},
			})
			continue
		}
	}

	// SQS_DLQ_ORPHANED: queue has RedriveAllowPolicy but no active source references it
	for _, q := range queues {
		if q.redriveAllowPolicy == "" {
			continue
		}
		if referencedDLQArns[q.arn] {
			continue
		}
		result.Findings = append(result.Findings, Finding{
			ID:                    FindingSQSDLQOrphaned,
			Severity:              SeverityHigh,
			ResourceType:          ResourceSQS,
			ResourceID:            q.name,
			ResourceName:          q.arn,
			Region:                s.region,
			Message:               "Dead-letter queue with no active source queue",
			EstimatedMonthlyWaste: 0,
		})
	}

	return result, nil
}

func (s *SQSScanner) listQueues(ctx context.Context) ([]string, error) {
	var urls []string
	paginator := sqs.NewListQueuesPaginator(s.client, &sqs.ListQueuesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		urls = append(urls, page.QueueUrls...)
	}
	return urls, nil
}

func (s *SQSScanner) getQueueInfo(ctx context.Context, queueURL string) (sqsQueueInfo, error) {
	out, err := s.client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: &queueURL,
		AttributeNames: []sqstypes.QueueAttributeName{
			sqstypes.QueueAttributeNameQueueArn,
			sqstypes.QueueAttributeNameRedrivePolicy,
			sqstypes.QueueAttributeNameRedriveAllowPolicy,
		},
	})
	if err != nil {
		return sqsQueueInfo{}, err
	}

	return sqsQueueInfo{
		url:                queueURL,
		name:               queueNameFromURL(queueURL),
		arn:                out.Attributes["QueueArn"],
		redrivePolicy:      out.Attributes["RedrivePolicy"],
		redriveAllowPolicy: out.Attributes["RedriveAllowPolicy"],
	}, nil
}

// queueNameFromURL extracts the queue name from an SQS queue URL.
// e.g., "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue" → "my-queue"
func queueNameFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

// parseDLQArn extracts deadLetterTargetArn from a RedrivePolicy JSON string.
func parseDLQArn(redrivePolicy string) string {
	var policy struct {
		DeadLetterTargetArn string `json:"deadLetterTargetArn"`
	}
	if err := json.Unmarshal([]byte(redrivePolicy), &policy); err != nil {
		return ""
	}
	return policy.DeadLetterTargetArn
}
