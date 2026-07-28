package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type mockSQSClient struct {
	queueURLs  []string
	attributes map[string]map[string]string // queueURL → attributes
	tags       map[string]map[string]string // queueURL → tags
}

func (m *mockSQSClient) ListQueueTags(_ context.Context, input *sqs.ListQueueTagsInput, _ ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error) {
	return &sqs.ListQueueTagsOutput{Tags: m.tags[*input.QueueUrl]}, nil
}

func (m *mockSQSClient) ListQueues(_ context.Context, _ *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	return &sqs.ListQueuesOutput{QueueUrls: m.queueURLs}, nil
}

func (m *mockSQSClient) GetQueueAttributes(_ context.Context, input *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	attrs := m.attributes[*input.QueueUrl]
	if attrs == nil {
		attrs = map[string]string{}
	}
	return &sqs.GetQueueAttributesOutput{Attributes: attrs}, nil
}

func TestSQSScanner_IdleQueue(t *testing.T) {
	mock := &mockSQSClient{
		queueURLs: []string{"https://sqs.us-east-1.amazonaws.com/123/idle-queue"},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/idle-queue": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:idle-queue",
			},
		},
	}

	scanner := NewSQSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingSQSIdle {
		t.Fatalf("expected SQS_IDLE, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.ResourceID != "idle-queue" {
		t.Fatalf("expected idle-queue, got %s", f.ResourceID)
	}
}

func TestSQSScanner_NoConsumer(t *testing.T) {
	mock := &mockSQSClient{
		queueURLs: []string{"https://sqs.us-east-1.amazonaws.com/123/no-consumer-queue"},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/no-consumer-queue": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:no-consumer-queue",
			},
		},
	}

	// Sent > 0, Received = 0
	callCount := 0
	metrics := NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			callCount++
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				val := 100.0 // NumberOfMessagesSent > 0
				if callCount == 2 {
					val = 0 // NumberOfMessagesReceived = 0
				}
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{val},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})

	scanner := NewSQSScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingSQSNoConsumer {
		t.Fatalf("expected SQS_NO_CONSUMER, got %s", f.ID)
	}
}

func TestSQSScanner_DLQOrphaned(t *testing.T) {
	mock := &mockSQSClient{
		queueURLs: []string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue",
			"https://sqs.us-east-1.amazonaws.com/123/orphaned-dlq",
		},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:source-queue",
				// RedrivePolicy points to a different DLQ (not orphaned-dlq)
				"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123:other-dlq"}`,
			},
			"https://sqs.us-east-1.amazonaws.com/123/orphaned-dlq": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:orphaned-dlq",
				// Has RedriveAllowPolicy — it's a DLQ
				"RedriveAllowPolicy": `{"redrivePermission":"allowAll"}`,
			},
		},
	}

	// Both queues active — no idle/no-consumer findings
	scanner := NewSQSScanner(mock, activeMetricsFetcher(500), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have the DLQ orphaned finding
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingSQSDLQOrphaned {
		t.Fatalf("expected SQS_DLQ_ORPHANED, got %s", f.ID)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.ResourceID != "orphaned-dlq" {
		t.Fatalf("expected orphaned-dlq, got %s", f.ResourceID)
	}
}

func TestSQSScanner_ActiveQueue(t *testing.T) {
	mock := &mockSQSClient{
		queueURLs: []string{"https://sqs.us-east-1.amazonaws.com/123/active-queue"},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/active-queue": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:active-queue",
			},
		},
	}

	scanner := NewSQSScanner(mock, activeMetricsFetcher(1000), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active queue, got %d", len(result.Findings))
	}
}

func TestSQSScanner_Excluded(t *testing.T) {
	mock := &mockSQSClient{
		queueURLs: []string{"https://sqs.us-east-1.amazonaws.com/123/excluded-queue"},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/excluded-queue": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:excluded-queue",
			},
		},
	}

	scanner := NewSQSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude: ExcludeConfig{
			ResourceIDs: map[string]bool{"excluded-queue": true},
		},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded queue, got %d", len(result.Findings))
	}
}

func TestSQSScanner_ExcludedByTag(t *testing.T) {
	url := "https://sqs.us-east-1.amazonaws.com/123/tagged-queue"
	mock := &mockSQSClient{
		queueURLs: []string{url},
		attributes: map[string]map[string]string{
			url: {"QueueArn": "arn:aws:sqs:us-east-1:123:tagged-queue"},
		},
		tags: map[string]map[string]string{
			url: {"Team": "payments"},
		},
	}

	scanner := NewSQSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for tag-excluded queue, got %d", len(result.Findings))
	}
}

func TestSQSScanner_ReferencedDLQ_ZeroMessages_NotFlaggedIdle(t *testing.T) {
	// WO-245: a live dogfood scan found 7 of 38 SQS_IDLE findings were
	// structurally-confirmed DLQ targets of other live queues — zero messages
	// in a healthy DLQ is the correct, expected state, not waste.
	mock := &mockSQSClient{
		queueURLs: []string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue",
			"https://sqs.us-east-1.amazonaws.com/123/billing-dlq",
		},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue": {
				"QueueArn":      "arn:aws:sqs:us-east-1:123:source-queue",
				"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123:billing-dlq"}`,
			},
			"https://sqs.us-east-1.amazonaws.com/123/billing-dlq": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:billing-dlq",
			},
		},
	}

	// Both queues report zero sent/received — source-queue is genuinely idle,
	// billing-dlq is a healthy DLQ that should be excluded.
	scanner := NewSQSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding (source-queue only), got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].ResourceID != "source-queue" {
		t.Fatalf("expected the finding to be for source-queue, not the DLQ, got %s", result.Findings[0].ResourceID)
	}
}

func TestSQSScanner_ReferencedDLQ_WithMessages_StillFlaggedNoConsumer(t *testing.T) {
	// A DLQ that DOES have undelivered messages (real failures landed there)
	// but nothing consuming them is a genuinely different, still-actionable
	// signal than "healthy and empty" — SQS_NO_CONSUMER must still fire.
	mock := &mockSQSClient{
		queueURLs: []string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue2",
			"https://sqs.us-east-1.amazonaws.com/123/billing-dlq2",
		},
		attributes: map[string]map[string]string{
			"https://sqs.us-east-1.amazonaws.com/123/source-queue2": {
				"QueueArn":      "arn:aws:sqs:us-east-1:123:source-queue2",
				"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123:billing-dlq2"}`,
			},
			"https://sqs.us-east-1.amazonaws.com/123/billing-dlq2": {
				"QueueArn": "arn:aws:sqs:us-east-1:123:billing-dlq2",
			},
		},
	}

	callCount := 0
	metrics := NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			callCount++
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				val := 0.0
				if callCount == 1 { // NumberOfMessagesSent
					val = 50
				}
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{val},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})

	scanner := NewSQSScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var dlqFinding *Finding
	for i := range result.Findings {
		if result.Findings[i].ResourceID == "billing-dlq2" {
			dlqFinding = &result.Findings[i]
		}
	}
	if dlqFinding == nil {
		t.Fatalf("expected a finding for billing-dlq2 (messages piling up unconsumed), got %+v", result.Findings)
	}
	if dlqFinding.ID != FindingSQSNoConsumer {
		t.Fatalf("expected SQS_NO_CONSUMER for the DLQ with undelivered messages, got %s", dlqFinding.ID)
	}
}

// sqsAttributeName is used to verify the constant values
func TestSQSScanner_Type(t *testing.T) {
	scanner := &SQSScanner{}
	if scanner.Type() != ResourceSQS {
		t.Fatalf("expected ResourceSQS, got %s", scanner.Type())
	}

	// Verify attribute name constants are correct
	if sqstypes.QueueAttributeNameRedrivePolicy != "RedrivePolicy" {
		t.Fatal("unexpected RedrivePolicy attribute name")
	}
}
