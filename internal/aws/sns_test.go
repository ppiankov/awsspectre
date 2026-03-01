package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

type mockSNSClient struct {
	topics        []snstypes.Topic
	subscriptions map[string][]snstypes.Subscription // topicARN → subscriptions
}

func (m *mockSNSClient) ListTopics(_ context.Context, _ *sns.ListTopicsInput, _ ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	return &sns.ListTopicsOutput{Topics: m.topics}, nil
}

func (m *mockSNSClient) ListSubscriptionsByTopic(_ context.Context, input *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	subs := m.subscriptions[*input.TopicArn]
	return &sns.ListSubscriptionsByTopicOutput{Subscriptions: subs}, nil
}

func TestSNSScanner_NoSubscribers(t *testing.T) {
	mock := &mockSNSClient{
		topics: []snstypes.Topic{
			{TopicArn: awssdk.String("arn:aws:sns:us-east-1:123:empty-topic")},
		},
		subscriptions: map[string][]snstypes.Subscription{
			"arn:aws:sns:us-east-1:123:empty-topic": {},
		},
	}

	scanner := NewSNSScanner(mock, zeroMetricsFetcher(), "us-east-1")
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
	if f.ID != FindingSNSNoSubscribers {
		t.Fatalf("expected SNS_NO_SUBSCRIBERS, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.ResourceID != "empty-topic" {
		t.Fatalf("expected empty-topic, got %s", f.ResourceID)
	}
}

func TestSNSScanner_IdleTopic(t *testing.T) {
	mock := &mockSNSClient{
		topics: []snstypes.Topic{
			{TopicArn: awssdk.String("arn:aws:sns:us-east-1:123:idle-topic")},
		},
		subscriptions: map[string][]snstypes.Subscription{
			"arn:aws:sns:us-east-1:123:idle-topic": {
				{SubscriptionArn: awssdk.String("arn:aws:sns:us-east-1:123:idle-topic:sub1")},
				{SubscriptionArn: awssdk.String("arn:aws:sns:us-east-1:123:idle-topic:sub2")},
			},
		},
	}

	// Zero messages published
	scanner := NewSNSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingSNSIdle {
		t.Fatalf("expected SNS_IDLE, got %s", f.ID)
	}
	if f.Severity != SeverityLow {
		t.Fatalf("expected low severity, got %s", f.Severity)
	}
	if f.Metadata["subscriber_count"] != 2 {
		t.Fatalf("expected 2 subscribers, got %v", f.Metadata["subscriber_count"])
	}
}

func TestSNSScanner_ActiveTopic(t *testing.T) {
	mock := &mockSNSClient{
		topics: []snstypes.Topic{
			{TopicArn: awssdk.String("arn:aws:sns:us-east-1:123:active-topic")},
		},
		subscriptions: map[string][]snstypes.Subscription{
			"arn:aws:sns:us-east-1:123:active-topic": {
				{SubscriptionArn: awssdk.String("arn:aws:sns:us-east-1:123:active-topic:sub1")},
			},
		},
	}

	// Non-zero messages published
	metrics := NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{500},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})

	scanner := NewSNSScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active topic, got %d", len(result.Findings))
	}
}

func TestSNSScanner_Excluded(t *testing.T) {
	mock := &mockSNSClient{
		topics: []snstypes.Topic{
			{TopicArn: awssdk.String("arn:aws:sns:us-east-1:123:excluded-topic")},
		},
		subscriptions: map[string][]snstypes.Subscription{
			"arn:aws:sns:us-east-1:123:excluded-topic": {},
		},
	}

	scanner := NewSNSScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"excluded-topic": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded topic, got %d", len(result.Findings))
	}
}
