package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type mockLogsClient struct {
	groups []logstypes.LogGroup
	tags   map[string]map[string]string // log group ARN -> tags
}

func (m *mockLogsClient) DescribeLogGroups(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: m.groups}, nil
}

func (m *mockLogsClient) ListTagsForResource(_ context.Context, input *cloudwatchlogs.ListTagsForResourceInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListTagsForResourceOutput, error) {
	return &cloudwatchlogs.ListTagsForResourceOutput{Tags: m.tags[*input.ResourceArn]}, nil
}

func TestLogsScanner_NoRetentionPolicy_Flagged(t *testing.T) {
	mock := &mockLogsClient{
		groups: []logstypes.LogGroup{
			{
				LogGroupName: awssdk.String("/aws/lambda/my-func"),
				Arn:          awssdk.String("arn:aws:logs:us-east-1:123:log-group:/aws/lambda/my-func:*"),
				LogGroupArn:  awssdk.String("arn:aws:logs:us-east-1:123:log-group:/aws/lambda/my-func"),
				StoredBytes:  awssdk.Int64(5 * 1024 * 1024 * 1024), // 5 GiB
			},
		},
	}
	scanner := NewLogsScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
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
	if f.ID != FindingLogGroupNoRetention {
		t.Fatalf("expected LOG_GROUP_NO_RETENTION, got %s", f.ID)
	}
	if f.ResourceType != ResourceLogGroup {
		t.Fatalf("expected ResourceLogGroup, got %s", f.ResourceType)
	}
	if f.ResourceID != "/aws/lambda/my-func" {
		t.Fatalf("expected resource id /aws/lambda/my-func, got %s", f.ResourceID)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate for 5 GiB stored")
	}
	if !f.Hygiene {
		t.Fatal("expected Hygiene=true even when real cost is present — visibility must not depend on current cost")
	}
}

func TestLogsScanner_WithRetentionPolicy_NotFlagged(t *testing.T) {
	mock := &mockLogsClient{
		groups: []logstypes.LogGroup{
			{
				LogGroupName:    awssdk.String("/aws/lambda/retained-func"),
				RetentionInDays: awssdk.Int32(30),
			},
		},
	}
	scanner := NewLogsScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for log group with retention set, got %d", len(result.Findings))
	}
}

func TestLogsScanner_ZeroStoredBytes_HygieneOnly(t *testing.T) {
	mock := &mockLogsClient{
		groups: []logstypes.LogGroup{
			{
				LogGroupName: awssdk.String("/aws/lambda/fresh-func"),
				StoredBytes:  awssdk.Int64(0),
			},
		},
	}
	scanner := NewLogsScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if !f.Hygiene {
		t.Fatal("expected Hygiene=true for a freshly-created log group with zero stored bytes")
	}
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected zero waste estimate, got %f", f.EstimatedMonthlyWaste)
	}
}

func TestLogsScanner_ExcludedByResourceID(t *testing.T) {
	mock := &mockLogsClient{
		groups: []logstypes.LogGroup{
			{LogGroupName: awssdk.String("/aws/lambda/excluded-func")},
		},
	}
	scanner := NewLogsScanner(mock, "us-east-1")

	cfg := ScanConfig{
		Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"/aws/lambda/excluded-func": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded log group, got %d", len(result.Findings))
	}
}

func TestLogsScanner_ExcludedByTag(t *testing.T) {
	arn := "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/tagged-func"
	mock := &mockLogsClient{
		groups: []logstypes.LogGroup{
			{LogGroupName: awssdk.String("/aws/lambda/tagged-func"), LogGroupArn: awssdk.String(arn)},
		},
		tags: map[string]map[string]string{
			arn: {"Team": "payments"},
		},
	}
	scanner := NewLogsScanner(mock, "us-east-1")

	cfg := ScanConfig{
		Exclude: ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for tag-excluded log group, got %d", len(result.Findings))
	}
}

func TestLogsScanner_NoGroups(t *testing.T) {
	mock := &mockLogsClient{groups: nil}
	scanner := NewLogsScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestLogsScanner_Type(t *testing.T) {
	scanner := &LogsScanner{}
	if scanner.Type() != ResourceLogGroup {
		t.Fatalf("expected ResourceLogGroup, got %s", scanner.Type())
	}
}
