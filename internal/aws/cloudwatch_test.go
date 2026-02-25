package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type mockCloudWatchClient struct {
	getMetricDataFn func(ctx context.Context, input *cloudwatch.GetMetricDataInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

func (m *mockCloudWatchClient) GetMetricData(ctx context.Context, input *cloudwatch.GetMetricDataInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	return m.getMetricDataFn(ctx, input, opts...)
}

func TestMetricsFetcher_FetchAverage(t *testing.T) {
	mock := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{10.0, 20.0, 30.0},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}

	fetcher := NewMetricsFetcher(mock)
	result, err := fetcher.FetchAverage(context.Background(), "AWS/EC2", "CPUUtilization", "InstanceId", []string{"i-001", "i-002"}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}

	// Average of 10, 20, 30 = 20
	if result["i-001"] != 20.0 {
		t.Fatalf("expected average 20.0, got %f", result["i-001"])
	}
}

func TestMetricsFetcher_FetchSum(t *testing.T) {
	mock := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{100.0, 200.0},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}

	fetcher := NewMetricsFetcher(mock)
	result, err := fetcher.FetchSum(context.Background(), "AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", []string{"nat-001"}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Sum of 100 + 200 = 300
	if result["nat-001"] != 300.0 {
		t.Fatalf("expected sum 300.0, got %f", result["nat-001"])
	}
}

func TestMetricsFetcher_EmptyIDs(t *testing.T) {
	fetcher := NewMetricsFetcher(nil)
	result, err := fetcher.FetchAverage(context.Background(), "AWS/EC2", "CPUUtilization", "InstanceId", nil, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for empty IDs, got %v", result)
	}
}

func TestMetricsFetcher_NoDataPoints(t *testing.T) {
	mock := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{}},
				},
			}, nil
		},
	}

	fetcher := NewMetricsFetcher(mock)
	result, err := fetcher.FetchAverage(context.Background(), "AWS/EC2", "CPUUtilization", "InstanceId", []string{"i-001"}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No data points means no result entry
	if _, ok := result["i-001"]; ok {
		t.Fatal("expected no result for instance with no data points")
	}
}

func TestMetricsFetcher_APIError(t *testing.T) {
	mock := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return nil, fmt.Errorf("throttling: rate exceeded")
		},
	}

	fetcher := NewMetricsFetcher(mock)
	_, err := fetcher.FetchAverage(context.Background(), "AWS/EC2", "CPUUtilization", "InstanceId", []string{"i-001"}, 7)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBatchIDs(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		batchSize int
		wantCount int
	}{
		{"empty", 0, 500, 0},
		{"under limit", 100, 500, 1},
		{"exact limit", 500, 500, 1},
		{"over limit", 501, 500, 2},
		{"multiple batches", 1500, 500, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := make([]string, tt.count)
			for i := range ids {
				ids[i] = fmt.Sprintf("id-%d", i)
			}
			batches := batchIDs(ids, tt.batchSize)
			if len(batches) != tt.wantCount {
				t.Fatalf("expected %d batches, got %d", tt.wantCount, len(batches))
			}

			// Verify all IDs are present
			total := 0
			for _, b := range batches {
				total += len(b)
			}
			if total != tt.count {
				t.Fatalf("expected %d total IDs, got %d", tt.count, total)
			}
		})
	}
}
