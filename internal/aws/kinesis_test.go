package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

type mockKinesisClient struct {
	streams   []string
	summaries map[string]*kinesis.DescribeStreamSummaryOutput
}

func (m *mockKinesisClient) ListStreams(_ context.Context, _ *kinesis.ListStreamsInput, _ ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	return &kinesis.ListStreamsOutput{
		StreamNames:    m.streams,
		HasMoreStreams: awssdk.Bool(false),
	}, nil
}

func (m *mockKinesisClient) DescribeStreamSummary(_ context.Context, input *kinesis.DescribeStreamSummaryInput, _ ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	if out, ok := m.summaries[*input.StreamName]; ok {
		return out, nil
	}
	return nil, fmt.Errorf("stream not found: %s", *input.StreamName)
}

type mockFirehoseClient struct {
	streams []string
}

func (m *mockFirehoseClient) ListDeliveryStreams(_ context.Context, _ *firehose.ListDeliveryStreamsInput, _ ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	return &firehose.ListDeliveryStreamsOutput{
		DeliveryStreamNames:    m.streams,
		HasMoreDeliveryStreams: awssdk.Bool(false),
	}, nil
}

func makeKinesisSummary(shardCount int32, mode kinesistypes.StreamMode, arn string) *kinesis.DescribeStreamSummaryOutput {
	return &kinesis.DescribeStreamSummaryOutput{
		StreamDescriptionSummary: &kinesistypes.StreamDescriptionSummary{
			OpenShardCount:    awssdk.Int32(shardCount),
			StreamARN:         awssdk.String(arn),
			StreamModeDetails: &kinesistypes.StreamModeDetails{StreamMode: mode},
		},
	}
}

func zeroMetricsFetcher() *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{0},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})
}

func activeMetricsFetcher(value float64) *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{value},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})
}

func TestKinesisScanner_IdleStream(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"idle-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"idle-stream": makeKinesisSummary(4, kinesistypes.StreamModeProvisioned, "arn:aws:kinesis:us-east-1:123:stream/idle-stream"),
		},
	}

	scanner := NewKinesisScanner(mock, zeroMetricsFetcher(), "us-east-1")
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
	if f.ID != FindingKinesisStreamIdle {
		t.Fatalf("expected KINESIS_STREAM_IDLE, got %s", f.ID)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste <= 0 {
		t.Fatalf("expected non-zero waste for provisioned idle stream, got %f", f.EstimatedMonthlyWaste)
	}
	if f.Metadata["shard_count"] != int32(4) {
		t.Fatalf("expected 4 shards, got %v", f.Metadata["shard_count"])
	}
}

func TestKinesisScanner_ActiveStream(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"active-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"active-stream": makeKinesisSummary(2, kinesistypes.StreamModeProvisioned, "arn:aws:kinesis:us-east-1:123:stream/active-stream"),
		},
	}

	// Return high values for all metrics (active stream with good utilization)
	// 2 shards × 1MB/s × 604800s = ~1.27TB capacity over 7 days; 200GB = ~15.8% utilization
	scanner := NewKinesisScanner(mock, activeMetricsFetcher(200_000_000_000), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active stream, got %d", len(result.Findings))
	}
}

func TestKinesisScanner_OverProvisioned(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"over-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"over-stream": makeKinesisSummary(10, kinesistypes.StreamModeProvisioned, "arn:aws:kinesis:us-east-1:123:stream/over-stream"),
		},
	}

	// IncomingRecords > 0 (not idle) but IncomingBytes very low relative to 10 shards
	// 10 shards = 10 MB/s capacity. 100 bytes/s over 7 days is < 1% utilization
	metrics := NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				val := 1.0 // IncomingRecords and GetRecords.Records > 0 (not idle)
				if q.MetricStat != nil && *q.MetricStat.Metric.MetricName == "IncomingBytes" {
					val = 100.0 // Very low bytes — under-provisioned threshold
				}
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{val},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})

	scanner := NewKinesisScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingKinesisOverProvisioned {
		t.Fatalf("expected KINESIS_OVER_PROVISIONED, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
}

func TestKinesisScanner_OnDemandIdle(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"ondemand-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"ondemand-stream": makeKinesisSummary(2, kinesistypes.StreamModeOnDemand, "arn:aws:kinesis:us-east-1:123:stream/ondemand-stream"),
		},
	}

	scanner := NewKinesisScanner(mock, zeroMetricsFetcher(), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingKinesisStreamIdle {
		t.Fatalf("expected KINESIS_STREAM_IDLE, got %s", f.ID)
	}
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected $0 waste for on-demand idle stream, got %f", f.EstimatedMonthlyWaste)
	}
}

func TestKinesisScanner_Excluded(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"excluded-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"excluded-stream": makeKinesisSummary(2, kinesistypes.StreamModeProvisioned, "arn:aws:kinesis:us-east-1:123:stream/excluded-stream"),
		},
	}

	scanner := NewKinesisScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"excluded-stream": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded stream, got %d", len(result.Findings))
	}
}

func TestFirehoseScanner_IdleStream(t *testing.T) {
	mock := &mockFirehoseClient{streams: []string{"idle-firehose"}}

	scanner := NewFirehoseScanner(mock, zeroMetricsFetcher(), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingKinesisFirehoseIdle {
		t.Fatalf("expected KINESIS_FIREHOSE_IDLE, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected $0 waste, got %f", f.EstimatedMonthlyWaste)
	}
}

func TestFirehoseScanner_ActiveStream(t *testing.T) {
	mock := &mockFirehoseClient{streams: []string{"active-firehose"}}

	scanner := NewFirehoseScanner(mock, activeMetricsFetcher(1000), "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active firehose, got %d", len(result.Findings))
	}
}
