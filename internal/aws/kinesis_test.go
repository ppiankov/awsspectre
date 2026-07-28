package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

type mockKinesisClient struct {
	streams   []string
	summaries map[string]*kinesis.DescribeStreamSummaryOutput
	tags      map[string][]kinesistypes.Tag
}

func (m *mockKinesisClient) ListTagsForStream(_ context.Context, input *kinesis.ListTagsForStreamInput, _ ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error) {
	return &kinesis.ListTagsForStreamOutput{
		Tags:        m.tags[*input.StreamName],
		HasMoreTags: awssdk.Bool(false),
	}, nil
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
	tags    map[string][]firehosetypes.Tag
	// streamTypes maps delivery stream name to its type; unset names default
	// to DirectPut, matching this scanner's pre-WO-244 behavior.
	streamTypes map[string]firehosetypes.DeliveryStreamType
	// describeErrors maps delivery stream name to an error DescribeDeliveryStream
	// should return for it, to exercise the safe-default fallback.
	describeErrors map[string]error
}

func (m *mockFirehoseClient) ListDeliveryStreams(_ context.Context, _ *firehose.ListDeliveryStreamsInput, _ ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	return &firehose.ListDeliveryStreamsOutput{
		DeliveryStreamNames:    m.streams,
		HasMoreDeliveryStreams: awssdk.Bool(false),
	}, nil
}

func (m *mockFirehoseClient) ListTagsForDeliveryStream(_ context.Context, input *firehose.ListTagsForDeliveryStreamInput, _ ...func(*firehose.Options)) (*firehose.ListTagsForDeliveryStreamOutput, error) {
	return &firehose.ListTagsForDeliveryStreamOutput{
		Tags:        m.tags[*input.DeliveryStreamName],
		HasMoreTags: awssdk.Bool(false),
	}, nil
}

func (m *mockFirehoseClient) DescribeDeliveryStream(_ context.Context, input *firehose.DescribeDeliveryStreamInput, _ ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error) {
	name := *input.DeliveryStreamName
	if err, ok := m.describeErrors[name]; ok {
		return nil, err
	}
	streamType := firehosetypes.DeliveryStreamTypeDirectPut
	if t, ok := m.streamTypes[name]; ok {
		streamType = t
	}
	return &firehose.DescribeDeliveryStreamOutput{
		DeliveryStreamDescription: &firehosetypes.DeliveryStreamDescription{
			DeliveryStreamName: &name,
			DeliveryStreamType: streamType,
		},
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
	if f.Hygiene {
		t.Fatalf("provisioned idle stream should remain cost-bearing, not hygiene")
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
	if !f.Hygiene {
		t.Fatalf("expected on-demand idle stream to be marked hygiene")
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

func TestKinesisScanner_ExcludedByTag(t *testing.T) {
	mock := &mockKinesisClient{
		streams: []string{"tagged-stream"},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"tagged-stream": makeKinesisSummary(2, kinesistypes.StreamModeProvisioned, "arn:aws:kinesis:us-east-1:123:stream/tagged-stream"),
		},
		tags: map[string][]kinesistypes.Tag{
			"tagged-stream": {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
		},
	}

	scanner := NewKinesisScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for tag-excluded stream, got %d", len(result.Findings))
	}
}

func TestFirehoseScanner_ExcludedByTag(t *testing.T) {
	mock := &mockFirehoseClient{
		streams: []string{"tagged-firehose"},
		tags: map[string][]firehosetypes.Tag{
			"tagged-firehose": {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
		},
	}

	scanner := NewFirehoseScanner(mock, zeroMetricsFetcher(), "us-east-1")
	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for tag-excluded firehose, got %d", len(result.Findings))
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

// metricNameAwareFetcher returns a fixed value per exact CloudWatch metric
// name, defaulting to 0 for any name not in values — used to prove a scanner
// queries the correct metric rather than merely queries *a* metric.
func metricNameAwareFetcher(values map[string]float64) *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				val := 0.0
				if q.MetricStat != nil && q.MetricStat.Metric != nil && q.MetricStat.Metric.MetricName != nil {
					val = values[*q.MetricStat.Metric.MetricName]
				}
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{val},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})
}

func TestFirehoseScanner_KinesisStreamAsSource_UsesCorrectMetric_NotIdle(t *testing.T) {
	// WO-244: a live dogfood account had a KinesisStreamAsSource delivery
	// stream (cloudfront-logs) with real DataReadFromKinesisStream.Records
	// activity, but AWS never emits IncomingRecords for that source type at
	// all — checking IncomingRecords unconditionally would always read zero.
	mock := &mockFirehoseClient{
		streams:     []string{"kinesis-sourced-firehose"},
		streamTypes: map[string]firehosetypes.DeliveryStreamType{"kinesis-sourced-firehose": firehosetypes.DeliveryStreamTypeKinesisStreamAsSource},
	}
	metrics := metricNameAwareFetcher(map[string]float64{"DataReadFromKinesisStream.Records": 500})

	scanner := NewFirehoseScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings — real DataReadFromKinesisStream.Records activity exists, got %d", len(result.Findings))
	}
}

func TestFirehoseScanner_KinesisStreamAsSource_GenuinelyIdle_StillFlagged(t *testing.T) {
	mock := &mockFirehoseClient{
		streams:     []string{"kinesis-sourced-idle"},
		streamTypes: map[string]firehosetypes.DeliveryStreamType{"kinesis-sourced-idle": firehosetypes.DeliveryStreamTypeKinesisStreamAsSource},
	}
	metrics := metricNameAwareFetcher(nil) // zero on every metric

	scanner := NewFirehoseScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for a genuinely idle Kinesis-sourced stream, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingKinesisFirehoseIdle {
		t.Fatalf("expected KINESIS_FIREHOSE_IDLE, got %s", result.Findings[0].ID)
	}
}

func TestFirehoseScanner_DirectPut_UnaffectedByFix(t *testing.T) {
	// A DirectPut stream's existing IncomingRecords-based behavior must be
	// unchanged: real IncomingRecords activity, zero DataReadFromKinesisStream.Records
	// (the metric a DirectPut stream would never have anyway) — still not idle.
	mock := &mockFirehoseClient{
		streams:     []string{"directput-firehose"},
		streamTypes: map[string]firehosetypes.DeliveryStreamType{"directput-firehose": firehosetypes.DeliveryStreamTypeDirectPut},
	}
	metrics := metricNameAwareFetcher(map[string]float64{"IncomingRecords": 200})

	scanner := NewFirehoseScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for an active DirectPut stream, got %d", len(result.Findings))
	}
}

func TestFirehoseScanner_DescribeDeliveryStreamError_FallsBackToDirectPutSafely(t *testing.T) {
	// When DescribeDeliveryStream fails, isKinesisStreamAsSource defaults to
	// DirectPut (today's pre-WO-244 behavior) rather than guessing. Prove
	// that fallback actually queries IncomingRecords and, when that metric
	// shows real activity, does not flag the stream — the failure must not
	// silently reintroduce a false positive.
	mock := &mockFirehoseClient{
		streams:        []string{"describe-fails"},
		describeErrors: map[string]error{"describe-fails": errors.New("simulated throttling")},
	}
	metrics := metricNameAwareFetcher(map[string]float64{"IncomingRecords": 50})

	scanner := NewFirehoseScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings — DescribeDeliveryStream failure should fall back to DirectPut/IncomingRecords, which shows real activity, got %d", len(result.Findings))
	}
}

func TestFirehoseScanner_MetricFetchError_DoesNotFlagAsFalsePositive(t *testing.T) {
	// If the metric fetch itself fails for a partition, streams in that
	// partition must NOT be treated as zero (idle) — that would be a false
	// positive worse than the bug this WO fixes. No finding should be
	// produced for a stream whose metrics couldn't be fetched.
	mock := &mockFirehoseClient{streams: []string{"metrics-fail"}}
	metrics := NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return nil, errors.New("simulated CloudWatch API error")
		},
	})

	scanner := NewFirehoseScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings when the metric fetch itself errors, got %d", len(result.Findings))
	}
}
