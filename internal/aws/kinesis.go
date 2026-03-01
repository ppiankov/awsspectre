package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// KinesisAPI is the minimal interface for Kinesis operations.
type KinesisAPI interface {
	ListStreams(ctx context.Context, input *kinesis.ListStreamsInput, opts ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(ctx context.Context, input *kinesis.DescribeStreamSummaryInput, opts ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
}

// KinesisScanner detects idle and over-provisioned Kinesis data streams.
type KinesisScanner struct {
	client  KinesisAPI
	metrics *MetricsFetcher
	region  string
}

// NewKinesisScanner creates a scanner for Kinesis data streams.
func NewKinesisScanner(client KinesisAPI, metrics *MetricsFetcher, region string) *KinesisScanner {
	return &KinesisScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *KinesisScanner) Type() ResourceType {
	return ResourceKinesis
}

// streamInfo holds metadata from DescribeStreamSummary.
type streamInfo struct {
	name       string
	shardCount int32
	mode       string
	arn        string
}

// Scan examines all Kinesis streams for idle or over-provisioned shards.
func (s *KinesisScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	streamNames, err := s.listStreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Kinesis streams: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(streamNames)}
	if len(streamNames) == 0 {
		return result, nil
	}

	// Describe each stream to get shard count and mode
	var streams []streamInfo
	var names []string
	for _, name := range streamNames {
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}

		info, err := s.describeStream(ctx, name)
		if err != nil {
			slog.Warn("Failed to describe Kinesis stream", "stream", name, "error", err)
			continue
		}
		streams = append(streams, info)
		names = append(names, name)
	}

	if len(names) == 0 {
		return result, nil
	}

	// Fetch CloudWatch metrics
	incomingRecords, err := s.metrics.FetchSum(ctx, "AWS/Kinesis", "IncomingRecords", "StreamName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch Kinesis IncomingRecords", "region", s.region, "error", err)
		return result, nil
	}

	getRecords, err := s.metrics.FetchSum(ctx, "AWS/Kinesis", "GetRecords.Records", "StreamName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch Kinesis GetRecords", "region", s.region, "error", err)
		return result, nil
	}

	incomingBytes, err := s.metrics.FetchSum(ctx, "AWS/Kinesis", "IncomingBytes", "StreamName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch Kinesis IncomingBytes", "region", s.region, "error", err)
		// Non-fatal: over-provisioned check will be skipped
	}

	for _, info := range streams {
		incoming := incomingRecords[info.name]
		reading := getRecords[info.name]

		isProvisioned := info.mode == string(kinesistypes.StreamModeProvisioned)
		shardCost := 0.0
		if isProvisioned {
			shardCost = pricing.MonthlyKinesisShardCost(int(info.shardCount), s.region)
		}

		// KINESIS_STREAM_IDLE: zero records in and out
		if incoming == 0 && reading == 0 {
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingKinesisStreamIdle,
				Severity:              SeverityHigh,
				ResourceType:          ResourceKinesis,
				ResourceID:            info.name,
				ResourceName:          info.arn,
				Region:                s.region,
				Message:               fmt.Sprintf("Zero records in/out over %d days (%d shards, %s mode)", cfg.IdleDays, info.shardCount, info.mode),
				EstimatedMonthlyWaste: shardCost,
				Metadata: map[string]any{
					"shard_count": info.shardCount,
					"stream_mode": info.mode,
				},
			})
			continue
		}

		// KINESIS_OVER_PROVISIONED: low shard utilization (provisioned mode only)
		if isProvisioned && incomingBytes != nil && info.shardCount > 0 {
			totalBytes := incomingBytes[info.name]
			lookbackSeconds := float64(cfg.IdleDays) * 86400
			avgBytesPerSec := totalBytes / lookbackSeconds
			// Each shard handles 1 MB/s (1048576 bytes/s)
			capacityBytesPerSec := float64(info.shardCount) * 1048576
			capacityPct := (avgBytesPerSec / capacityBytesPerSec) * 100

			if capacityPct < 10 {
				result.Findings = append(result.Findings, Finding{
					ID:                    FindingKinesisOverProvisioned,
					Severity:              SeverityMedium,
					ResourceType:          ResourceKinesis,
					ResourceID:            info.name,
					ResourceName:          info.arn,
					Region:                s.region,
					Message:               fmt.Sprintf("Shard utilization %.1f%% over %d days (%d shards)", capacityPct, cfg.IdleDays, info.shardCount),
					EstimatedMonthlyWaste: shardCost,
					Metadata: map[string]any{
						"shard_count":                info.shardCount,
						"stream_mode":                info.mode,
						"avg_incoming_bytes_per_sec": avgBytesPerSec,
						"capacity_pct":               capacityPct,
					},
				})
			}
		}
	}

	return result, nil
}

func (s *KinesisScanner) listStreams(ctx context.Context) ([]string, error) {
	var names []string
	paginator := kinesis.NewListStreamsPaginator(s.client, &kinesis.ListStreamsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		names = append(names, page.StreamNames...)
	}
	return names, nil
}

func (s *KinesisScanner) describeStream(ctx context.Context, name string) (streamInfo, error) {
	out, err := s.client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
		StreamName: &name,
	})
	if err != nil {
		return streamInfo{}, err
	}

	summary := out.StreamDescriptionSummary
	mode := string(kinesistypes.StreamModeProvisioned)
	if summary.StreamModeDetails != nil {
		mode = string(summary.StreamModeDetails.StreamMode)
	}

	shardCount := int32(0)
	if summary.OpenShardCount != nil {
		shardCount = *summary.OpenShardCount
	}

	return streamInfo{
		name:       name,
		shardCount: shardCount,
		mode:       mode,
		arn:        deref(summary.StreamARN),
	}, nil
}

// FirehoseAPI is the minimal interface for Firehose operations.
type FirehoseAPI interface {
	ListDeliveryStreams(ctx context.Context, input *firehose.ListDeliveryStreamsInput, opts ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
}

// FirehoseScanner detects idle Firehose delivery streams.
type FirehoseScanner struct {
	client  FirehoseAPI
	metrics *MetricsFetcher
	region  string
}

// NewFirehoseScanner creates a scanner for Firehose delivery streams.
func NewFirehoseScanner(client FirehoseAPI, metrics *MetricsFetcher, region string) *FirehoseScanner {
	return &FirehoseScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *FirehoseScanner) Type() ResourceType {
	return ResourceFirehose
}

// Scan examines all Firehose delivery streams for zero incoming records.
func (s *FirehoseScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	streamNames, err := s.listDeliveryStreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Firehose delivery streams: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(streamNames)}
	if len(streamNames) == 0 {
		return result, nil
	}

	var names []string
	for _, name := range streamNames {
		if cfg.Exclude.ShouldExclude(name, nil) {
			continue
		}
		names = append(names, name)
	}

	if len(names) == 0 {
		return result, nil
	}

	incoming, err := s.metrics.FetchSum(ctx, "AWS/Firehose", "IncomingRecords", "DeliveryStreamName", names, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch Firehose metrics", "region", s.region, "error", err)
		return result, nil
	}

	for _, name := range names {
		if incoming[name] > 0 {
			continue
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingKinesisFirehoseIdle,
			Severity:              SeverityMedium,
			ResourceType:          ResourceFirehose,
			ResourceID:            name,
			Region:                s.region,
			Message:               fmt.Sprintf("Zero incoming records over %d days", cfg.IdleDays),
			EstimatedMonthlyWaste: 0,
			Metadata: map[string]any{
				"delivery_stream_name": name,
			},
		})
	}

	return result, nil
}

func (s *FirehoseScanner) listDeliveryStreams(ctx context.Context) ([]string, error) {
	var names []string
	var startName *string

	for {
		out, err := s.client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{
			ExclusiveStartDeliveryStreamName: startName,
		})
		if err != nil {
			return nil, err
		}
		names = append(names, out.DeliveryStreamNames...)

		if out.HasMoreDeliveryStreams == nil || !*out.HasMoreDeliveryStreams || len(out.DeliveryStreamNames) == 0 {
			break
		}
		last := out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1]
		startName = &last
	}
	return names, nil
}
