package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// KinesisAPI is the minimal interface for Kinesis operations.
type KinesisAPI interface {
	ListStreams(ctx context.Context, input *kinesis.ListStreamsInput, opts ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(ctx context.Context, input *kinesis.DescribeStreamSummaryInput, opts ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
	ListTagsForStream(ctx context.Context, input *kinesis.ListTagsForStreamInput, opts ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error)
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
		tags, err := s.fetchStreamTags(ctx, name)
		if err != nil {
			slog.Warn("Failed to fetch Kinesis stream tags", "stream", name, "error", err)
			tags = nil
		}
		if cfg.Exclude.ShouldExclude(name, tags) {
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
				Hygiene:               !isProvisioned, // WO-197: on-demand idle streams have no shard cost but must stay visible.
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

// maxTagPages caps tag-pagination loops. AWS resources carry at most 50 tags,
// so this is generous headroom against a misbehaving HasMoreTags response.
const maxTagPages = 10

// fetchStreamTags fetches all tags for a Kinesis data stream, paginating via
// ExclusiveStartTagKey (no bulk/batched tag API exists for Kinesis streams).
func (s *KinesisScanner) fetchStreamTags(ctx context.Context, name string) (map[string]string, error) {
	tags := make(map[string]string)
	var startKey *string
	for page := 0; page < maxTagPages; page++ {
		out, err := s.client.ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{
			StreamName:           &name,
			ExclusiveStartTagKey: startKey,
		})
		if err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tags[deref(t.Key)] = deref(t.Value)
		}
		if out.HasMoreTags == nil || !*out.HasMoreTags || len(out.Tags) == 0 {
			break
		}
		last := out.Tags[len(out.Tags)-1]
		startKey = last.Key
	}
	return tags, nil
}

// FirehoseAPI is the minimal interface for Firehose operations.
type FirehoseAPI interface {
	ListDeliveryStreams(ctx context.Context, input *firehose.ListDeliveryStreamsInput, opts ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
	ListTagsForDeliveryStream(ctx context.Context, input *firehose.ListTagsForDeliveryStreamInput, opts ...func(*firehose.Options)) (*firehose.ListTagsForDeliveryStreamOutput, error)
	DescribeDeliveryStream(ctx context.Context, input *firehose.DescribeDeliveryStreamInput, opts ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error)
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

// Scan examines all Firehose delivery streams for zero incoming records,
// checking IncomingRecords for DirectPut streams or DataReadFromKinesisStream.Records
// for KinesisStreamAsSource streams — WO-244.
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
		tags, err := s.fetchDeliveryStreamTags(ctx, name)
		if err != nil {
			slog.Warn("Failed to fetch Firehose delivery stream tags", "stream", name, "error", err)
			tags = nil
		}
		if cfg.Exclude.ShouldExclude(name, tags) {
			continue
		}
		names = append(names, name)
	}

	if len(names) == 0 {
		return result, nil
	}

	// AWS/Firehose's IncomingRecords metric only exists for DirectPut delivery
	// streams; a KinesisStreamAsSource stream never emits it at all, so
	// checking it unconditionally would silently and permanently read zero
	// for every Kinesis-sourced stream, regardless of real activity — WO-244.
	// The correct ingestion signal for that source type is
	// DataReadFromKinesisStream.Records.
	var directPutNames, kinesisSourceNames []string
	for _, name := range names {
		if s.isKinesisStreamAsSource(ctx, name) {
			kinesisSourceNames = append(kinesisSourceNames, name)
		} else {
			directPutNames = append(directPutNames, name)
		}
	}

	// evaluable tracks which streams actually got a successful metric fetch —
	// a partition whose FetchSum call fails must NOT fall through to being
	// treated as zero (idle); that would silently flag every stream in the
	// failed partition as a false positive, worse than the bug this WO fixes.
	incoming := map[string]float64{}
	evaluable := make(map[string]bool, len(names))
	if len(directPutNames) > 0 {
		sums, err := s.metrics.FetchSum(ctx, "AWS/Firehose", "IncomingRecords", "DeliveryStreamName", directPutNames, cfg.IdleDays)
		if err != nil {
			slog.Warn("Failed to fetch Firehose IncomingRecords metrics", "region", s.region, "error", err)
		} else {
			for _, name := range directPutNames {
				evaluable[name] = true
			}
			for k, v := range sums {
				incoming[k] = v
			}
		}
	}
	if len(kinesisSourceNames) > 0 {
		sums, err := s.metrics.FetchSum(ctx, "AWS/Firehose", "DataReadFromKinesisStream.Records", "DeliveryStreamName", kinesisSourceNames, cfg.IdleDays)
		if err != nil {
			slog.Warn("Failed to fetch Firehose DataReadFromKinesisStream.Records metrics", "region", s.region, "error", err)
		} else {
			for _, name := range kinesisSourceNames {
				evaluable[name] = true
			}
			for k, v := range sums {
				incoming[k] = v
			}
		}
	}

	for _, name := range names {
		if !evaluable[name] {
			continue
		}
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
			Hygiene:               true, // WO-194: zero-waste Firehose hygiene findings stay visible.
			Metadata: map[string]any{
				"delivery_stream_name": name,
			},
		})
	}

	return result, nil
}

// isKinesisStreamAsSource reports whether the named delivery stream sources
// from a Kinesis data stream (vs. DirectPut). Defaults to false (DirectPut,
// today's existing IncomingRecords-based behavior) on any DescribeDeliveryStream
// error, since that's the same metric this scanner already relied on before
// WO-244 — a describe failure never makes detection worse than it was.
func (s *FirehoseScanner) isKinesisStreamAsSource(ctx context.Context, name string) bool {
	out, err := s.client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &name})
	if err != nil || out.DeliveryStreamDescription == nil {
		slog.Warn("Failed to describe Firehose delivery stream", "stream", name, "error", err)
		return false
	}
	return out.DeliveryStreamDescription.DeliveryStreamType == firehosetypes.DeliveryStreamTypeKinesisStreamAsSource
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

// fetchDeliveryStreamTags fetches all tags for a Firehose delivery stream,
// paginating via ExclusiveStartTagKey (no bulk/batched tag API exists).
func (s *FirehoseScanner) fetchDeliveryStreamTags(ctx context.Context, name string) (map[string]string, error) {
	tags := make(map[string]string)
	var startKey *string
	for page := 0; page < maxTagPages; page++ {
		out, err := s.client.ListTagsForDeliveryStream(ctx, &firehose.ListTagsForDeliveryStreamInput{
			DeliveryStreamName:   &name,
			ExclusiveStartTagKey: startKey,
		})
		if err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tags[deref(t.Key)] = deref(t.Value)
		}
		if out.HasMoreTags == nil || !*out.HasMoreTags || len(out.Tags) == 0 {
			break
		}
		last := out.Tags[len(out.Tags)-1]
		startKey = last.Key
	}
	return tags, nil
}
