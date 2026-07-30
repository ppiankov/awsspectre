package aws

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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
	createTime *time.Time
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

	now := time.Now().UTC()

	for _, info := range streams {
		incoming := incomingRecords[info.name]
		reading := getRecords[info.name]

		isProvisioned := info.mode == string(kinesistypes.StreamModeProvisioned)
		shardCost := 0.0
		if isProvisioned {
			shardCost = pricing.MonthlyKinesisShardCost(int(info.shardCount), s.region)
		}

		window, sufficient := idleWindowDescription(cfg.IdleDays, info.createTime, now)

		// KINESIS_STREAM_IDLE: zero records in and out
		if incoming == 0 && reading == 0 {
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingKinesisStreamIdle,
				Severity:              SeverityHigh,
				ResourceType:          ResourceKinesis,
				ResourceID:            info.name,
				ResourceName:          info.arn,
				Region:                s.region,
				Message:               fmt.Sprintf("Zero records in/out over %s (%d shards, %s mode)", window, info.shardCount, info.mode),
				EstimatedMonthlyWaste: shardCost,
				Hygiene:               !isProvisioned, // WO-197: on-demand idle streams have no shard cost but must stay visible.
				Metadata: map[string]any{
					"shard_count":        info.shardCount,
					"stream_mode":        info.mode,
					"sufficient_history": sufficient,
				},
			})
			continue
		}

		// KINESIS_OVER_PROVISIONED: low shard utilization (provisioned mode only).
		// totalBytes only reflects real observed traffic since the stream was
		// created — for a stream younger than cfg.IdleDays, dividing by the full
		// configured window understates the real utilization, since the same
		// bytes were actually seen over a shorter period. Use whichever is
		// smaller: the configured window, or the stream's actual observed
		// age — WO-252 (same fix shape as WO-251's NAT Gateway extrapolation).
		if isProvisioned && incomingBytes != nil && info.shardCount > 0 {
			totalBytes := incomingBytes[info.name]
			observedDays := float64(cfg.IdleDays)
			if info.createTime != nil {
				age := now.Sub(*info.createTime)
				if age < 0 {
					age = 0 // clock skew — treat as no observed history
				}
				if ageDays := age.Hours() / 24; ageDays < observedDays {
					observedDays = ageDays
				}
			}
			lookbackSeconds := observedDays * 86400
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
					Message:               fmt.Sprintf("Shard utilization %.1f%% over %s (%d shards)", capacityPct, window, info.shardCount),
					EstimatedMonthlyWaste: shardCost,
					Metadata: map[string]any{
						"shard_count":                info.shardCount,
						"stream_mode":                info.mode,
						"avg_incoming_bytes_per_sec": avgBytesPerSec,
						"capacity_pct":               capacityPct,
						"observed_days":              observedDays,
						"sufficient_history":         sufficient,
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
		createTime: summary.StreamCreationTimestamp,
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
	createTimeByName := make(map[string]*time.Time, len(names))
	for _, name := range names {
		isKinesisSource, createTime := s.describeDeliveryStream(ctx, name)
		createTimeByName[name] = createTime
		if isKinesisSource {
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

	now := time.Now().UTC()

	for _, name := range names {
		if !evaluable[name] {
			continue
		}
		if incoming[name] > 0 {
			continue
		}

		window, sufficient := idleWindowDescription(cfg.IdleDays, createTimeByName[name], now)

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingKinesisFirehoseIdle,
			Severity:              SeverityMedium,
			ResourceType:          ResourceFirehose,
			ResourceID:            name,
			Region:                s.region,
			Message:               fmt.Sprintf("Zero incoming records over %s", window),
			EstimatedMonthlyWaste: 0,
			Hygiene:               true, // WO-194: zero-waste Firehose hygiene findings stay visible.
			Metadata: map[string]any{
				"delivery_stream_name": name,
				"sufficient_history":   sufficient,
			},
		})
	}

	return result, nil
}

// describeDeliveryStream reports whether the named delivery stream sources
// from a Kinesis data stream (vs. DirectPut) and its creation timestamp.
// Defaults to (false, nil) on any DescribeDeliveryStream error, since false
// (DirectPut) is the same metric this scanner already relied on before
// WO-244, and a nil createTime defaults idleWindowDescription to full
// confidence — a describe failure never makes detection worse than it was.
func (s *FirehoseScanner) describeDeliveryStream(ctx context.Context, name string) (isKinesisSource bool, createTime *time.Time) {
	out, err := s.client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &name})
	if err != nil || out.DeliveryStreamDescription == nil {
		slog.Warn("Failed to describe Firehose delivery stream", "stream", name, "error", err)
		return false, nil
	}
	desc := out.DeliveryStreamDescription
	return desc.DeliveryStreamType == firehosetypes.DeliveryStreamTypeKinesisStreamAsSource, desc.CreateTimestamp
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
