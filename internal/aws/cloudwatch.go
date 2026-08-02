package aws

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

const (
	// maxMetricDataQueries is the maximum number of metric queries per GetMetricData call.
	maxMetricDataQueries = 500
	// metricPeriodSeconds is the aggregation period for CloudWatch metrics (1 hour).
	metricPeriodSeconds = 3600
	// dailyPeriodSeconds is a 1-day aggregation period used to fetch per-day
	// statistics (e.g. daily CPU maxima for WO-247 burst detection).
	dailyPeriodSeconds = 86400
)

// CloudWatchAPI is the minimal interface for CloudWatch operations needed by the metrics fetcher.
type CloudWatchAPI interface {
	GetMetricData(ctx context.Context, input *cloudwatch.GetMetricDataInput, opts ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// MetricsFetcher retrieves CloudWatch metrics in batches.
type MetricsFetcher struct {
	client CloudWatchAPI
}

// NewMetricsFetcher creates a fetcher using the given CloudWatch client.
func NewMetricsFetcher(client CloudWatchAPI) *MetricsFetcher {
	return &MetricsFetcher{client: client}
}

// FetchAverage retrieves the average value of a metric for a set of resource IDs over a lookback period.
// Returns a map of resource ID to average value.
func (f *MetricsFetcher) FetchAverage(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int) (map[string]float64, error) {
	return f.fetchMetric(ctx, namespace, metricName, dimensionName, ids, lookbackDays, "Average", nil)
}

// FetchSum retrieves the sum of a metric for a set of resource IDs over a lookback period.
// Returns a map of resource ID to total sum.
func (f *MetricsFetcher) FetchSum(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int) (map[string]float64, error) {
	return f.fetchMetric(ctx, namespace, metricName, dimensionName, ids, lookbackDays, "Sum", nil)
}

// FetchSumWithStaticDim retrieves the sum of a metric with per-resource and static dimensions.
func (f *MetricsFetcher) FetchSumWithStaticDim(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int, staticDims []cwtypes.Dimension) (map[string]float64, error) {
	// WO-189: CloudFront metrics require DistributionId plus the static Region=Global dimension.
	return f.fetchMetric(ctx, namespace, metricName, dimensionName, ids, lookbackDays, "Sum", staticDims)
}

func (f *MetricsFetcher) fetchMetric(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int, stat string, staticDims []cwtypes.Dimension) (map[string]float64, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	startTime := now.Add(-time.Duration(lookbackDays) * 24 * time.Hour)

	results := make(map[string]float64, len(ids))
	batches := batchIDs(ids, maxMetricDataQueries)

	for batchIdx, batch := range batches {
		slog.Debug("Fetching CloudWatch metrics", "batch", batchIdx+1, "total_batches", len(batches), "metric", metricName, "count", len(batch))

		queries := make([]cwtypes.MetricDataQuery, 0, len(batch))
		for i, id := range batch {
			queryID := fmt.Sprintf("m%d", i)
			dimensions := make([]cwtypes.Dimension, 0, len(staticDims)+1)
			dimensions = append(dimensions, cwtypes.Dimension{
				Name:  awssdk.String(dimensionName),
				Value: awssdk.String(id),
			})
			dimensions = append(dimensions, staticDims...)

			queries = append(queries, cwtypes.MetricDataQuery{
				Id: awssdk.String(queryID),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{
						Namespace:  awssdk.String(namespace),
						MetricName: awssdk.String(metricName),
						Dimensions: dimensions,
					},
					Period: awssdk.Int32(metricPeriodSeconds),
					Stat:   awssdk.String(stat),
				},
			})
		}

		out, err := f.client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
			MetricDataQueries: queries,
			StartTime:         awssdk.Time(startTime),
			EndTime:           awssdk.Time(now),
		})
		if err != nil {
			return nil, fmt.Errorf("get metric data (%s/%s): %w", namespace, metricName, err)
		}

		for _, result := range out.MetricDataResults {
			if result.Id == nil {
				continue
			}
			// Parse the index from the query ID to map back to the resource ID
			var idx int
			if _, err := fmt.Sscanf(*result.Id, "m%d", &idx); err != nil || idx >= len(batch) {
				continue
			}

			if len(result.Values) == 0 {
				continue
			}

			// Compute the aggregate (average of averages, or total sum)
			var total float64
			for _, v := range result.Values {
				total += v
			}
			if stat == "Average" && len(result.Values) > 0 {
				results[batch[idx]] = total / float64(len(result.Values))
			} else {
				results[batch[idx]] = total
			}
		}
	}

	return results, nil
}

// FetchDailyMaximum retrieves the per-day maximum value of a metric for a set
// of resource IDs over a lookback period, one datapoint per day. Returns a
// map of resource ID to the slice of daily maxima (oldest-first as CloudWatch
// returns them). Used by IDLE_EC2 burst detection (WO-247): a flat CPU
// *average* hides periodic cron/batch spikes that only a per-day *maximum*
// surfaces.
func (f *MetricsFetcher) FetchDailyMaximum(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int) (map[string][]float64, error) {
	return f.fetchMetricSeries(ctx, namespace, metricName, dimensionName, ids, lookbackDays, "Maximum", dailyPeriodSeconds, nil)
}

// fetchMetricSeries is the series-returning counterpart to fetchMetric: it
// issues one MetricDataQuery per ID (batched, same as fetchMetric) but returns
// the raw per-bucket Values slice per ID instead of aggregating to a single
// number. periodSeconds controls the bucket size (e.g. dailyPeriodSeconds for
// per-day buckets).
func (f *MetricsFetcher) fetchMetricSeries(ctx context.Context, namespace, metricName, dimensionName string, ids []string, lookbackDays int, stat string, periodSeconds int32, staticDims []cwtypes.Dimension) (map[string][]float64, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	startTime := now.Add(-time.Duration(lookbackDays) * 24 * time.Hour)

	results := make(map[string][]float64, len(ids))
	batches := batchIDs(ids, maxMetricDataQueries)

	for batchIdx, batch := range batches {
		slog.Debug("Fetching CloudWatch metric series", "batch", batchIdx+1, "total_batches", len(batches), "metric", metricName, "count", len(batch))

		queries := make([]cwtypes.MetricDataQuery, 0, len(batch))
		for i, id := range batch {
			queryID := fmt.Sprintf("m%d", i)
			dimensions := make([]cwtypes.Dimension, 0, len(staticDims)+1)
			dimensions = append(dimensions, cwtypes.Dimension{
				Name:  awssdk.String(dimensionName),
				Value: awssdk.String(id),
			})
			dimensions = append(dimensions, staticDims...)

			queries = append(queries, cwtypes.MetricDataQuery{
				Id: awssdk.String(queryID),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{
						Namespace:  awssdk.String(namespace),
						MetricName: awssdk.String(metricName),
						Dimensions: dimensions,
					},
					Period: awssdk.Int32(periodSeconds),
					Stat:   awssdk.String(stat),
				},
			})
		}

		out, err := f.client.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
			MetricDataQueries: queries,
			StartTime:         awssdk.Time(startTime),
			EndTime:           awssdk.Time(now),
		})
		if err != nil {
			return nil, fmt.Errorf("get metric series (%s/%s): %w", namespace, metricName, err)
		}

		for _, result := range out.MetricDataResults {
			if result.Id == nil || len(result.Values) == 0 {
				continue
			}
			var idx int
			if _, err := fmt.Sscanf(*result.Id, "m%d", &idx); err != nil || idx >= len(batch) {
				continue
			}
			// CloudWatch returns daily buckets oldest-first; copy to avoid
			// aliasing the SDK's slice.
			series := make([]float64, len(result.Values))
			copy(series, result.Values)
			results[batch[idx]] = series
		}
	}

	return results, nil
}

// batchIDs splits a slice of IDs into batches of the given size.
func batchIDs(ids []string, batchSize int) [][]string {
	if batchSize <= 0 {
		batchSize = maxMetricDataQueries
	}

	var batches [][]string
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		batches = append(batches, ids[i:end])
	}
	return batches
}
