package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type mockRDSClient struct {
	instances []rdstypes.DBInstance
}

func (m *mockRDSClient) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: m.instances}, nil
}

// newRDSMockMetrics creates a mock MetricsFetcher that dispatches on metric name.
// freeableMemoryBytes is the average FreeableMemory to return (0 means no data).
func newRDSMockMetrics(cpuValues []float64, connValues []float64, freeableBytes float64) *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				if q.MetricStat == nil {
					continue
				}
				metricName := *q.MetricStat.Metric.MetricName
				switch metricName {
				case "CPUUtilization":
					if cpuValues != nil {
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: cpuValues,
						})
					}
				case "DatabaseConnections":
					if connValues != nil {
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: connValues,
						})
					}
				case "FreeableMemory":
					if freeableBytes > 0 {
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{freeableBytes},
						})
					}
				}
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})
}

func TestRDSScanner_IdleCPU(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("my-database"),
				DBInstanceClass:      awssdk.String("db.t3.medium"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("postgres"),
				MultiAZ:              awssdk.Bool(false),
			},
		},
	}

	// Low CPU, some connections, low memory usage (3 GiB free of 4 GiB = 25% used)
	metrics := newRDSMockMetrics([]float64{2.0, 3.0, 1.0}, []float64{5.0, 10.0}, 3*1024*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

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
	if f.ID != FindingIdleRDS {
		t.Fatalf("expected IDLE_RDS, got %s", f.ID)
	}
	if f.ResourceID != "my-database" {
		t.Fatalf("expected my-database, got %s", f.ResourceID)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestRDSScanner_ZeroConnections(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("unused-db"),
				DBInstanceClass:      awssdk.String("db.r5.large"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("mysql"),
				MultiAZ:              awssdk.Bool(true),
			},
		},
	}

	// Normal CPU but zero connections, low memory (12 GiB free of 16 GiB = 25% used)
	metrics := newRDSMockMetrics([]float64{25.0, 30.0}, []float64{0}, 12*1024*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingIdleRDS {
		t.Fatalf("expected IDLE_RDS, got %s", f.ID)
	}
	if f.ResourceName != "unused-db" {
		t.Fatalf("expected unused-db, got %s", f.ResourceName)
	}
}

func TestRDSScanner_HealthyInstance(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("healthy-db"),
				DBInstanceClass:      awssdk.String("db.t3.medium"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("postgres"),
				MultiAZ:              awssdk.Bool(false),
			},
		},
	}

	// High CPU and connections
	metrics := newRDSMockMetrics([]float64{45.0, 50.0}, []float64{20.0, 30.0}, 2*1024*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for healthy instance, got %d", len(result.Findings))
	}
}

func TestRDSScanner_NotAvailableNotFlagged(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("creating-db"),
				DBInstanceClass:      awssdk.String("db.t3.medium"),
				DBInstanceStatus:     awssdk.String("creating"),
				Engine:               awssdk.String("postgres"),
			},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for non-available instance, got %d", len(result.Findings))
	}
}

func TestRDSScanner_NoInstances(t *testing.T) {
	mock := &mockRDSClient{instances: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestRDSScanner_ExcludedInstance(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("excluded-db"),
				DBInstanceClass:      awssdk.String("db.t3.medium"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("postgres"),
			},
		},
	}

	metrics := newMockMetricsFetcher(map[string]float64{"excluded-db": 1.0})
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"excluded-db": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded instance, got %d", len(result.Findings))
	}
}

func TestRDSScanner_LowCPUHighMemory_NotIdle(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("cache-heavy-db"),
				DBInstanceClass:      awssdk.String("db.r5.large"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("postgres"),
				MultiAZ:              awssdk.Bool(false),
			},
		},
	}

	// Low CPU, has connections, but high memory (2 GiB free of 16 GiB = 87.5% used)
	metrics := newRDSMockMetrics([]float64{2.0}, []float64{5.0}, 2*1024*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for memory-heavy RDS instance, got %d", len(result.Findings))
	}
}

func TestRDSScanner_LowCPULowMemory_StillIdle(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("idle-db"),
				DBInstanceClass:      awssdk.String("db.t3.medium"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("mysql"),
				MultiAZ:              awssdk.Bool(false),
			},
		},
	}

	// Low CPU, some connections, low memory (3.5 GiB free of 4 GiB = 12.5% used)
	metrics := newRDSMockMetrics([]float64{1.5}, []float64{2.0}, 3.5*1024*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for truly idle RDS, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Metadata["has_mem_metrics"] != true {
		t.Fatalf("expected has_mem_metrics true, got %v", f.Metadata["has_mem_metrics"])
	}
	memPct, ok := f.Metadata["avg_mem_percent"].(float64)
	if !ok || memPct > 20 {
		t.Fatalf("expected low memory percent, got %v", f.Metadata["avg_mem_percent"])
	}
}

func TestRDSScanner_UnknownClass_FallbackCPUOnly(t *testing.T) {
	mock := &mockRDSClient{
		instances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: awssdk.String("exotic-db"),
				DBInstanceClass:      awssdk.String("db.x99.unknown"),
				DBInstanceStatus:     awssdk.String("available"),
				Engine:               awssdk.String("postgres"),
				MultiAZ:              awssdk.Bool(false),
			},
		},
	}

	// Low CPU, some connections, freeable memory present but class unknown
	metrics := newRDSMockMetrics([]float64{1.0}, []float64{3.0}, 500*1024*1024)
	scanner := NewRDSScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for unknown class (CPU-only fallback), got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Metadata["has_mem_metrics"] != false {
		t.Fatalf("expected has_mem_metrics false for unknown class, got %v", f.Metadata["has_mem_metrics"])
	}
}

func TestRDSScanner_Type(t *testing.T) {
	scanner := &RDSScanner{}
	if scanner.Type() != ResourceRDS {
		t.Fatalf("expected ResourceRDS, got %s", scanner.Type())
	}
}
