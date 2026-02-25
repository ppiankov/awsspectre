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

	// Return low CPU and some connections
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				if q.MetricStat != nil {
					metricName := *q.MetricStat.Metric.MetricName
					switch metricName {
					case "CPUUtilization":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{2.0, 3.0, 1.0},
						})
					case "DatabaseConnections":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{5.0, 10.0},
						})
					}
				}
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
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

	// Return normal CPU but zero connections
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				if q.MetricStat != nil {
					metricName := *q.MetricStat.Metric.MetricName
					switch metricName {
					case "CPUUtilization":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{25.0, 30.0},
						})
					case "DatabaseConnections":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{0},
						})
					}
				}
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
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

	// Return high CPU and connections
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i, q := range input.MetricDataQueries {
				if q.MetricStat != nil {
					metricName := *q.MetricStat.Metric.MetricName
					switch metricName {
					case "CPUUtilization":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{45.0, 50.0},
						})
					case "DatabaseConnections":
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{20.0, 30.0},
						})
					}
				}
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
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

func TestRDSScanner_Type(t *testing.T) {
	scanner := &RDSScanner{}
	if scanner.Type() != ResourceRDS {
		t.Fatalf("expected ResourceRDS, got %s", scanner.Type())
	}
}
