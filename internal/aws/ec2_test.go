package aws

import (
	"context"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEC2Client struct {
	instances []ec2types.Reservation
}

func (m *mockEC2Client) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: m.instances,
	}, nil
}

func newMockMetricsFetcher(cpuValues map[string]float64) *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			var results []cwtypes.MetricDataResult
			for i, q := range input.MetricDataQueries {
				if q.MetricStat != nil && len(q.MetricStat.Metric.Dimensions) > 0 {
					instID := *q.MetricStat.Metric.Dimensions[0].Value
					if val, ok := cpuValues[instID]; ok {
						results = append(results, cwtypes.MetricDataResult{
							Id:     awssdk.String(fmt.Sprintf("m%d", i)),
							Values: []float64{val},
						})
					}
				}
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	})
}

func TestEC2Scanner_IdleInstance(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-idle001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags:         []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("idle-web")}},
					},
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(map[string]float64{"i-idle001": 2.3})
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Fatalf("expected 1 resource scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingIdleEC2 {
		t.Fatalf("expected IDLE_EC2, got %s", f.ID)
	}
	if f.ResourceID != "i-idle001" {
		t.Fatalf("expected i-idle001, got %s", f.ResourceID)
	}
	if f.ResourceName != "idle-web" {
		t.Fatalf("expected name idle-web, got %s", f.ResourceName)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestEC2Scanner_HealthyInstance(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-healthy001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(map[string]float64{"i-healthy001": 45.0})
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for healthy instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_StoppedInstance(t *testing.T) {
	launchTime := time.Now().UTC().Add(-60 * 24 * time.Hour) // 60 days ago
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-stopped001"),
						InstanceType: ec2types.InstanceTypeM5Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
						Tags:         []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("old-server")}},
					},
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingStoppedEC2 {
		t.Fatalf("expected STOPPED_EC2, got %s", f.ID)
	}
	if f.ResourceName != "old-server" {
		t.Fatalf("expected name old-server, got %s", f.ResourceName)
	}
}

func TestEC2Scanner_RecentlyStoppedNotFlagged(t *testing.T) {
	launchTime := time.Now().UTC().Add(-5 * 24 * time.Hour) // 5 days ago
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-recent001"),
						InstanceType: ec2types.InstanceTypeT3Micro,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for recently stopped instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_NoInstances(t *testing.T) {
	mock := &mockEC2Client{instances: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_ExcludedInstance(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-excluded001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(map[string]float64{"i-excluded001": 1.0})
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"i-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected excluded instance to produce no findings, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_Type(t *testing.T) {
	scanner := &EC2Scanner{}
	if scanner.Type() != ResourceEC2 {
		t.Fatalf("expected ResourceEC2, got %s", scanner.Type())
	}
}
