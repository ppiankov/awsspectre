package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEC2Client struct {
	instances []ec2types.Reservation
	volumes   []ec2types.Volume
}

func (m *mockEC2Client) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: m.instances,
	}, nil
}

func (m *mockEC2Client) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{
		Volumes: m.volumes,
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

func newEC2MockMetricsFetcher(cpuValues, memValues map[string]float64) *MetricsFetcher {
	return newEC2MockMetricsFetcherWithGPU(cpuValues, memValues, nil)
}

func newEC2MockMetricsFetcherWithGPU(cpuValues, memValues, gpuValues map[string]float64) *MetricsFetcher {
	return NewMetricsFetcher(&mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			var results []cwtypes.MetricDataResult
			for i, q := range input.MetricDataQueries {
				if q.MetricStat == nil || len(q.MetricStat.Metric.Dimensions) == 0 {
					continue
				}
				instID := *q.MetricStat.Metric.Dimensions[0].Value
				namespace := *q.MetricStat.Metric.Namespace
				metricName := *q.MetricStat.Metric.MetricName

				var values map[string]float64
				switch {
				case namespace == "AWS/EC2":
					values = cpuValues
				case namespace == "CWAgent" && metricName == "mem_used_percent":
					values = memValues
				case namespace == "CWAgent" && metricName == "utilization_gpu":
					values = gpuValues
				}

				if values == nil {
					continue
				}
				if val, ok := values[instID]; ok {
					results = append(results, cwtypes.MetricDataResult{
						Id:     awssdk.String(fmt.Sprintf("m%d", i)),
						Values: []float64{val},
					})
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

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-idle001": 2.3}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
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
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true when LaunchTime is unset, got %v", f.Metadata["sufficient_history"])
	}
	if f.Message != "CPU 2.3% over 7 days" {
		t.Fatalf("expected full-window message, got %q", f.Message)
	}
}

func TestEC2Scanner_IdleInstance_LongRunning_FullWindowMessage(t *testing.T) {
	launchTime := time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-idle-longrun"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-idle-longrun": 1.5}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Message != "CPU 1.5% over 7 days" {
		t.Fatalf("expected full-window message for a long-running instance, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true for a 30-day-old instance, got %v", f.Metadata["sufficient_history"])
	}
}

func TestEC2Scanner_IdleInstance_RecentlyStarted_InsufficientHistoryMessage(t *testing.T) {
	// WO-236: a live dogfood scan found a GitLab CI runner instance started
	// 11 minutes before the scan ran, with only 1 CloudWatch datapoint in the
	// 7-day window, reported as "CPU 1.7% over 7 days" — an overclaim of data
	// coverage. The finding must still surface (real evidence, not suppressed)
	// but must not claim full-window confidence it doesn't have.
	launchTime := time.Now().UTC().Add(-11 * time.Minute)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-freshly-started"),
						InstanceType: ec2types.InstanceTypeR5Xlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-freshly-started": 1.7}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the finding to still surface (evidence, not suppressed), got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected message to NOT claim full 7-day coverage for an instance running 11 minutes, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "insufficient running history") {
		t.Fatalf("expected message to disclose insufficient history, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != false {
		t.Fatalf("expected sufficient_history=false for a freshly-started instance, got %v", f.Metadata["sufficient_history"])
	}
}

func TestEC2Scanner_IdleInstance_NodeGroupManaged_ASGTag(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("aws:autoscaling:groupName"), Value: awssdk.String("app-nodepool-asg")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-nodegroup001": 2.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity for a node-group-managed instance, got %s", f.Severity)
	}
	if f.RemediationPath != RemediationViaController {
		t.Fatalf("expected via_controller remediation path, got %s", f.RemediationPath)
	}
	if !strings.Contains(f.Message, "node group") {
		t.Fatalf("expected message to mention the node group, got %q", f.Message)
	}
	if f.Metadata["node_group_managed"] != true {
		t.Fatalf("expected node_group_managed=true, got %v", f.Metadata["node_group_managed"])
	}
}

func TestEC2Scanner_IdleInstance_NodeGroupManaged_EKSClusterNameTag(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup002"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("eks:cluster-name"), Value: awssdk.String("prod-eks-cluster")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-nodegroup002": 2.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity for eks:cluster-name tag, got %s", f.Severity)
	}
	if f.RemediationPath != RemediationViaController {
		t.Fatalf("expected via_controller remediation path, got %s", f.RemediationPath)
	}
}

func TestEC2Scanner_IdleInstance_NodeGroupManaged_KubernetesClusterOwnedTag(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup003"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("kubernetes.io/cluster/prod-eks-cluster"), Value: awssdk.String("owned")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-nodegroup003": 2.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity for kubernetes.io/cluster/*=owned tag, got %s", f.Severity)
	}
	if f.RemediationPath != RemediationViaController {
		t.Fatalf("expected via_controller remediation path, got %s", f.RemediationPath)
	}
}

func TestEC2Scanner_IdleInstance_KubernetesClusterTagNotOwned_NotNodeGroupManaged(t *testing.T) {
	// A "kubernetes.io/cluster/<name>" tag with a value other than "owned"
	// (e.g. "shared") means the cluster merely references the resource, not
	// that it owns/manages its lifecycle — must not be treated as node-group
	// managed.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-shared001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("kubernetes.io/cluster/prod-eks-cluster"), Value: awssdk.String("shared")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-shared001": 2.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity (not node-group managed), got %s", f.Severity)
	}
	if f.RemediationPath != RemediationDirect && f.RemediationPath != "" {
		t.Fatalf("expected direct/empty remediation path, got %s", f.RemediationPath)
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

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-healthy001": 45.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
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
						BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
							{Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String("vol-root001")}},
							{Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String("vol-data001")}},
						},
					},
				},
			},
		},
		volumes: []ec2types.Volume{
			{VolumeId: awssdk.String("vol-root001"), VolumeType: ec2types.VolumeTypeGp3, Size: awssdk.Int32(100)},
			{VolumeId: awssdk.String("vol-data001"), VolumeType: ec2types.VolumeTypeGp3, Size: awssdk.Int32(500)},
		},
	}

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
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
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity for stopped instance, got %s", f.Severity)
	}
	// 100 GiB gp3 ($8) + 500 GiB gp3 ($40) = $48/month
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero EBS waste for stopped instance with volumes")
	}
	if f.Metadata["ebs_monthly_cost"] == nil {
		t.Fatal("expected ebs_monthly_cost in metadata")
	}
	if f.Metadata["attached_volumes"] == nil {
		t.Fatal("expected attached_volumes in metadata")
	}
}

func TestEC2Scanner_StoppedInstanceNoVolumes(t *testing.T) {
	launchTime := time.Now().UTC().Add(-45 * 24 * time.Hour)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-novols001"),
						InstanceType: ec2types.InstanceTypeT3Micro,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatalf("expected zero waste for stopped instance without volumes, got %f", f.EstimatedMonthlyWaste)
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

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for recently stopped instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_NoInstances(t *testing.T) {
	mock := &mockEC2Client{instances: nil}
	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
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

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-excluded001": 1.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays:             7,
		IdleCPUThreshold:     5.0,
		HighMemoryThreshold:  50.0,
		StoppedThresholdDays: 30,
		Exclude:              ExcludeConfig{ResourceIDs: map[string]bool{"i-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected excluded instance to produce no findings, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_ExcludedByTag(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-tagged001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("Environment"), Value: awssdk.String("production")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(map[string]float64{"i-tagged001": 1.0}, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30,
		Exclude: ExcludeConfig{Tags: map[string]string{"Environment": "production"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected tag-excluded instance to produce no findings, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_LowCPUHighMemory_NotIdle(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-memheavy001"),
						InstanceType: ec2types.InstanceTypeR5Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags:         []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("openclaw")}},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(
		map[string]float64{"i-memheavy001": 2.0},
		map[string]float64{"i-memheavy001": 85.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for memory-heavy instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_LowCPULowMemory_StillIdle(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-trueidle001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(
		map[string]float64{"i-trueidle001": 1.5},
		map[string]float64{"i-trueidle001": 15.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for truly idle instance, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingIdleEC2 {
		t.Fatalf("expected IDLE_EC2, got %s", f.ID)
	}
	if f.Metadata["avg_mem_percent"] != 15.0 {
		t.Fatalf("expected avg_mem_percent 15.0, got %v", f.Metadata["avg_mem_percent"])
	}
	if f.Metadata["has_mem_metrics"] != true {
		t.Fatalf("expected has_mem_metrics true, got %v", f.Metadata["has_mem_metrics"])
	}
}

func TestEC2Scanner_GPUInstance_LowCPUHighGPU_NotIdle(t *testing.T) {
	// WO-235: a GPU-bound workload commonly runs with low host CPU while the
	// GPU itself is saturated — CPU-only detection would falsely flag this
	// (expensive) instance as idle.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-gpubusy001"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-gpubusy001": 2.0},
		nil,
		map[string]float64{"i-gpubusy001": 95.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for a GPU-saturated instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_GPUInstance_LowCPULowGPU_StillIdle(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-gpuidle001"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-gpuidle001": 1.0},
		nil,
		map[string]float64{"i-gpuidle001": 3.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for a genuinely idle GPU instance, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ID != FindingIdleEC2 {
		t.Fatalf("expected IDLE_EC2, got %s", f.ID)
	}
	if f.Metadata["avg_gpu_percent"] != 3.0 {
		t.Fatalf("expected avg_gpu_percent 3.0, got %v", f.Metadata["avg_gpu_percent"])
	}
	if f.Metadata["has_gpu_metrics"] != true {
		t.Fatalf("expected has_gpu_metrics true, got %v", f.Metadata["has_gpu_metrics"])
	}
}

func TestEC2Scanner_NodeGroupManaged_GPUOverride_NotIdle(t *testing.T) {
	// A node-group-managed GPU instance that is actually saturated on the GPU
	// must still be skipped entirely by the GPU override — the node-group
	// check must not resurrect a finding the GPU override already ruled out.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup-gpubusy"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("aws:autoscaling:groupName"), Value: awssdk.String("gpu-nodepool-asg")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-nodegroup-gpubusy": 2.0},
		nil,
		map[string]float64{"i-nodegroup-gpubusy": 95.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for a GPU-saturated node-group-managed instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_NodeGroupManaged_LowGPU_StillIdle_Annotated(t *testing.T) {
	// A genuinely idle node-group-managed GPU instance must get both the
	// existing GPU metadata AND the node-group annotation together.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup-gpuidle"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("aws:autoscaling:groupName"), Value: awssdk.String("gpu-nodepool-asg")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-nodegroup-gpuidle": 1.0},
		nil,
		map[string]float64{"i-nodegroup-gpuidle": 3.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for a genuinely idle node-group-managed GPU instance, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Metadata["avg_gpu_percent"] != 3.0 {
		t.Fatalf("expected avg_gpu_percent 3.0, got %v", f.Metadata["avg_gpu_percent"])
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.RemediationPath != RemediationViaController {
		t.Fatalf("expected via_controller remediation path, got %s", f.RemediationPath)
	}
	if f.Metadata["node_group_managed"] != true {
		t.Fatalf("expected node_group_managed=true, got %v", f.Metadata["node_group_managed"])
	}
}

func TestEC2Scanner_NodeGroupManaged_MemoryOverride_NotIdle(t *testing.T) {
	// A node-group-managed instance with high memory utilization must still
	// be skipped entirely by the memory override.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nodegroup-membusy"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						Tags: []ec2types.Tag{
							{Key: awssdk.String("aws:autoscaling:groupName"), Value: awssdk.String("app-nodepool-asg")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(
		map[string]float64{"i-nodegroup-membusy": 2.0},
		map[string]float64{"i-nodegroup-membusy": 85.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for a memory-busy node-group-managed instance, got %d", len(result.Findings))
	}
}

func TestEC2Scanner_StoppedInstance_NodeGroupTags_ScopeContained(t *testing.T) {
	// WO-239 is scoped to IDLE_EC2 only — a stopped instance with node-group
	// tags must produce an ordinary STOPPED_EC2 finding, untouched by the
	// node-group annotation/RemediationPath logic.
	launchTime := time.Now().UTC().Add(-45 * 24 * time.Hour)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-stopped-nodegroup"),
						InstanceType: ec2types.InstanceTypeT3Micro,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
						Tags: []ec2types.Tag{
							{Key: awssdk.String("aws:autoscaling:groupName"), Value: awssdk.String("app-nodepool-asg")},
						},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
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
	if f.Metadata["node_group_managed"] != nil {
		t.Fatalf("expected no node_group_managed metadata on STOPPED_EC2, got %v", f.Metadata["node_group_managed"])
	}
	if f.RemediationPath != "" {
		t.Fatalf("expected empty RemediationPath on STOPPED_EC2 (unaffected by WO-239), got %s", f.RemediationPath)
	}
}

func TestEC2Scanner_GPUInstance_NoGPUMetrics_FallsBackToCPU(t *testing.T) {
	// No CloudWatch agent GPU plugin installed — no GPU metric data at all.
	// Must fall back to CPU-only detection rather than blocking the finding.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-gpunometrics001"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-gpunometrics001": 1.0},
		nil,
		nil, // no GPU data available for this instance
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding when GPU metrics are unavailable (CPU-only fallback), got %d", len(result.Findings))
	}
}

func TestEC2Scanner_NonGPUInstance_HighGPUMetricIgnored(t *testing.T) {
	// A non-GPU instance type must never consult the GPU override, even if
	// (implausibly) GPU-namespaced data happens to exist for its ID.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-notgpu001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-notgpu001": 1.0},
		nil,
		map[string]float64{"i-notgpu001": 95.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding — GPU override must not apply to a non-GPU instance type, got %d", len(result.Findings))
	}
	if _, ok := result.Findings[0].Metadata["avg_gpu_percent"]; ok {
		t.Fatalf("expected no GPU metadata keys on a non-GPU instance finding, got %v", result.Findings[0].Metadata["avg_gpu_percent"])
	}
}

func TestEC2Scanner_GPUInstance_LowGPUHighMemory_NotIdle(t *testing.T) {
	// A GPU instance can fall through the GPU check (low GPU utilization) and
	// still be caught by the independent memory override.
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-gpumemheavy001"),
						InstanceType: ec2types.InstanceTypeG4dnXlarge,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcherWithGPU(
		map[string]float64{"i-gpumemheavy001": 2.0},
		map[string]float64{"i-gpumemheavy001": 85.0},
		map[string]float64{"i-gpumemheavy001": 3.0},
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings — memory override must still apply to a GPU instance with low GPU utilization, got %d", len(result.Findings))
	}
}

func TestIsGPUInstanceType(t *testing.T) {
	cases := []struct {
		instanceType string
		want         bool
	}{
		{"g4dn.xlarge", true},
		{"g4dn.2xlarge", true},
		{"p3.2xlarge", true},
		{"p4d.24xlarge", true},
		{"g5.xlarge", true},
		{"g6.xlarge", true},
		{"inf1.xlarge", true},
		{"inf2.xlarge", true},
		{"trn1.2xlarge", true},
		{"t3.medium", false},
		{"r5.2xlarge", false},
		{"m5.large", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isGPUInstanceType(c.instanceType); got != c.want {
			t.Errorf("isGPUInstanceType(%q) = %v, want %v", c.instanceType, got, c.want)
		}
	}
}

func TestIsNodeGroupManagedEC2(t *testing.T) {
	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{"asg tag alone", map[string]string{"aws:autoscaling:groupName": "app-nodepool-asg"}, true},
		{"eks cluster-name tag alone", map[string]string{"eks:cluster-name": "prod-eks-cluster"}, true},
		{"aws:eks:cluster-name tag alone", map[string]string{"aws:eks:cluster-name": "prod-eks-cluster"}, true},
		{"kubernetes.io/cluster/*=owned", map[string]string{"kubernetes.io/cluster/prod-eks-cluster": "owned"}, true},
		{"kubernetes.io/cluster/*=shared not owned", map[string]string{"kubernetes.io/cluster/prod-eks-cluster": "shared"}, false},
		{"unrelated tags", map[string]string{"Name": "web-01", "Environment": "prod"}, false},
		{"no tags", map[string]string{}, false},
		{"nil tags", nil, false},
	}
	for _, c := range cases {
		if got := isNodeGroupManagedEC2(c.tags); got != c.want {
			t.Errorf("%s: isNodeGroupManagedEC2(%v) = %v, want %v", c.name, c.tags, got, c.want)
		}
	}
}

func TestEC2Scanner_LowCPU_NoCWAgent_FallbackIdle(t *testing.T) {
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-noagent001"),
						InstanceType: ec2types.InstanceTypeT3Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					},
				},
			},
		},
	}

	metrics := newEC2MockMetricsFetcher(
		map[string]float64{"i-noagent001": 3.0},
		nil,
	)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding when CWAgent absent, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Metadata["has_mem_metrics"] != false {
		t.Fatalf("expected has_mem_metrics false, got %v", f.Metadata["has_mem_metrics"])
	}
}

func TestEC2Scanner_StoppedInstance_UsesCloudTrailStopTime_BelowThreshold(t *testing.T) {
	// WO-243: a live dogfood account showed a LaunchTime 60 days in the past,
	// but the real CloudTrail StopInstances event was only 19 days before the
	// scan — below the 30-day StoppedThresholdDays default. Using LaunchTime
	// alone wrongly fires the finding; the CloudTrail event correctly
	// suppresses it.
	launchTime := time.Now().UTC().Add(-60 * 24 * time.Hour)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-recentlystopped001"),
						InstanceType: ec2types.InstanceTypeM5Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}
	realStop := time.Now().UTC().Add(-19 * 24 * time.Hour)
	ct := &mockCloudTrailClient{events: []cttypes.Event{newMockEvent("StopInstances", realStop)}}

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")
	scanner.SetCloudTrailClient(ct)

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no STOPPED_EC2 finding — real stop was only 19 days ago, below the 30-day threshold, got %d findings", len(result.Findings))
	}
}

func TestEC2Scanner_StoppedInstance_AboveThreshold_UsesCloudTrailDayCount(t *testing.T) {
	// A LaunchTime ~100 days ago with a real CloudTrail StopInstances event
	// ~40 days before the scan — still above the 30-day threshold either way,
	// so the finding fires in both cases, but the reported days_stopped must
	// reflect the CloudTrail-derived value (40), not the LaunchTime-derived
	// one (100).
	launchTime := time.Now().UTC().Add(-100 * 24 * time.Hour)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-aboveThreshold001"),
						InstanceType: ec2types.InstanceTypeM5Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}
	stopTime := time.Now().UTC().Add(-40 * 24 * time.Hour)
	ct := &mockCloudTrailClient{events: []cttypes.Event{newMockEvent("StopInstances", stopTime)}}

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")
	scanner.SetCloudTrailClient(ct)

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if days, _ := result.Findings[0].Metadata["days_stopped"].(int); days < 39 || days > 41 {
		t.Fatalf("expected days_stopped ~40 from CloudTrail (not ~100 from LaunchTime), got %v", result.Findings[0].Metadata["days_stopped"])
	}
}

func TestEC2Scanner_StoppedInstance_CloudTrailNoMatch_FallsBackToLaunchTime(t *testing.T) {
	launchTime := time.Now().UTC().Add(-60 * 24 * time.Hour)
	mock := &mockEC2Client{
		instances: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId:   awssdk.String("i-nomatch001"),
						InstanceType: ec2types.InstanceTypeM5Large,
						State:        &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
						LaunchTime:   &launchTime,
					},
				},
			},
		},
	}
	ct := &mockCloudTrailClient{events: nil} // no matching event found

	metrics := newEC2MockMetricsFetcher(nil, nil)
	scanner := NewEC2Scanner(mock, metrics, "us-east-1")
	scanner.SetCloudTrailClient(ct)

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, IdleCPUThreshold: 5.0, HighMemoryThreshold: 50.0, StoppedThresholdDays: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected fallback to LaunchTime-based detection, got %d findings", len(result.Findings))
	}
	if days, _ := result.Findings[0].Metadata["days_stopped"].(int); days < 59 || days > 61 {
		t.Fatalf("expected days_stopped ~60 from LaunchTime fallback, got %v", result.Findings[0].Metadata["days_stopped"])
	}
}

func TestEC2Scanner_Type(t *testing.T) {
	scanner := &EC2Scanner{}
	if scanner.Type() != ResourceEC2 {
		t.Fatalf("expected ResourceEC2, got %s", scanner.Type())
	}
}
