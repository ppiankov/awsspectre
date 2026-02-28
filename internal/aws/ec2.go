package aws

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// EC2API is the minimal interface for EC2 instance operations.
type EC2API interface {
	DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// EC2Scanner detects idle and stopped EC2 instances.
type EC2Scanner struct {
	client  EC2API
	metrics *MetricsFetcher
	region  string
}

// NewEC2Scanner creates a scanner for EC2 instances.
func NewEC2Scanner(client EC2API, metrics *MetricsFetcher, region string) *EC2Scanner {
	return &EC2Scanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type this scanner handles.
func (s *EC2Scanner) Type() ResourceType {
	return ResourceEC2
}

// Scan examines all EC2 instances in the region for waste.
func (s *EC2Scanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	instances, err := s.listInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("list EC2 instances: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(instances)}
	if len(instances) == 0 {
		return result, nil
	}

	// Check stopped instances
	now := time.Now().UTC()
	var runningIDs []string
	for _, inst := range instances {
		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[deref(inst.InstanceId)] {
			continue
		}

		if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameStopped {
			stoppedAt := stoppedSince(inst)
			if stoppedAt.IsZero() {
				continue
			}
			daysStopped := int(now.Sub(stoppedAt).Hours() / 24)
			if daysStopped >= cfg.StoppedThresholdDays {
				instanceType := string(inst.InstanceType)
				result.Findings = append(result.Findings, Finding{
					ID:                    FindingStoppedEC2,
					Severity:              SeverityMedium,
					ResourceType:          ResourceEC2,
					ResourceID:            deref(inst.InstanceId),
					ResourceName:          instanceName(inst),
					Region:                s.region,
					Message:               fmt.Sprintf("Stopped for %d days", daysStopped),
					EstimatedMonthlyWaste: 0,
					Metadata: map[string]any{
						"instance_type": instanceType,
						"days_stopped":  daysStopped,
						"state":         "stopped",
					},
				})
			}
			continue
		}

		if inst.State != nil && inst.State.Name == ec2types.InstanceStateNameRunning {
			runningIDs = append(runningIDs, deref(inst.InstanceId))
		}
	}

	// Check CPU and memory utilization for running instances
	if len(runningIDs) > 0 {
		cpuMap, err := s.metrics.FetchAverage(ctx, "AWS/EC2", "CPUUtilization", "InstanceId", runningIDs, cfg.IdleDays)
		if err != nil {
			slog.Warn("Failed to fetch EC2 CPU metrics", "region", s.region, "error", err)
		} else {
			// Fetch memory utilization from CloudWatch Agent (optional — not all instances have the agent)
			memMap, memErr := s.metrics.FetchAverage(ctx, "CWAgent", "mem_used_percent", "InstanceId", runningIDs, cfg.IdleDays)
			if memErr != nil {
				slog.Warn("Failed to fetch EC2 memory metrics", "region", s.region, "error", memErr)
				memMap = make(map[string]float64)
			}

			instanceMap := buildInstanceMap(instances)
			for _, id := range runningIDs {
				avgCPU, ok := cpuMap[id]
				if !ok {
					continue
				}
				if avgCPU < cfg.IdleCPUThreshold {
					// Check if memory utilization is high enough to override the idle CPU signal
					avgMem, hasMem := memMap[id]
					if hasMem && avgMem >= cfg.HighMemoryThreshold {
						slog.Debug("Instance has low CPU but high memory — not idle",
							"instance", id, "cpu", avgCPU, "memory", avgMem)
						continue
					}

					inst := instanceMap[id]
					instanceType := string(inst.InstanceType)
					cost := pricing.MonthlyEC2Cost(instanceType, s.region)
					result.Findings = append(result.Findings, Finding{
						ID:                    FindingIdleEC2,
						Severity:              SeverityHigh,
						ResourceType:          ResourceEC2,
						ResourceID:            id,
						ResourceName:          instanceName(inst),
						Region:                s.region,
						Message:               idleMessage(avgCPU, avgMem, hasMem, cfg.IdleDays),
						EstimatedMonthlyWaste: cost,
						Metadata: map[string]any{
							"instance_type":   instanceType,
							"avg_cpu_percent": avgCPU,
							"avg_mem_percent": avgMem,
							"has_mem_metrics": hasMem,
							"state":           "running",
						},
					})
				}
			}
		}
	}

	return result, nil
}

func (s *EC2Scanner) listInstances(ctx context.Context) ([]ec2types.Instance, error) {
	var instances []ec2types.Instance
	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("instance-state-name"),
				Values: []string{"running", "stopped"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, res := range page.Reservations {
			instances = append(instances, res.Instances...)
		}
	}
	return instances, nil
}

func instanceName(inst ec2types.Instance) string {
	for _, tag := range inst.Tags {
		if deref(tag.Key) == "Name" {
			return deref(tag.Value)
		}
	}
	return ""
}

func stoppedSince(inst ec2types.Instance) time.Time {
	// LaunchTime is used as a proxy for when the instance was last active.
	// For a more precise stopped-since timestamp, CloudTrail events would be needed.
	if inst.LaunchTime != nil {
		return *inst.LaunchTime
	}
	return time.Time{}
}

func idleMessage(avgCPU, avgMem float64, hasMem bool, idleDays int) string {
	if hasMem {
		return fmt.Sprintf("CPU %.1f%%, memory %.1f%% over %d days", avgCPU, avgMem, idleDays)
	}
	return fmt.Sprintf("CPU %.1f%% over %d days", avgCPU, idleDays)
}

func buildInstanceMap(instances []ec2types.Instance) map[string]ec2types.Instance {
	m := make(map[string]ec2types.Instance, len(instances))
	for _, inst := range instances {
		if inst.InstanceId != nil {
			m[*inst.InstanceId] = inst
		}
	}
	return m
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
