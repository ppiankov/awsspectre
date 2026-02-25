package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// rdsIdleCPUThreshold is the CPU % below which an RDS instance is considered idle.
const rdsIdleCPUThreshold = 5.0

// RDSAPI is the minimal interface for RDS operations.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, input *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// RDSScanner detects idle RDS instances.
type RDSScanner struct {
	client  RDSAPI
	metrics *MetricsFetcher
	region  string
}

// NewRDSScanner creates a scanner for RDS instances.
func NewRDSScanner(client RDSAPI, metrics *MetricsFetcher, region string) *RDSScanner {
	return &RDSScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *RDSScanner) Type() ResourceType {
	return ResourceRDS
}

// Scan examines all RDS instances for idle resources.
func (s *RDSScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	instances, err := s.listDBInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("list RDS instances: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(instances)}
	if len(instances) == 0 {
		return result, nil
	}

	// Collect instance identifiers for metric lookup
	var ids []string
	instMap := make(map[string]rdstypes.DBInstance, len(instances))
	for _, inst := range instances {
		id := deref(inst.DBInstanceIdentifier)
		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[id] {
			continue
		}
		// Only check instances that are "available" (running)
		if deref(inst.DBInstanceStatus) != "available" {
			continue
		}
		ids = append(ids, id)
		instMap[id] = inst
	}

	if len(ids) == 0 {
		return result, nil
	}

	// Fetch CPU utilization
	cpuMap, err := s.metrics.FetchAverage(ctx, "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", ids, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch RDS CPU metrics", "region", s.region, "error", err)
		return result, nil
	}

	// Fetch database connections
	connMap, err := s.metrics.FetchSum(ctx, "AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", ids, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch RDS connection metrics", "region", s.region, "error", err)
		connMap = make(map[string]float64)
	}

	for _, id := range ids {
		avgCPU, hasCPU := cpuMap[id]
		totalConns := connMap[id]

		// Flag if CPU is below threshold or zero connections
		isIdle := (hasCPU && avgCPU < rdsIdleCPUThreshold) || totalConns == 0
		if !isIdle {
			continue
		}

		inst := instMap[id]
		instanceClass := deref(inst.DBInstanceClass)
		multiAZ := inst.MultiAZ != nil && *inst.MultiAZ
		cost := pricing.MonthlyRDSCost(instanceClass, s.region, multiAZ)

		msg := fmt.Sprintf("CPU %.1f%% over %d days", avgCPU, cfg.IdleDays)
		if totalConns == 0 {
			msg = fmt.Sprintf("Zero connections over %d days, CPU %.1f%%", cfg.IdleDays, avgCPU)
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingIdleRDS,
			Severity:              SeverityHigh,
			ResourceType:          ResourceRDS,
			ResourceID:            id,
			ResourceName:          id,
			Region:                s.region,
			Message:               msg,
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"instance_class":    instanceClass,
				"engine":            deref(inst.Engine),
				"multi_az":          multiAZ,
				"avg_cpu_percent":   avgCPU,
				"total_connections": totalConns,
			},
		})
	}

	return result, nil
}

func (s *RDSScanner) listDBInstances(ctx context.Context) ([]rdstypes.DBInstance, error) {
	var instances []rdstypes.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(s.client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		instances = append(instances, page.DBInstances...)
	}
	return instances, nil
}
