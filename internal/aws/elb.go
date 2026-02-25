package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// ELBAPI is the minimal interface for ELBv2 operations.
type ELBAPI interface {
	DescribeLoadBalancers(ctx context.Context, input *elasticloadbalancingv2.DescribeLoadBalancersInput, opts ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeTargetGroups(ctx context.Context, input *elasticloadbalancingv2.DescribeTargetGroupsInput, opts ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(ctx context.Context, input *elasticloadbalancingv2.DescribeTargetHealthInput, opts ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error)
}

// ELBScanner detects idle ALBs and NLBs.
type ELBScanner struct {
	client  ELBAPI
	metrics *MetricsFetcher
	region  string
}

// NewELBScanner creates a scanner for load balancers.
func NewELBScanner(client ELBAPI, metrics *MetricsFetcher, region string) *ELBScanner {
	return &ELBScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type. Returns ALB as the primary type since it handles both.
func (s *ELBScanner) Type() ResourceType {
	return ResourceALB
}

// Scan examines all ALBs and NLBs in the region for idle load balancers.
func (s *ELBScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	lbs, err := s.listLoadBalancers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list load balancers: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(lbs)}
	if len(lbs) == 0 {
		return result, nil
	}

	for _, lb := range lbs {
		lbARN := deref(lb.LoadBalancerArn)
		lbName := deref(lb.LoadBalancerName)

		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[lbARN] {
			continue
		}

		// Check if the LB has any healthy targets
		hasHealthy, err := s.hasHealthyTargets(ctx, lbARN)
		if err != nil {
			slog.Warn("Failed to check target health", "lb", lbName, "error", err)
			continue
		}

		if hasHealthy {
			// LB has healthy targets — check request count via CloudWatch
			idle, err := s.isIdleByRequests(ctx, lb, cfg.IdleDays)
			if err != nil {
				slog.Warn("Failed to check request metrics", "lb", lbName, "error", err)
				continue
			}
			if !idle {
				continue
			}
		}

		// LB is idle: zero healthy targets or zero requests
		findingID, resourceType, cost := s.classifyLB(lb)
		msg := fmt.Sprintf("Load balancer %q has no healthy targets or zero requests over %d days", lbName, cfg.IdleDays)

		result.Findings = append(result.Findings, Finding{
			ID:                    findingID,
			Severity:              SeverityHigh,
			ResourceType:          resourceType,
			ResourceID:            lbARN,
			ResourceName:          lbName,
			Region:                s.region,
			Message:               msg,
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"lb_type": string(lb.Type),
				"scheme":  string(lb.Scheme),
				"vpc_id":  deref(lb.VpcId),
			},
		})
	}

	return result, nil
}

func (s *ELBScanner) listLoadBalancers(ctx context.Context) ([]elbtypes.LoadBalancer, error) {
	var lbs []elbtypes.LoadBalancer
	var marker *string

	for {
		out, err := s.client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}
		lbs = append(lbs, out.LoadBalancers...)
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return lbs, nil
}

func (s *ELBScanner) hasHealthyTargets(ctx context.Context, lbARN string) (bool, error) {
	tgOut, err := s.client.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: &lbARN,
	})
	if err != nil {
		return false, err
	}

	for _, tg := range tgOut.TargetGroups {
		if tg.TargetGroupArn == nil {
			continue
		}
		healthOut, err := s.client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
			TargetGroupArn: tg.TargetGroupArn,
		})
		if err != nil {
			continue
		}
		for _, desc := range healthOut.TargetHealthDescriptions {
			if desc.TargetHealth != nil && desc.TargetHealth.State == elbtypes.TargetHealthStateEnumHealthy {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *ELBScanner) isIdleByRequests(ctx context.Context, lb elbtypes.LoadBalancer, idleDays int) (bool, error) {
	// Extract the LB suffix from the ARN for CloudWatch dimension
	// ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
	lbARN := deref(lb.LoadBalancerArn)
	if lbARN == "" {
		return false, nil
	}

	var metricName string
	switch lb.Type {
	case elbtypes.LoadBalancerTypeEnumApplication:
		metricName = "RequestCount"
	case elbtypes.LoadBalancerTypeEnumNetwork:
		metricName = "ActiveFlowCount"
	default:
		return false, nil
	}

	namespace := "AWS/ApplicationELB"
	dimensionName := "LoadBalancer"
	if lb.Type == elbtypes.LoadBalancerTypeEnumNetwork {
		namespace = "AWS/NetworkELB"
	}

	// Extract the LB dimension value from the ARN
	lbDimValue := extractLBDimension(lbARN)
	if lbDimValue == "" {
		return false, nil
	}

	sums, err := s.metrics.FetchSum(ctx, namespace, metricName, dimensionName, []string{lbDimValue}, idleDays)
	if err != nil {
		return false, err
	}

	total, ok := sums[lbDimValue]
	if !ok {
		// No data means no requests
		return true, nil
	}
	return total == 0, nil
}

func (s *ELBScanner) classifyLB(lb elbtypes.LoadBalancer) (FindingID, ResourceType, float64) {
	switch lb.Type {
	case elbtypes.LoadBalancerTypeEnumNetwork:
		return FindingIdleNLB, ResourceNLB, pricing.MonthlyNLBCost(s.region)
	default:
		return FindingIdleALB, ResourceALB, pricing.MonthlyALBCost(s.region)
	}
}

// extractLBDimension extracts the CloudWatch dimension value from an ELBv2 ARN.
// Input:  arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-lb/abc123
// Output: app/my-lb/abc123
func extractLBDimension(arn string) string {
	const prefix = "loadbalancer/"
	for i := 0; i <= len(arn)-len(prefix); i++ {
		if arn[i:i+len(prefix)] == prefix {
			return arn[i+len(prefix):]
		}
	}
	return ""
}
