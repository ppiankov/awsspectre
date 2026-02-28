package aws

import (
	"context"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// NATGatewayAPI is the minimal interface for NAT Gateway operations.
type NATGatewayAPI interface {
	DescribeNatGateways(ctx context.Context, input *ec2.DescribeNatGatewaysInput, opts ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
}

// NATGatewayScanner detects NAT Gateways with zero bytes processed.
type NATGatewayScanner struct {
	client  NATGatewayAPI
	metrics *MetricsFetcher
	region  string
}

// NewNATGatewayScanner creates a scanner for NAT Gateways.
func NewNATGatewayScanner(client NATGatewayAPI, metrics *MetricsFetcher, region string) *NATGatewayScanner {
	return &NATGatewayScanner{client: client, metrics: metrics, region: region}
}

// Type returns the resource type.
func (s *NATGatewayScanner) Type() ResourceType {
	return ResourceNATGateway
}

// Scan examines all NAT Gateways for zero bytes processed over the idle window.
func (s *NATGatewayScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	gateways, err := s.listNATGateways(ctx)
	if err != nil {
		return nil, fmt.Errorf("list NAT Gateways: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(gateways)}
	if len(gateways) == 0 {
		return result, nil
	}

	// Collect IDs for CloudWatch lookup
	var ids []string
	gwMap := make(map[string]ec2types.NatGateway, len(gateways))
	for _, gw := range gateways {
		id := deref(gw.NatGatewayId)
		if cfg.Exclude.ShouldExclude(id, ec2TagsToMap(gw.Tags)) {
			continue
		}
		ids = append(ids, id)
		gwMap[id] = gw
	}

	if len(ids) == 0 {
		return result, nil
	}

	// Fetch bytes out metric
	bytesOut, err := s.metrics.FetchSum(ctx, "AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", ids, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch NAT Gateway metrics", "region", s.region, "error", err)
		return result, nil
	}

	// Fetch bytes in metric
	bytesIn, err := s.metrics.FetchSum(ctx, "AWS/NATGateway", "BytesInFromDestination", "NatGatewayId", ids, cfg.IdleDays)
	if err != nil {
		slog.Warn("Failed to fetch NAT Gateway inbound metrics", "region", s.region, "error", err)
		bytesIn = make(map[string]float64)
	}

	for _, id := range ids {
		totalOut := bytesOut[id]
		totalIn := bytesIn[id]
		totalBytes := totalOut + totalIn

		gw := gwMap[id]
		name := natGatewayName(gw)
		baseMeta := map[string]any{
			"subnet_id": deref(gw.SubnetId),
			"vpc_id":    deref(gw.VpcId),
			"state":     string(gw.State),
		}

		if totalBytes == 0 {
			cost := pricing.MonthlyNATGatewayCost(s.region)
			result.Findings = append(result.Findings, Finding{
				ID:                    FindingIdleNATGateway,
				Severity:              SeverityHigh,
				ResourceType:          ResourceNATGateway,
				ResourceID:            id,
				ResourceName:          name,
				Region:                s.region,
				Message:               fmt.Sprintf("Zero bytes processed over %d days", cfg.IdleDays),
				EstimatedMonthlyWaste: cost,
				Metadata:              baseMeta,
			})
			continue
		}

		// Low-traffic check: extrapolate to monthly and compare to threshold
		monthlyBytes := totalBytes * (30.0 / float64(cfg.IdleDays))
		monthlyGB := monthlyBytes / (1024 * 1024 * 1024)

		if cfg.NATGWLowTrafficGB > 0 && monthlyGB < cfg.NATGWLowTrafficGB {
			gatewayCost := pricing.MonthlyNATGatewayCost(s.region)
			dataCost := monthlyGB * pricing.NATGatewayDataCostPerGB(s.region)
			totalCost := gatewayCost + dataCost

			meta := map[string]any{
				"subnet_id":            deref(gw.SubnetId),
				"vpc_id":               deref(gw.VpcId),
				"state":                string(gw.State),
				"bytes_in":             totalIn,
				"bytes_out":            totalOut,
				"total_bytes":          totalBytes,
				"estimated_monthly_gb": monthlyGB,
				"gateway_monthly_cost": gatewayCost,
				"data_processing_cost": dataCost,
			}

			result.Findings = append(result.Findings, Finding{
				ID:                    FindingLowTrafficNATGateway,
				Severity:              SeverityMedium,
				ResourceType:          ResourceNATGateway,
				ResourceID:            id,
				ResourceName:          name,
				Region:                s.region,
				Message:               fmt.Sprintf("NAT Gateway %q processed %.2f GB/month (est.) — $%.2f gateway + $%.2f data = $%.2f/month", name, monthlyGB, gatewayCost, dataCost, totalCost),
				EstimatedMonthlyWaste: totalCost,
				Metadata:              meta,
			})
		}
	}

	return result, nil
}

func (s *NATGatewayScanner) listNATGateways(ctx context.Context) ([]ec2types.NatGateway, error) {
	var gateways []ec2types.NatGateway
	paginator := ec2.NewDescribeNatGatewaysPaginator(s.client, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{
			{Name: awssdk.String("state"), Values: []string{"available"}},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		gateways = append(gateways, page.NatGateways...)
	}
	return gateways, nil
}

func natGatewayName(gw ec2types.NatGateway) string {
	for _, tag := range gw.Tags {
		if deref(tag.Key) == "Name" {
			return deref(tag.Value)
		}
	}
	return ""
}
