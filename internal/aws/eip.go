package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/ppiankov/awsspectre/internal/pricing"
)

// EIPAPI is the minimal interface for Elastic IP operations.
type EIPAPI interface {
	DescribeAddresses(ctx context.Context, input *ec2.DescribeAddressesInput, opts ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

// EIPScanner detects unassociated Elastic IPs.
type EIPScanner struct {
	client EIPAPI
	region string
}

// NewEIPScanner creates a scanner for Elastic IPs.
func NewEIPScanner(client EIPAPI, region string) *EIPScanner {
	return &EIPScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *EIPScanner) Type() ResourceType {
	return ResourceEIP
}

// Scan examines all Elastic IPs in the region for unassociated addresses.
func (s *EIPScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	out, err := s.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("describe addresses: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(out.Addresses)}

	for _, addr := range out.Addresses {
		allocID := deref(addr.AllocationId)
		if cfg.Exclude.ShouldExclude(allocID, ec2TagsToMap(addr.Tags)) {
			continue
		}

		// EIP is unassociated if it has no association ID
		if addr.AssociationId != nil {
			continue
		}

		cost := pricing.MonthlyEIPCost(s.region)
		publicIP := deref(addr.PublicIp)

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingUnusedEIP,
			Severity:              SeverityMedium,
			ResourceType:          ResourceEIP,
			ResourceID:            allocID,
			Region:                s.region,
			Message:               fmt.Sprintf("Elastic IP %s not associated with any instance", publicIP),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"public_ip": publicIP,
				"domain":    string(addr.Domain),
			},
		})
	}

	return result, nil
}
