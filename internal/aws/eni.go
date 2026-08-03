package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ENIAPI is the minimal interface for ENI operations.
type ENIAPI interface {
	DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// ENIScanner detects unattached (available-status) elastic network interfaces.
type ENIScanner struct {
	client ENIAPI
	region string
}

// NewENIScanner creates a scanner for unattached ENIs.
func NewENIScanner(client ENIAPI, region string) *ENIScanner {
	return &ENIScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *ENIScanner) Type() ResourceType {
	return ResourceENI
}

// Scan examines all ENIs for unattached interfaces.
func (s *ENIScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	enis, err := s.listENIs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ENIs: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(enis)}
	if len(enis) == 0 {
		return result, nil
	}

	for _, eni := range enis {
		name := deref(eni.NetworkInterfaceId)
		tags := ec2TagsToMap(eni.TagSet)
		if cfg.Exclude.ShouldExclude(name, tags) {
			continue
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingUnattachedENI,
			Severity:              SeverityLow,
			ResourceType:          ResourceENI,
			ResourceID:            name,
			ResourceName:          deref(eni.Description),
			Region:                s.region,
			Message:               "Unattached elastic network interface",
			EstimatedMonthlyWaste: 0,
			Hygiene:               true,
			Metadata: map[string]any{
				"vpc_id": deref(eni.VpcId),
			},
		})
	}

	return result, nil
}

func (s *ENIScanner) listENIs(ctx context.Context) ([]ec2types.NetworkInterface, error) {
	var enis []ec2types.NetworkInterface
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(s.client, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("status"), Values: []string{"available"}},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		enis = append(enis, page.NetworkInterfaces...)
	}
	return enis, nil
}
