package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// SecurityGroupAPI is the minimal interface for security group operations.
type SecurityGroupAPI interface {
	DescribeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// SecurityGroupScanner detects security groups with no attached ENIs.
type SecurityGroupScanner struct {
	client SecurityGroupAPI
	region string
}

// NewSecurityGroupScanner creates a scanner for security groups.
func NewSecurityGroupScanner(client SecurityGroupAPI, region string) *SecurityGroupScanner {
	return &SecurityGroupScanner{client: client, region: region}
}

// Type returns the resource type.
func (s *SecurityGroupScanner) Type() ResourceType {
	return ResourceSecurityGroup
}

// Scan examines all security groups for unused ones.
func (s *SecurityGroupScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	groups, err := s.listSecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list security groups: %w", err)
	}

	result := &ScanResult{ResourcesScanned: len(groups)}
	if len(groups) == 0 {
		return result, nil
	}

	// Build set of SG IDs that have at least one ENI attached
	usedSGs, err := s.findUsedSecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("find used security groups: %w", err)
	}

	for _, sg := range groups {
		sgID := deref(sg.GroupId)
		sgName := deref(sg.GroupName)

		if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[sgID] {
			continue
		}

		// Skip default security groups — they can't be deleted
		if sgName == "default" {
			continue
		}

		if usedSGs[sgID] {
			continue
		}

		result.Findings = append(result.Findings, Finding{
			ID:                    FindingUnusedSecurityGroup,
			Severity:              SeverityLow,
			ResourceType:          ResourceSecurityGroup,
			ResourceID:            sgID,
			ResourceName:          sgName,
			Region:                s.region,
			Message:               fmt.Sprintf("Security group %q has no attached ENIs", sgName),
			EstimatedMonthlyWaste: 0, // SGs have no direct cost
			Metadata: map[string]any{
				"group_name": sgName,
				"vpc_id":     deref(sg.VpcId),
			},
		})
	}

	return result, nil
}

func (s *SecurityGroupScanner) listSecurityGroups(ctx context.Context) ([]ec2types.SecurityGroup, error) {
	var groups []ec2types.SecurityGroup
	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.SecurityGroups...)
	}
	return groups, nil
}

func (s *SecurityGroupScanner) findUsedSecurityGroups(ctx context.Context) (map[string]bool, error) {
	used := make(map[string]bool)
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(s.client, &ec2.DescribeNetworkInterfacesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, eni := range page.NetworkInterfaces {
			for _, sg := range eni.Groups {
				if sg.GroupId != nil {
					used[*sg.GroupId] = true
				}
			}
		}
	}

	// Also check security groups that reference other groups in their rules
	// (cross-referenced SGs are "in use" even without direct ENI attachment)
	allGroups, err := s.listSecurityGroups(ctx)
	if err == nil {
		for _, sg := range allGroups {
			for _, perm := range sg.IpPermissions {
				for _, pair := range perm.UserIdGroupPairs {
					if pair.GroupId != nil {
						used[*pair.GroupId] = true
					}
				}
			}
			for _, perm := range sg.IpPermissionsEgress {
				for _, pair := range perm.UserIdGroupPairs {
					if pair.GroupId != nil {
						used[*pair.GroupId] = true
					}
				}
			}
		}
	}

	return used, nil
}
