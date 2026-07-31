package aws

import (
	"context"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// SecurityGroupAPI is the minimal interface for security group operations.
type SecurityGroupAPI interface {
	DescribeSecurityGroups(ctx context.Context, input *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeLaunchTemplateVersions(ctx context.Context, input *ec2.DescribeLaunchTemplateVersionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error)
}

// AutoScalingAPI is the minimal interface for Auto Scaling Group operations
// needed to detect security groups referenced by an ASG's launch template or
// launch configuration, regardless of the ASG's current desired capacity —
// WO-232.
type AutoScalingAPI interface {
	DescribeAutoScalingGroups(ctx context.Context, input *autoscaling.DescribeAutoScalingGroupsInput, opts ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	DescribeLaunchConfigurations(ctx context.Context, input *autoscaling.DescribeLaunchConfigurationsInput, opts ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error)
}

// autoScalingBatchSize caps LaunchConfigurationNames per
// DescribeLaunchConfigurations call to stay comfortably under AWS's
// documented per-call limits.
const autoScalingBatchSize = 50

// SecurityGroupScanner detects security groups with no attached ENIs.
type SecurityGroupScanner struct {
	client      SecurityGroupAPI
	region      string
	autoScaling AutoScalingAPI
}

// NewSecurityGroupScanner creates a scanner for security groups.
func NewSecurityGroupScanner(client SecurityGroupAPI, region string) *SecurityGroupScanner {
	return &SecurityGroupScanner{client: client, region: region}
}

// SetAutoScalingClient enables ASG-referenced security group detection
// (WO-232). Optional: without it, a security group referenced only by a
// scaled-to-zero ASG's launch template/configuration falls back to being
// flagged as unused, since it currently has no live ENI attachments either.
func (s *SecurityGroupScanner) SetAutoScalingClient(client AutoScalingAPI) {
	s.autoScaling = client
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

		if cfg.Exclude.ShouldExclude(sgID, ec2TagsToMap(sg.Tags)) {
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
			EstimatedMonthlyWaste: 0,    // SGs have no direct cost
			Hygiene:               true, // WO-194: zero-waste security-group hygiene findings stay visible.
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

	// A security group referenced only by a scaled-to-zero ASG's launch
	// template/configuration shows zero ENI attachments right now but will
	// need the group again the moment it scales back up — WO-232.
	s.findASGReferencedSecurityGroups(ctx, used)

	return used, nil
}

// findASGReferencedSecurityGroups adds to used any security group ID
// referenced by an Auto Scaling Group's launch template or launch
// configuration, regardless of the ASG's current desired capacity. Optional:
// without an AutoScaling client (SetAutoScalingClient not called), this step
// is silently skipped and detection falls back to ENI/rule-based signals
// only — the same graceful-degradation pattern as CloudTrailAPI elsewhere in
// this package.
func (s *SecurityGroupScanner) findASGReferencedSecurityGroups(ctx context.Context, used map[string]bool) {
	if s.autoScaling == nil {
		return
	}

	groups, err := s.listAutoScalingGroups(ctx)
	if err != nil {
		slog.Warn("Failed to list Auto Scaling Groups", "region", s.region, "error", err)
		return
	}
	if len(groups) == 0 {
		return
	}

	var lcNames []string
	type templateRef struct {
		id      string
		version string
	}
	var templateRefs []templateRef
	seenTemplateVersion := make(map[string]bool)

	addTemplateRef := func(spec *asgtypes.LaunchTemplateSpecification) {
		if spec == nil || spec.LaunchTemplateId == nil {
			return
		}
		version := "$Default"
		if spec.Version != nil && *spec.Version != "" {
			version = *spec.Version
		}
		key := *spec.LaunchTemplateId + "/" + version
		if seenTemplateVersion[key] {
			return
		}
		seenTemplateVersion[key] = true
		templateRefs = append(templateRefs, templateRef{id: *spec.LaunchTemplateId, version: version})
	}

	for _, g := range groups {
		if g.LaunchConfigurationName != nil && *g.LaunchConfigurationName != "" {
			lcNames = append(lcNames, *g.LaunchConfigurationName)
		}
		addTemplateRef(g.LaunchTemplate)
		if g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil {
			addTemplateRef(g.MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification)
		}
	}

	if len(lcNames) > 0 {
		sgIDs, err := s.launchConfigurationSecurityGroups(ctx, lcNames)
		if err != nil {
			slog.Warn("Failed to describe launch configurations", "region", s.region, "error", err)
		} else {
			for _, id := range sgIDs {
				used[id] = true
			}
		}
	}

	for _, ref := range templateRefs {
		sgIDs, err := s.launchTemplateSecurityGroups(ctx, ref.id, ref.version)
		if err != nil {
			slog.Warn("Failed to describe launch template version", "launch_template_id", ref.id, "version", ref.version, "error", err)
			continue
		}
		for _, id := range sgIDs {
			used[id] = true
		}
	}
}

func (s *SecurityGroupScanner) listAutoScalingGroups(ctx context.Context) ([]asgtypes.AutoScalingGroup, error) {
	var groups []asgtypes.AutoScalingGroup
	paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(s.autoScaling, &autoscaling.DescribeAutoScalingGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.AutoScalingGroups...)
	}
	return groups, nil
}

func (s *SecurityGroupScanner) launchConfigurationSecurityGroups(ctx context.Context, names []string) ([]string, error) {
	var sgIDs []string
	for i := 0; i < len(names); i += autoScalingBatchSize {
		end := i + autoScalingBatchSize
		if end > len(names) {
			end = len(names)
		}
		out, err := s.autoScaling.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{
			LaunchConfigurationNames: names[i:end],
		})
		if err != nil {
			return nil, err
		}
		for _, lc := range out.LaunchConfigurations {
			sgIDs = append(sgIDs, lc.SecurityGroups...)
		}
	}
	return sgIDs, nil
}

func (s *SecurityGroupScanner) launchTemplateSecurityGroups(ctx context.Context, templateID, version string) ([]string, error) {
	out, err := s.client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: awssdk.String(templateID),
		Versions:         []string{version},
	})
	if err != nil {
		return nil, err
	}

	var sgIDs []string
	for _, v := range out.LaunchTemplateVersions {
		if v.LaunchTemplateData == nil {
			continue
		}
		sgIDs = append(sgIDs, v.LaunchTemplateData.SecurityGroupIds...)
		for _, ni := range v.LaunchTemplateData.NetworkInterfaces {
			sgIDs = append(sgIDs, ni.Groups...)
		}
	}
	return sgIDs, nil
}
