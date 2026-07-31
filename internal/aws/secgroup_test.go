package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockSecurityGroupClient struct {
	groups     []ec2types.SecurityGroup
	interfaces []ec2types.NetworkInterface
	// launchTemplateVersions is keyed by launch template ID.
	launchTemplateVersions map[string]ec2types.LaunchTemplateVersion
}

func (m *mockSecurityGroupClient) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: m.groups}, nil
}

func (m *mockSecurityGroupClient) DescribeNetworkInterfaces(_ context.Context, _ *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: m.interfaces}, nil
}

func (m *mockSecurityGroupClient) DescribeLaunchTemplateVersions(_ context.Context, input *ec2.DescribeLaunchTemplateVersionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	if input.LaunchTemplateId == nil {
		return &ec2.DescribeLaunchTemplateVersionsOutput{}, nil
	}
	v, ok := m.launchTemplateVersions[*input.LaunchTemplateId]
	if !ok {
		return &ec2.DescribeLaunchTemplateVersionsOutput{}, nil
	}
	return &ec2.DescribeLaunchTemplateVersionsOutput{LaunchTemplateVersions: []ec2types.LaunchTemplateVersion{v}}, nil
}

type mockAutoScalingClient struct {
	groups []asgtypes.AutoScalingGroup
	// launchConfigurations is keyed by LaunchConfigurationName.
	launchConfigurations map[string]asgtypes.LaunchConfiguration
}

func (m *mockAutoScalingClient) DescribeAutoScalingGroups(_ context.Context, _ *autoscaling.DescribeAutoScalingGroupsInput, _ ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: m.groups}, nil
}

func (m *mockAutoScalingClient) DescribeLaunchConfigurations(_ context.Context, input *autoscaling.DescribeLaunchConfigurationsInput, _ ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
	var lcs []asgtypes.LaunchConfiguration
	for _, name := range input.LaunchConfigurationNames {
		if lc, ok := m.launchConfigurations[name]; ok {
			lcs = append(lcs, lc)
		}
	}
	return &autoscaling.DescribeLaunchConfigurationsOutput{LaunchConfigurations: lcs}, nil
}

func TestSecurityGroupScanner_UnusedSG(t *testing.T) {
	mock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-unused001"),
				GroupName: awssdk.String("old-api-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil, // no ENIs = no SG usage
	}

	scanner := NewSecurityGroupScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Fatalf("expected 1 scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingUnusedSecurityGroup {
		t.Fatalf("expected UNUSED_SECURITY_GROUP, got %s", f.ID)
	}
	if f.ResourceID != "sg-unused001" {
		t.Fatalf("expected sg-unused001, got %s", f.ResourceID)
	}
	if f.Severity != SeverityLow {
		t.Fatalf("expected low severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste != 0 {
		t.Fatal("security groups should have zero cost")
	}
}

func TestSecurityGroupScanner_UsedSGNotFlagged(t *testing.T) {
	mock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-used001"),
				GroupName: awssdk.String("web-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: []ec2types.NetworkInterface{
			{
				Groups: []ec2types.GroupIdentifier{
					{GroupId: awssdk.String("sg-used001")},
				},
			},
		},
	}

	scanner := NewSecurityGroupScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for used SG, got %d", len(result.Findings))
	}
}

func TestSecurityGroupScanner_DefaultSGSkipped(t *testing.T) {
	mock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-default001"),
				GroupName: awssdk.String("default"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil,
	}

	scanner := NewSecurityGroupScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for default SG, got %d", len(result.Findings))
	}
}

func TestSecurityGroupScanner_CrossReferencedSGNotFlagged(t *testing.T) {
	mock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-ref001"),
				GroupName: awssdk.String("referenced-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
			{
				GroupId:   awssdk.String("sg-other"),
				GroupName: awssdk.String("other-sg"),
				VpcId:     awssdk.String("vpc-001"),
				IpPermissions: []ec2types.IpPermission{
					{
						UserIdGroupPairs: []ec2types.UserIdGroupPair{
							{GroupId: awssdk.String("sg-ref001")},
						},
					},
				},
			},
		},
		interfaces: nil,
	}

	scanner := NewSecurityGroupScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// sg-ref001 is referenced by sg-other's ingress rules, so it should not be flagged
	for _, f := range result.Findings {
		if f.ResourceID == "sg-ref001" {
			t.Fatal("expected cross-referenced SG to not be flagged")
		}
	}
}

func TestSecurityGroupScanner_NoGroups(t *testing.T) {
	mock := &mockSecurityGroupClient{}
	scanner := NewSecurityGroupScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestSecurityGroupScanner_ExcludedSG(t *testing.T) {
	mock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-excluded001"),
				GroupName: awssdk.String("excluded-sg"),
			},
		},
		interfaces: nil,
	}

	scanner := NewSecurityGroupScanner(mock, "us-east-1")
	cfg := ScanConfig{
		Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"sg-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded SG, got %d", len(result.Findings))
	}
}

func TestSecurityGroupScanner_ASGReferencedViaLaunchConfiguration_NotFlagged(t *testing.T) {
	// WO-232: a security group referenced only by a scaled-to-zero ASG's
	// launch configuration has no live ENI attachments right now but will
	// need the group again the moment it scales back up.
	sgMock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-lc-referenced"),
				GroupName: awssdk.String("gpu-nodepool-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil, // scaled to zero — no ENIs
	}
	asgMock := &mockAutoScalingClient{
		groups: []asgtypes.AutoScalingGroup{
			{
				AutoScalingGroupName:    awssdk.String("gpu-nodepool-asg"),
				LaunchConfigurationName: awssdk.String("gpu-nodepool-lc"),
			},
		},
		launchConfigurations: map[string]asgtypes.LaunchConfiguration{
			"gpu-nodepool-lc": {
				LaunchConfigurationName: awssdk.String("gpu-nodepool-lc"),
				SecurityGroups:          []string{"sg-lc-referenced"},
			},
		},
	}

	scanner := NewSecurityGroupScanner(sgMock, "us-east-1")
	scanner.SetAutoScalingClient(asgMock)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected the ASG-referenced SG to not be flagged, got %d findings: %+v", len(result.Findings), result.Findings)
	}
}

func TestSecurityGroupScanner_ASGReferencedViaLaunchTemplate_NotFlagged(t *testing.T) {
	sgMock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-lt-referenced"),
				GroupName: awssdk.String("spot-nodepool-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil,
		launchTemplateVersions: map[string]ec2types.LaunchTemplateVersion{
			"lt-001": {
				LaunchTemplateId: awssdk.String("lt-001"),
				LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
					SecurityGroupIds: []string{"sg-lt-referenced"},
				},
			},
		},
	}
	asgMock := &mockAutoScalingClient{
		groups: []asgtypes.AutoScalingGroup{
			{
				AutoScalingGroupName: awssdk.String("spot-nodepool-asg"),
				LaunchTemplate: &asgtypes.LaunchTemplateSpecification{
					LaunchTemplateId: awssdk.String("lt-001"),
					Version:          awssdk.String("$Latest"),
				},
			},
		},
	}

	scanner := NewSecurityGroupScanner(sgMock, "us-east-1")
	scanner.SetAutoScalingClient(asgMock)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected the ASG launch-template-referenced SG to not be flagged, got %d findings: %+v", len(result.Findings), result.Findings)
	}
}

func TestSecurityGroupScanner_ASGReferencedViaMixedInstancesPolicy_NotFlagged(t *testing.T) {
	// A mixed-instances ASG references its launch template indirectly via
	// MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification, not
	// the top-level LaunchTemplate field.
	sgMock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-mip-referenced"),
				GroupName: awssdk.String("mixed-nodepool-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil,
		launchTemplateVersions: map[string]ec2types.LaunchTemplateVersion{
			"lt-002": {
				LaunchTemplateId: awssdk.String("lt-002"),
				LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
					NetworkInterfaces: []ec2types.LaunchTemplateInstanceNetworkInterfaceSpecification{
						{Groups: []string{"sg-mip-referenced"}},
					},
				},
			},
		},
	}
	asgMock := &mockAutoScalingClient{
		groups: []asgtypes.AutoScalingGroup{
			{
				AutoScalingGroupName: awssdk.String("mixed-nodepool-asg"),
				MixedInstancesPolicy: &asgtypes.MixedInstancesPolicy{
					LaunchTemplate: &asgtypes.LaunchTemplate{
						LaunchTemplateSpecification: &asgtypes.LaunchTemplateSpecification{
							LaunchTemplateId: awssdk.String("lt-002"),
							Version:          awssdk.String("$Default"),
						},
					},
				},
			},
		},
	}

	scanner := NewSecurityGroupScanner(sgMock, "us-east-1")
	scanner.SetAutoScalingClient(asgMock)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected the MixedInstancesPolicy-referenced SG to not be flagged, got %d findings: %+v", len(result.Findings), result.Findings)
	}
}

func TestSecurityGroupScanner_GenuinelyUnreferencedSG_StillFlaggedWithASGClientSet(t *testing.T) {
	// Even with an AutoScaling client configured, a security group that no
	// ASG references at all must still be flagged — the new code path must
	// not accidentally suppress everything.
	sgMock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-genuinely-unused"),
				GroupName: awssdk.String("orphan-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil,
	}
	asgMock := &mockAutoScalingClient{
		groups: []asgtypes.AutoScalingGroup{
			{
				AutoScalingGroupName:    awssdk.String("unrelated-asg"),
				LaunchConfigurationName: awssdk.String("unrelated-lc"),
			},
		},
		launchConfigurations: map[string]asgtypes.LaunchConfiguration{
			"unrelated-lc": {
				LaunchConfigurationName: awssdk.String("unrelated-lc"),
				SecurityGroups:          []string{"sg-completely-different"},
			},
		},
	}

	scanner := NewSecurityGroupScanner(sgMock, "us-east-1")
	scanner.SetAutoScalingClient(asgMock)
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the genuinely unreferenced SG to still be flagged, got %d findings", len(result.Findings))
	}
	if result.Findings[0].ResourceID != "sg-genuinely-unused" {
		t.Fatalf("expected sg-genuinely-unused, got %s", result.Findings[0].ResourceID)
	}
}

func TestSecurityGroupScanner_NoAutoScalingClient_FallsBackToENIOnly(t *testing.T) {
	// Without SetAutoScalingClient, an ASG-only-referenced SG with no ENIs
	// still gets flagged (documents the intentional graceful-degradation
	// fallback — the same shape as TestSecurityGroupScanner_UnusedSG, but
	// explicit about why: no autoscaling client means no ASG lookup at all).
	sgMock := &mockSecurityGroupClient{
		groups: []ec2types.SecurityGroup{
			{
				GroupId:   awssdk.String("sg-no-asg-client"),
				GroupName: awssdk.String("gpu-nodepool-sg"),
				VpcId:     awssdk.String("vpc-001"),
			},
		},
		interfaces: nil,
	}

	scanner := NewSecurityGroupScanner(sgMock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the SG to be flagged without an AutoScaling client configured, got %d findings", len(result.Findings))
	}
}

func TestSecurityGroupScanner_Type(t *testing.T) {
	scanner := &SecurityGroupScanner{}
	if scanner.Type() != ResourceSecurityGroup {
		t.Fatalf("expected ResourceSecurityGroup, got %s", scanner.Type())
	}
}
