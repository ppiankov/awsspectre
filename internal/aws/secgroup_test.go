package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockSecurityGroupClient struct {
	groups     []ec2types.SecurityGroup
	interfaces []ec2types.NetworkInterface
}

func (m *mockSecurityGroupClient) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: m.groups}, nil
}

func (m *mockSecurityGroupClient) DescribeNetworkInterfaces(_ context.Context, _ *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: m.interfaces}, nil
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

func TestSecurityGroupScanner_Type(t *testing.T) {
	scanner := &SecurityGroupScanner{}
	if scanner.Type() != ResourceSecurityGroup {
		t.Fatalf("expected ResourceSecurityGroup, got %s", scanner.Type())
	}
}
