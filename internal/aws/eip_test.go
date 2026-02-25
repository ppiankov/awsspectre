package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEIPClient struct {
	addresses []ec2types.Address
}

func (m *mockEIPClient) DescribeAddresses(_ context.Context, _ *ec2.DescribeAddressesInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: m.addresses}, nil
}

func TestEIPScanner_UnassociatedEIP(t *testing.T) {
	mock := &mockEIPClient{
		addresses: []ec2types.Address{
			{
				AllocationId: awssdk.String("eipalloc-unassoc001"),
				PublicIp:     awssdk.String("54.1.2.3"),
				Domain:       ec2types.DomainTypeVpc,
				// No AssociationId = unassociated
			},
		},
	}

	scanner := NewEIPScanner(mock, "us-east-1")
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
	if f.ID != FindingUnusedEIP {
		t.Fatalf("expected UNUSED_EIP, got %s", f.ID)
	}
	if f.ResourceID != "eipalloc-unassoc001" {
		t.Fatalf("expected eipalloc-unassoc001, got %s", f.ResourceID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestEIPScanner_AssociatedEIPNotFlagged(t *testing.T) {
	mock := &mockEIPClient{
		addresses: []ec2types.Address{
			{
				AllocationId:  awssdk.String("eipalloc-assoc001"),
				PublicIp:      awssdk.String("54.1.2.4"),
				AssociationId: awssdk.String("eipassoc-12345"),
				Domain:        ec2types.DomainTypeVpc,
			},
		},
	}

	scanner := NewEIPScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for associated EIP, got %d", len(result.Findings))
	}
}

func TestEIPScanner_NoEIPs(t *testing.T) {
	mock := &mockEIPClient{addresses: nil}
	scanner := NewEIPScanner(mock, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestEIPScanner_MixedEIPs(t *testing.T) {
	mock := &mockEIPClient{
		addresses: []ec2types.Address{
			{
				AllocationId:  awssdk.String("eipalloc-1"),
				PublicIp:      awssdk.String("54.1.1.1"),
				AssociationId: awssdk.String("eipassoc-1"),
			},
			{
				AllocationId: awssdk.String("eipalloc-2"),
				PublicIp:     awssdk.String("54.1.1.2"),
				// unassociated
			},
			{
				AllocationId:  awssdk.String("eipalloc-3"),
				PublicIp:      awssdk.String("54.1.1.3"),
				AssociationId: awssdk.String("eipassoc-3"),
			},
		},
	}

	scanner := NewEIPScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 3 {
		t.Fatalf("expected 3 scanned, got %d", result.ResourcesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (only unassociated), got %d", len(result.Findings))
	}
}

func TestEIPScanner_ExcludedEIP(t *testing.T) {
	mock := &mockEIPClient{
		addresses: []ec2types.Address{
			{
				AllocationId: awssdk.String("eipalloc-excluded"),
				PublicIp:     awssdk.String("54.1.2.5"),
			},
		},
	}

	scanner := NewEIPScanner(mock, "us-east-1")
	cfg := ScanConfig{
		Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"eipalloc-excluded": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded EIP, got %d", len(result.Findings))
	}
}

func TestEIPScanner_Type(t *testing.T) {
	scanner := &EIPScanner{}
	if scanner.Type() != ResourceEIP {
		t.Fatalf("expected ResourceEIP, got %s", scanner.Type())
	}
}
