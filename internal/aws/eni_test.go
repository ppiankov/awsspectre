package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockENIClient struct {
	enis []ec2types.NetworkInterface
}

func (m *mockENIClient) DescribeNetworkInterfaces(_ context.Context, _ *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: m.enis}, nil
}

func TestENIScanner_UnattachedENI(t *testing.T) {
	mock := &mockENIClient{
		enis: []ec2types.NetworkInterface{
			{NetworkInterfaceId: awssdk.String("eni-orphan001"), Status: ec2types.NetworkInterfaceStatusAvailable, Description: awssdk.String("leftover")},
		},
	}
	scanner := NewENIScanner(mock, "us-east-1")

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
	if f.ID != FindingUnattachedENI {
		t.Fatalf("expected UNATTACHED_ENI, got %s", f.ID)
	}
	if f.ResourceType != ResourceENI {
		t.Fatalf("expected ResourceENI, got %s", f.ResourceType)
	}
	if !f.Hygiene {
		t.Fatal("expected Hygiene=true")
	}
}

func TestENIScanner_NoENIs(t *testing.T) {
	mock := &mockENIClient{enis: nil}
	scanner := NewENIScanner(mock, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestENIScanner_ExcludedByID(t *testing.T) {
	mock := &mockENIClient{
		enis: []ec2types.NetworkInterface{
			{NetworkInterfaceId: awssdk.String("eni-excluded"), Status: ec2types.NetworkInterfaceStatusAvailable},
		},
	}
	scanner := NewENIScanner(mock, "us-east-1")
	cfg := ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"eni-excluded": true}}}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestENIScanner_Type(t *testing.T) {
	if (&ENIScanner{}).Type() != ResourceENI {
		t.Fatal("expected ResourceENI")
	}
}
