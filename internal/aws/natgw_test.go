package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockNATGatewayClient struct {
	gateways []ec2types.NatGateway
}

func (m *mockNATGatewayClient) DescribeNatGateways(_ context.Context, _ *ec2.DescribeNatGatewaysInput, _ ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return &ec2.DescribeNatGatewaysOutput{NatGateways: m.gateways}, nil
}

func TestNATGatewayScanner_IdleGateway(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-idle001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				Tags:         []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("idle-nat")}},
			},
		},
	}

	// Return zero bytes for both metrics
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{0}},
				},
			}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
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
	if f.ID != FindingIdleNATGateway {
		t.Fatalf("expected IDLE_NAT_GATEWAY, got %s", f.ID)
	}
	if f.ResourceID != "nat-idle001" {
		t.Fatalf("expected nat-idle001, got %s", f.ResourceID)
	}
	if f.ResourceName != "idle-nat" {
		t.Fatalf("expected name idle-nat, got %s", f.ResourceName)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestNATGatewayScanner_ActiveGateway(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-active001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
			},
		},
	}

	// Return non-zero bytes
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{1024.0, 2048.0},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active gateway, got %d", len(result.Findings))
	}
}

func TestNATGatewayScanner_NoGateways(t *testing.T) {
	mock := &mockNATGatewayClient{gateways: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestNATGatewayScanner_ExcludedGateway(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-excluded001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
			},
		},
	}

	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{0}},
				},
			}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{"nat-excluded001": true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded gateway, got %d", len(result.Findings))
	}
}

func TestNATGatewayScanner_Type(t *testing.T) {
	scanner := &NATGatewayScanner{}
	if scanner.Type() != ResourceNATGateway {
		t.Fatalf("expected ResourceNATGateway, got %s", scanner.Type())
	}
}

func TestNATGatewayName(t *testing.T) {
	gw := ec2types.NatGateway{
		Tags: []ec2types.Tag{
			{Key: awssdk.String("Env"), Value: awssdk.String("prod")},
			{Key: awssdk.String("Name"), Value: awssdk.String("my-nat")},
		},
	}
	if name := natGatewayName(gw); name != "my-nat" {
		t.Fatalf("expected my-nat, got %s", name)
	}

	gwNoName := ec2types.NatGateway{}
	if name := natGatewayName(gwNoName); name != "" {
		t.Fatalf("expected empty string, got %s", name)
	}
}
