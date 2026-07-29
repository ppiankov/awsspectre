package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestNATGatewayScanner_LowTraffic(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-lowtraffic001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				Tags:         []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("low-nat")}},
			},
		},
	}

	// Return small but non-zero bytes (~100 MB over 7 days)
	// 100 MB = 104857600 bytes; monthly est = 104857600 * (30/7) ≈ 449 MB ≈ 0.42 GB
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{50 * 1024 * 1024}, // 50 MB per metric
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, NATGWLowTrafficGB: 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 low-traffic finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingLowTrafficNATGateway {
		t.Fatalf("expected LOW_TRAFFIC_NAT_GATEWAY, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
	if f.Metadata["estimated_monthly_gb"] == nil {
		t.Fatal("expected estimated_monthly_gb in metadata")
	}
	if f.Metadata["gateway_monthly_cost"] == nil {
		t.Fatal("expected gateway_monthly_cost in metadata")
	}
	if f.Metadata["data_processing_cost"] == nil {
		t.Fatal("expected data_processing_cost in metadata")
	}
}

func TestNATGatewayScanner_AboveThreshold(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-busy001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
			},
		},
	}

	// Return ~5 GB over 7 days (well above 1 GB/month threshold)
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{2.5 * 1024 * 1024 * 1024}, // 2.5 GB per metric
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, NATGWLowTrafficGB: 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for above-threshold gateway, got %d", len(result.Findings))
	}
}

func TestNATGatewayScanner_RecentlyCreated_InsufficientHistoryMessage(t *testing.T) {
	// WO-251: same defect class as WO-236 (EC2) / WO-249 (RDS) / WO-250 (ELB)
	// — a gateway created less than cfg.IdleDays ago must not have its
	// zero-bytes message claim full window confidence it doesn't have.
	createTime := time.Now().UTC().Add(-11 * time.Minute)
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-fresh001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				CreateTime:   &createTime,
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

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the finding to still surface (evidence, not suppressed), got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected message to NOT claim full 7-day coverage for a gateway created 11 minutes ago, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "insufficient running history") {
		t.Fatalf("expected message to disclose insufficient history, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != false {
		t.Fatalf("expected sufficient_history=false for a freshly-created gateway, got %v", f.Metadata["sufficient_history"])
	}
}

func TestNATGatewayScanner_AboveThreshold_UsesFullWindowMessage(t *testing.T) {
	createTime := time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-longlived001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				CreateTime:   &createTime,
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

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if !strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected full-window message for a 30-day-old gateway, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true for a 30-day-old gateway, got %v", f.Metadata["sufficient_history"])
	}
}

func TestNATGatewayScanner_NoCreateTime_DefaultsToSufficientHistory(t *testing.T) {
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-unknownage001"),
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

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if !strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected full-window message when CreateTime is unset, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true when CreateTime is unset, got %v", f.Metadata["sufficient_history"])
	}
}

func TestNATGatewayScanner_YoungGateway_ExtrapolationUsesActualElapsedDays(t *testing.T) {
	// WO-251: the core computation bug. A gateway created 1 day ago that
	// processed 200MB of traffic has a REAL rate of 200MB/day — extrapolated
	// correctly that's ~5.86 GB/month, well above a 1 GB/month threshold. The
	// pre-fix code divided by the full 7-day cfg.IdleDays regardless of the
	// gateway's actual 1-day age, understating the monthly estimate to ~0.84
	// GB/month — BELOW the threshold — and would have incorrectly flagged
	// this as low-traffic. The fix must NOT flag it.
	createTime := time.Now().UTC().Add(-24 * time.Hour) // 1 day ago
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-young-busy001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				CreateTime:   &createTime,
			},
		},
	}

	// 100 MB per metric (bytes-in and bytes-out each), totalBytes = 200 MB.
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{100 * 1024 * 1024},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, NATGWLowTrafficGB: 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no low-traffic finding once the corrected ~5.86 GB/month rate is used, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func TestNATGatewayScanner_GatewayAgeExactlyAtIdleDays_ExtrapolationUnchanged(t *testing.T) {
	// Boundary case: a gateway whose age equals cfg.IdleDays exactly must
	// clamp observedDays to cfg.IdleDays with zero discontinuity from
	// pre-fix behavior — this is the same 200MB/1-day scenario as
	// TestNATGatewayScanner_YoungGateway_ExtrapolationUsesActualElapsedDays,
	// but aged to exactly 7 days: observedDays == cfg.IdleDays == 7, so the
	// extrapolation must match the original (pre-fix) totalBytes*30/7 math.
	createTime := time.Now().UTC().Add(-7 * 24 * time.Hour) // exactly 7 days ago
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-boundary001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				CreateTime:   &createTime,
			},
		},
	}

	// 100 MB per metric (bytes-in and bytes-out each), totalBytes = 200 MB —
	// same as the young-gateway test, but this gateway is old enough that
	// observedDays must clamp to 7, reproducing pre-fix output (~0.84 GB/month,
	// below the 1 GB/month threshold — the finding fires).
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{100 * 1024 * 1024},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, NATGWLowTrafficGB: 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 low-traffic finding at the exact age boundary, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	observedDays, ok := f.Metadata["observed_days"].(float64)
	if !ok {
		t.Fatalf("expected observed_days in metadata, got %v", f.Metadata["observed_days"])
	}
	if observedDays < 6.9 || observedDays > 7.1 {
		t.Fatalf("expected observed_days ≈ 7.0 (clamped to cfg.IdleDays) at the exact boundary, got %v", observedDays)
	}
	monthlyGB, ok := f.Metadata["estimated_monthly_gb"].(float64)
	if !ok {
		t.Fatalf("expected estimated_monthly_gb in metadata, got %v", f.Metadata["estimated_monthly_gb"])
	}
	if monthlyGB < 0.7 || monthlyGB > 1.0 {
		t.Fatalf("expected estimated_monthly_gb ≈ 0.837 (matching pre-fix totalBytes*30/7 math), got %v", monthlyGB)
	}
}

func TestNATGatewayScanner_YoungGateway_ObservedDaysMetadataDisclosed(t *testing.T) {
	// A young gateway whose corrected estimate is STILL below the threshold
	// (genuinely low traffic) must still fire, with observed_days disclosing
	// the actual elapsed time used for the extrapolation, for triage.
	createTime := time.Now().UTC().Add(-24 * time.Hour) // 1 day ago
	mock := &mockNATGatewayClient{
		gateways: []ec2types.NatGateway{
			{
				NatGatewayId: awssdk.String("nat-young-quiet001"),
				SubnetId:     awssdk.String("subnet-123"),
				VpcId:        awssdk.String("vpc-123"),
				State:        ec2types.NatGatewayStateAvailable,
				CreateTime:   &createTime,
			},
		},
	}

	// 1 MB per metric, totalBytes = 2 MB — genuinely low even extrapolated
	// from a single day (~0.0586 GB/month).
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{
					Id:     awssdk.String(fmt.Sprintf("m%d", i)),
					Values: []float64{1 * 1024 * 1024},
				})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewNATGatewayScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7, NATGWLowTrafficGB: 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 low-traffic finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	observedDays, ok := f.Metadata["observed_days"].(float64)
	if !ok {
		t.Fatalf("expected observed_days in metadata, got %v", f.Metadata["observed_days"])
	}
	if observedDays < 0.9 || observedDays > 1.1 {
		t.Fatalf("expected observed_days ≈ 1.0 (the gateway's actual age), got %v", observedDays)
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
