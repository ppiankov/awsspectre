package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

type mockELBClient struct {
	lbs               []elbtypes.LoadBalancer
	targetGroups      []elbtypes.TargetGroup
	targetHealths     []elbtypes.TargetHealthDescription
	tagsByARN         map[string][]elbtypes.Tag
	describeTagsCalls [][]string
}

func (m *mockELBClient) DescribeTags(_ context.Context, input *elasticloadbalancingv2.DescribeTagsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTagsOutput, error) {
	m.describeTagsCalls = append(m.describeTagsCalls, append([]string(nil), input.ResourceArns...))
	descriptions := make([]elbtypes.TagDescription, 0, len(input.ResourceArns))
	for _, arn := range input.ResourceArns {
		arn := arn
		descriptions = append(descriptions, elbtypes.TagDescription{
			ResourceArn: &arn,
			Tags:        m.tagsByARN[arn],
		})
	}
	return &elasticloadbalancingv2.DescribeTagsOutput{TagDescriptions: descriptions}, nil
}

func (m *mockELBClient) DescribeLoadBalancers(_ context.Context, _ *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
		LoadBalancers: m.lbs,
	}, nil
}

func (m *mockELBClient) DescribeTargetGroups(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{
		TargetGroups: m.targetGroups,
	}, nil
}

func (m *mockELBClient) DescribeTargetHealth(_ context.Context, _ *elasticloadbalancingv2.DescribeTargetHealthInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetHealthOutput, error) {
	return &elasticloadbalancingv2.DescribeTargetHealthOutput{
		TargetHealthDescriptions: m.targetHealths,
	}, nil
}

func TestELBScanner_IdleALB_NoHealthyTargets(t *testing.T) {
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-alb/abc123"),
				LoadBalancerName: awssdk.String("my-alb"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
				VpcId:            awssdk.String("vpc-123"),
			},
		},
		targetGroups: []elbtypes.TargetGroup{
			{TargetGroupArn: awssdk.String("arn:tg/my-tg/123")},
		},
		targetHealths: []elbtypes.TargetHealthDescription{
			{
				TargetHealth: &elbtypes.TargetHealth{
					State: elbtypes.TargetHealthStateEnumUnhealthy,
				},
			},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

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
	if f.ID != FindingIdleALB {
		t.Fatalf("expected IDLE_ALB, got %s", f.ID)
	}
	if f.ResourceName != "my-alb" {
		t.Fatalf("expected name my-alb, got %s", f.ResourceName)
	}
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
	if f.EstimatedMonthlyWaste == 0 {
		t.Fatal("expected non-zero waste estimate")
	}
}

func TestELBScanner_IdleNLB_NoHealthyTargets(t *testing.T) {
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/net/my-nlb/abc123"),
				LoadBalancerName: awssdk.String("my-nlb"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternal,
				VpcId:            awssdk.String("vpc-123"),
			},
		},
		targetGroups:  nil,
		targetHealths: nil,
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.ID != FindingIdleNLB {
		t.Fatalf("expected IDLE_NLB, got %s", f.ID)
	}
	if f.ResourceType != ResourceNLB {
		t.Fatalf("expected ResourceNLB, got %s", f.ResourceType)
	}
}

func TestELBScanner_HealthyALB_NotFlagged(t *testing.T) {
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/healthy-alb/abc123"),
				LoadBalancerName: awssdk.String("healthy-alb"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
				VpcId:            awssdk.String("vpc-123"),
			},
		},
		targetGroups: []elbtypes.TargetGroup{
			{TargetGroupArn: awssdk.String("arn:tg/tg1/123")},
		},
		targetHealths: []elbtypes.TargetHealthDescription{
			{
				TargetHealth: &elbtypes.TargetHealth{
					State: elbtypes.TargetHealthStateEnumHealthy,
				},
			},
		},
	}

	// Return non-zero request count
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, _ *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			return &cloudwatch.GetMetricDataOutput{
				MetricDataResults: []cwtypes.MetricDataResult{
					{Id: awssdk.String("m0"), Values: []float64{1000.0}},
				},
			}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for healthy ALB, got %d", len(result.Findings))
	}
}

func TestELBScanner_NoLoadBalancers(t *testing.T) {
	mock := &mockELBClient{lbs: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResourcesScanned != 0 {
		t.Fatalf("expected 0 scanned, got %d", result.ResourcesScanned)
	}
}

func TestELBScanner_ExcludedLB(t *testing.T) {
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/excluded/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("excluded"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
			},
		},
		targetGroups:  nil,
		targetHealths: nil,
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{ResourceIDs: map[string]bool{arn: true}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded LB, got %d", len(result.Findings))
	}
}

func TestELBScanner_ExcludedByTag(t *testing.T) {
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/tagged/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("tagged"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {{Key: awssdk.String("Team"), Value: awssdk.String("payments")}},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for tag-excluded LB, got %d", len(result.Findings))
	}
}

func TestELBScanner_DescribeTagsBatchesOverTwentyARNs(t *testing.T) {
	const total = 25
	lbs := make([]elbtypes.LoadBalancer, 0, total)
	tagsByARN := make(map[string][]elbtypes.Tag, total)
	for i := 0; i < total; i++ {
		arn := fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/lb-%d/abc", i)
		lbs = append(lbs, elbtypes.LoadBalancer{
			LoadBalancerArn:  awssdk.String(arn),
			LoadBalancerName: awssdk.String(fmt.Sprintf("lb-%d", i)),
			Type:             elbtypes.LoadBalancerTypeEnumApplication,
		})
		// Tag the last LB (in the second batch) so we can confirm tags from
		// batch 2 were actually merged into the exclude check.
		if i == total-1 {
			tagsByARN[arn] = []elbtypes.Tag{{Key: awssdk.String("Team"), Value: awssdk.String("payments")}}
		}
	}

	mock := &mockELBClient{lbs: lbs, tagsByARN: tagsByARN}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	cfg := ScanConfig{
		IdleDays: 7,
		Exclude:  ExcludeConfig{Tags: map[string]string{"Team": "payments"}},
	}
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.describeTagsCalls) != 2 {
		t.Fatalf("expected 2 batched DescribeTags calls for %d ARNs, got %d", total, len(mock.describeTagsCalls))
	}
	if len(mock.describeTagsCalls[0]) != 20 {
		t.Fatalf("expected first batch of 20, got %d", len(mock.describeTagsCalls[0]))
	}
	if len(mock.describeTagsCalls[1]) != 5 {
		t.Fatalf("expected second batch of 5, got %d", len(mock.describeTagsCalls[1]))
	}

	if len(result.Findings) != total-1 {
		t.Fatalf("expected %d findings (one excluded by tag from the second batch), got %d", total-1, len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.ResourceName == fmt.Sprintf("lb-%d", total-1) {
			t.Fatalf("expected the tagged LB from the second batch to be excluded, found %s", f.ResourceName)
		}
	}
}

func TestELBScanner_KubernetesManagedLB_DownRanked(t *testing.T) {
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/net/k8s-svc/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("k8s-svc"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {{Key: awssdk.String("elbv2.k8s.aws/cluster"), Value: awssdk.String("prod")}},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityMedium {
		t.Fatalf("expected down-ranked medium severity for k8s-managed LB, got %s", f.Severity)
	}
	if !strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected message to mention Kubernetes-managed guidance, got %q", f.Message)
	}
	if f.Metadata["controller_managed"] != true {
		t.Fatalf("expected controller_managed=true in metadata, got %v", f.Metadata["controller_managed"])
	}
}

func TestELBScanner_Type(t *testing.T) {
	scanner := &ELBScanner{}
	if scanner.Type() != ResourceALB {
		t.Fatalf("expected ResourceALB, got %s", scanner.Type())
	}
}

func TestExtractLBDimension(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			"ALB",
			"arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-alb/abc123",
			"app/my-alb/abc123",
		},
		{
			"NLB",
			"arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/net/my-nlb/def456",
			"net/my-nlb/def456",
		},
		{
			"empty ARN",
			"",
			"",
		},
		{
			"no loadbalancer prefix",
			"arn:aws:something:else",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLBDimension(tt.arn)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
