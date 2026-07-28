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

func TestELBScanner_KubernetesManagedLB_RecentlyCreated_BothCaveatsPresent(t *testing.T) {
	// WO-250: ELB is the only scanner in the idleWindowDescription family with
	// a second, independent caveat axis (controller-ownership, WO-220) — a
	// freshly-created, k8s-managed LB must surface BOTH the insufficient-history
	// disclosure and the Kubernetes-managed guidance in the same message.
	createTime := time.Now().UTC().Add(-11 * time.Minute)
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/net/k8s-svc-fresh/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("k8s-svc-fresh"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
				CreatedTime:      &createTime,
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
	if !strings.Contains(f.Message, "insufficient running history") {
		t.Fatalf("expected the insufficient-history caveat to be present, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected the Kubernetes-managed caveat to be present, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != false {
		t.Fatalf("expected sufficient_history=false, got %v", f.Metadata["sufficient_history"])
	}
	if f.Metadata["controller_managed"] != true {
		t.Fatalf("expected controller_managed=true, got %v", f.Metadata["controller_managed"])
	}
	if f.Severity != SeverityMedium {
		t.Fatalf("expected down-ranked medium severity, got %s", f.Severity)
	}
}

func TestELBScanner_EKSNativeManagedLB_DownRanked(t *testing.T) {
	// WO-234: EKS's native/Auto Mode load balancing integration tags LBs with
	// service.eks.amazonaws.com/* and eks:eks-cluster-name, a distinct
	// convention from the AWS Load Balancer Controller add-on above.
	arn := "arn:aws:elasticloadbalancing:eu-central-1:123456:loadbalancer/net/k8s-svc-eks-native/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("k8s-svc-eks-native"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {
				{Key: awssdk.String("service.eks.amazonaws.com/resource"), Value: awssdk.String("LoadBalancer")},
				{Key: awssdk.String("eks:eks-cluster-name"), Value: awssdk.String("eks-cluster-1")},
			},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "eu-central-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityMedium {
		t.Fatalf("expected down-ranked medium severity for EKS-native-managed LB, got %s", f.Severity)
	}
	if !strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected message to mention Kubernetes-managed guidance, got %q", f.Message)
	}
	if f.Metadata["controller_managed"] != true {
		t.Fatalf("expected controller_managed=true in metadata, got %v", f.Metadata["controller_managed"])
	}
}

func TestELBScanner_EKSClusterNameTagAlone_NotDownRanked(t *testing.T) {
	// WO-234: eks:eks-cluster-name alone is NOT a safe signal — the AWS Load
	// Balancer Controller also sets it on TargetGroupBinding resources to
	// authorize registering targets on a load balancer that isn't actually
	// k8s-owned (e.g. provisioned by Terraform). Only the pair together
	// (with service.eks.amazonaws.com/resource) means EKS-native-managed.
	arn := "arn:aws:elasticloadbalancing:eu-central-1:123456:loadbalancer/net/tf-owned-lb/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("tf-owned-lb"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {{Key: awssdk.String("eks:eks-cluster-name"), Value: awssdk.String("eks-cluster-1")}},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "eu-central-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity for eks:eks-cluster-name alone (not a safe standalone signal), got %s", f.Severity)
	}
	if strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected no Kubernetes guidance in message, got %q", f.Message)
	}
}

func TestELBScanner_EKSResourceTagAlone_NotDownRanked(t *testing.T) {
	// WO-234: service.eks.amazonaws.com/resource alone, without the cluster
	// name tag, should not be treated as EKS-native-managed either.
	arn := "arn:aws:elasticloadbalancing:eu-central-1:123456:loadbalancer/net/partial-tagged-lb/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("partial-tagged-lb"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {{Key: awssdk.String("service.eks.amazonaws.com/resource"), Value: awssdk.String("LoadBalancer")}},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "eu-central-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity for service.eks.amazonaws.com/resource alone, got %s", f.Severity)
	}
	if strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected no Kubernetes guidance in message, got %q", f.Message)
	}
}

func TestELBScanner_UntaggedLB_NotDownRanked(t *testing.T) {
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/net/plain-lb/abc123"
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String(arn),
				LoadBalancerName: awssdk.String("plain-lb"),
				Type:             elbtypes.LoadBalancerTypeEnumNetwork,
			},
		},
		tagsByARN: map[string][]elbtypes.Tag{
			arn: {{Key: awssdk.String("Environment"), Value: awssdk.String("prod")}},
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
	if f.Severity != SeverityHigh {
		t.Fatalf("expected high severity for a non-k8s-managed LB, got %s", f.Severity)
	}
	if strings.Contains(f.Message, "Kubernetes") {
		t.Fatalf("expected no Kubernetes guidance in message, got %q", f.Message)
	}
	if _, ok := f.Metadata["controller_managed"]; ok {
		t.Fatalf("expected no controller_managed metadata key, got %v", f.Metadata["controller_managed"])
	}
}

func TestELBScanner_IdleALB_RecentlyCreated_InsufficientHistoryMessage(t *testing.T) {
	// WO-250: same defect class as WO-236 (EC2) / WO-249 (RDS) — an LB
	// created less than cfg.IdleDays ago must not have its finding message
	// claim full window confidence it doesn't have.
	createTime := time.Now().UTC().Add(-11 * time.Minute)
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/freshly-created-alb/abc123"),
				LoadBalancerName: awssdk.String("freshly-created-alb"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
				VpcId:            awssdk.String("vpc-123"),
				CreatedTime:      &createTime,
			},
		},
		targetGroups: []elbtypes.TargetGroup{
			{TargetGroupArn: awssdk.String("arn:tg/my-tg/123")},
		},
		targetHealths: []elbtypes.TargetHealthDescription{
			{TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnumUnhealthy}},
		},
	}

	metrics := newMockMetricsFetcher(nil)
	scanner := NewELBScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected the finding to still surface (evidence, not suppressed), got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected message to NOT claim full 7-day coverage for an LB created 11 minutes ago, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "insufficient running history") {
		t.Fatalf("expected message to disclose insufficient history, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != false {
		t.Fatalf("expected sufficient_history=false for a freshly-created LB, got %v", f.Metadata["sufficient_history"])
	}
}

func TestELBScanner_IdleALB_AboveThreshold_UsesFullWindowMessage(t *testing.T) {
	createTime := time.Now().UTC().Add(-30 * 24 * time.Hour) // 30 days ago
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/long-lived-alb/abc123"),
				LoadBalancerName: awssdk.String("long-lived-alb"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
				VpcId:            awssdk.String("vpc-123"),
				CreatedTime:      &createTime,
			},
		},
		targetGroups: []elbtypes.TargetGroup{
			{TargetGroupArn: awssdk.String("arn:tg/my-tg/123")},
		},
		targetHealths: []elbtypes.TargetHealthDescription{
			{TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnumUnhealthy}},
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
	if !strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected full-window message for a 30-day-old LB, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true for a 30-day-old LB, got %v", f.Metadata["sufficient_history"])
	}
}

func TestELBScanner_IdleALB_NoCreateTime_DefaultsToSufficientHistory(t *testing.T) {
	mock := &mockELBClient{
		lbs: []elbtypes.LoadBalancer{
			{
				LoadBalancerArn:  awssdk.String("arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/unknown-age-alb/abc123"),
				LoadBalancerName: awssdk.String("unknown-age-alb"),
				Type:             elbtypes.LoadBalancerTypeEnumApplication,
				Scheme:           elbtypes.LoadBalancerSchemeEnumInternetFacing,
				VpcId:            awssdk.String("vpc-123"),
			},
		},
		targetGroups: []elbtypes.TargetGroup{
			{TargetGroupArn: awssdk.String("arn:tg/my-tg/123")},
		},
		targetHealths: []elbtypes.TargetHealthDescription{
			{TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnumUnhealthy}},
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
	if !strings.Contains(f.Message, "over 7 days") {
		t.Fatalf("expected full-window message when CreatedTime is unset, got %q", f.Message)
	}
	if f.Metadata["sufficient_history"] != true {
		t.Fatalf("expected sufficient_history=true when CreatedTime is unset, got %v", f.Metadata["sufficient_history"])
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
