package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

type mockOpenSearchClient struct {
	domains []ostypes.DomainInfo
	desc    *ostypes.DomainStatus
}

func (m *mockOpenSearchClient) ListDomainNames(_ context.Context, _ *opensearch.ListDomainNamesInput, _ ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	return &opensearch.ListDomainNamesOutput{DomainNames: m.domains}, nil
}

func (m *mockOpenSearchClient) DescribeDomain(_ context.Context, _ *opensearch.DescribeDomainInput, _ ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	return &opensearch.DescribeDomainOutput{DomainStatus: m.desc}, nil
}

func TestOpenSearchScanner_IdleDomain(t *testing.T) {
	mock := &mockOpenSearchClient{
		domains: []ostypes.DomainInfo{{DomainName: awssdk.String("idle-cluster")}},
		desc: &ostypes.DomainStatus{
			EngineVersion: awssdk.String("OpenSearch_2.3"),
			ClusterConfig: &ostypes.ClusterConfig{
				InstanceType:  ostypes.OpenSearchPartitionInstanceTypeM5LargeSearch,
				InstanceCount: awssdk.Int32(3),
			},
		},
	}
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			var results []cwtypes.MetricDataResult
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{Id: awssdk.String(fmt.Sprintf("m%d", i)), Values: []float64{0}})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewOpenSearchScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ID != FindingOpenSearchIdle {
		t.Fatalf("expected OPENSEARCH_IDLE, got %s", f.ID)
	}
	if f.ResourceType != ResourceOpenSearch {
		t.Fatalf("expected ResourceOpenSearch, got %s", f.ResourceType)
	}
	if f.Metadata["instance_type"] != "m5.large.search" {
		t.Fatalf("expected m5.large.search, got %v", f.Metadata["instance_type"])
	}
	if f.Metadata["instance_count"] != 3 {
		t.Fatalf("expected instance_count 3, got %v", f.Metadata["instance_count"])
	}
}

func TestOpenSearchScanner_ActiveDomain(t *testing.T) {
	mock := &mockOpenSearchClient{
		domains: []ostypes.DomainInfo{{DomainName: awssdk.String("active-cluster")}},
	}
	mockCW := &mockCloudWatchClient{
		getMetricDataFn: func(_ context.Context, input *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
			results := make([]cwtypes.MetricDataResult, 0, len(input.MetricDataQueries))
			for i := range input.MetricDataQueries {
				results = append(results, cwtypes.MetricDataResult{Id: awssdk.String(fmt.Sprintf("m%d", i)), Values: []float64{100.0}})
			}
			return &cloudwatch.GetMetricDataOutput{MetricDataResults: results}, nil
		},
	}
	metrics := NewMetricsFetcher(mockCW)
	scanner := NewOpenSearchScanner(mock, metrics, "us-east-1")

	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active domain, got %d", len(result.Findings))
	}
}

func TestOpenSearchScanner_NoDomains(t *testing.T) {
	mock := &mockOpenSearchClient{domains: nil}
	metrics := newMockMetricsFetcher(nil)
	scanner := NewOpenSearchScanner(mock, metrics, "us-east-1")
	result, err := scanner.Scan(context.Background(), ScanConfig{IdleDays: 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestOpenSearchScanner_Type(t *testing.T) {
	if (&OpenSearchScanner{}).Type() != ResourceOpenSearch {
		t.Fatal("expected ResourceOpenSearch")
	}
}
