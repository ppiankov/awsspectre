package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

func TestNewMultiRegionScanner_DefaultConcurrency(t *testing.T) {
	scanner := NewMultiRegionScanner(nil, []string{"us-east-1"}, 0, ScanConfig{})
	if scanner.concurrency != 4 {
		t.Fatalf("expected default concurrency 4, got %d", scanner.concurrency)
	}
}

func TestNewMultiRegionScanner_CustomConcurrency(t *testing.T) {
	scanner := NewMultiRegionScanner(nil, []string{"us-east-1"}, 8, ScanConfig{})
	if scanner.concurrency != 8 {
		t.Fatalf("expected concurrency 8, got %d", scanner.concurrency)
	}
}

func TestBuildScanners_Returns13Scanners(t *testing.T) {
	cfg := awssdk.Config{Region: "us-east-1"}
	scanners := buildScanners(cfg, "us-east-1")
	if len(scanners) != 13 {
		t.Fatalf("expected 13 scanners, got %d", len(scanners))
	}

	types := make(map[ResourceType]bool)
	for _, s := range scanners {
		types[s.Type()] = true
	}

	expected := []ResourceType{
		ResourceEC2, ResourceEBS, ResourceEIP, ResourceSnapshot, ResourceSecurityGroup,
		ResourceALB, ResourceNATGateway, ResourceRDS, ResourceLambda,
		ResourceKinesis, ResourceFirehose, ResourceSQS, ResourceSNS,
	}
	for _, rt := range expected {
		if !types[rt] {
			t.Fatalf("expected scanner for %s", rt)
		}
	}
}

func TestMultiRegionScanner_EmptyRegions(t *testing.T) {
	scanner := NewMultiRegionScanner(nil, nil, 4, ScanConfig{})
	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RegionsScanned != 0 {
		t.Fatalf("expected 0 regions scanned, got %d", result.RegionsScanned)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}
