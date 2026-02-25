package analyzer

import (
	"testing"

	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

func TestAnalyze_FiltersByMinCost(t *testing.T) {
	result := &awstype.ScanResult{
		ResourcesScanned: 10,
		RegionsScanned:   2,
		Findings: []awstype.Finding{
			{ID: awstype.FindingIdleEC2, Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEC2, EstimatedMonthlyWaste: 50.0},
			{ID: awstype.FindingUnusedEIP, Severity: awstype.SeverityMedium, ResourceType: awstype.ResourceEIP, EstimatedMonthlyWaste: 3.6},
			{ID: awstype.FindingDetachedEBS, Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEBS, EstimatedMonthlyWaste: 0.5},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 1.0})

	if len(analysis.Findings) != 2 {
		t.Fatalf("expected 2 findings after filtering, got %d", len(analysis.Findings))
	}
	if analysis.Summary.TotalFindings != 2 {
		t.Fatalf("expected summary total 2, got %d", analysis.Summary.TotalFindings)
	}
	if analysis.Summary.TotalMonthlyWaste != 53.6 {
		t.Fatalf("expected waste 53.6, got %f", analysis.Summary.TotalMonthlyWaste)
	}
}

func TestAnalyze_SummaryAggregation(t *testing.T) {
	result := &awstype.ScanResult{
		ResourcesScanned: 100,
		RegionsScanned:   3,
		Findings: []awstype.Finding{
			{Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEC2, EstimatedMonthlyWaste: 50.0},
			{Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceRDS, EstimatedMonthlyWaste: 100.0},
			{Severity: awstype.SeverityMedium, ResourceType: awstype.ResourceEIP, EstimatedMonthlyWaste: 3.6},
			{Severity: awstype.SeverityLow, ResourceType: awstype.ResourceSecurityGroup, EstimatedMonthlyWaste: 0.0},
		},
		Errors: []string{"us-west-2: timeout"},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if analysis.Summary.TotalResourcesScanned != 100 {
		t.Fatalf("expected 100 scanned, got %d", analysis.Summary.TotalResourcesScanned)
	}
	if analysis.Summary.RegionsScanned != 3 {
		t.Fatalf("expected 3 regions, got %d", analysis.Summary.RegionsScanned)
	}
	if analysis.Summary.TotalFindings != 4 {
		t.Fatalf("expected 4 findings, got %d", analysis.Summary.TotalFindings)
	}

	if analysis.Summary.BySeverity["high"] != 2 {
		t.Fatalf("expected 2 high severity, got %d", analysis.Summary.BySeverity["high"])
	}
	if analysis.Summary.BySeverity["medium"] != 1 {
		t.Fatalf("expected 1 medium severity, got %d", analysis.Summary.BySeverity["medium"])
	}
	if analysis.Summary.BySeverity["low"] != 1 {
		t.Fatalf("expected 1 low severity, got %d", analysis.Summary.BySeverity["low"])
	}

	if analysis.Summary.ByResourceType["ec2"] != 1 {
		t.Fatalf("expected 1 ec2, got %d", analysis.Summary.ByResourceType["ec2"])
	}
	if analysis.Summary.ByResourceType["rds"] != 1 {
		t.Fatalf("expected 1 rds, got %d", analysis.Summary.ByResourceType["rds"])
	}

	if len(analysis.Errors) != 1 {
		t.Fatalf("expected 1 error passed through, got %d", len(analysis.Errors))
	}
}

func TestAnalyze_NoFindings(t *testing.T) {
	result := &awstype.ScanResult{
		ResourcesScanned: 50,
		RegionsScanned:   1,
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 1.0})

	if len(analysis.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(analysis.Findings))
	}
	if analysis.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 total, got %d", analysis.Summary.TotalFindings)
	}
	if analysis.Summary.TotalMonthlyWaste != 0 {
		t.Fatalf("expected 0 waste, got %f", analysis.Summary.TotalMonthlyWaste)
	}
}

func TestAnalyze_ZeroMinCost(t *testing.T) {
	result := &awstype.ScanResult{
		ResourcesScanned: 5,
		RegionsScanned:   1,
		Findings: []awstype.Finding{
			{Severity: awstype.SeverityLow, ResourceType: awstype.ResourceSecurityGroup, EstimatedMonthlyWaste: 0.0},
			{Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEC2, EstimatedMonthlyWaste: 100.0},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if len(analysis.Findings) != 2 {
		t.Fatalf("expected 2 findings with zero min cost, got %d", len(analysis.Findings))
	}
}
