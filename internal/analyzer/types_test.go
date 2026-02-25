package analyzer

import (
	"encoding/json"
	"testing"

	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

func TestSummary_JSON(t *testing.T) {
	s := Summary{
		TotalResourcesScanned: 500,
		TotalFindings:         12,
		TotalMonthlyWaste:     847.20,
		BySeverity:            map[string]int{"high": 5, "medium": 4, "low": 3},
		ByResourceType:        map[string]int{"ec2": 3, "ebs": 2, "eip": 4, "rds": 1, "nat_gateway": 1, "snapshot": 1},
		RegionsScanned:        4,
	}

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.TotalFindings != 12 {
		t.Fatalf("expected 12 findings, got %d", decoded.TotalFindings)
	}
	if decoded.TotalMonthlyWaste != 847.20 {
		t.Fatalf("expected waste 847.20, got %f", decoded.TotalMonthlyWaste)
	}
}

func TestAnalysisResult_JSON(t *testing.T) {
	r := AnalysisResult{
		Findings: []awstype.Finding{
			{
				ID:                    awstype.FindingIdleEC2,
				Severity:              awstype.SeverityHigh,
				ResourceType:          awstype.ResourceEC2,
				ResourceID:            "i-test",
				Region:                "us-east-1",
				Message:               "test",
				EstimatedMonthlyWaste: 100.0,
			},
		},
		Summary: Summary{
			TotalFindings:     1,
			TotalMonthlyWaste: 100.0,
		},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded AnalysisResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
}
