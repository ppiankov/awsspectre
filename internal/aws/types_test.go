package aws

import (
	"encoding/json"
	"testing"
)

func TestFinding_JSON(t *testing.T) {
	f := Finding{
		ID:                    FindingIdleEC2,
		Severity:              SeverityHigh,
		ResourceType:          ResourceEC2,
		ResourceID:            "i-0abc123",
		ResourceName:          "web-server-1",
		Region:                "us-east-1",
		Message:               "CPU 2.1% over 7 days",
		EstimatedMonthlyWaste: 45.50,
		Metadata: map[string]any{
			"instance_type":   "t3.large",
			"avg_cpu_percent": 2.1,
		},
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != FindingIdleEC2 {
		t.Fatalf("expected ID %s, got %s", FindingIdleEC2, decoded.ID)
	}
	if decoded.Severity != SeverityHigh {
		t.Fatalf("expected severity %s, got %s", SeverityHigh, decoded.Severity)
	}
	if decoded.ResourceID != "i-0abc123" {
		t.Fatalf("expected resource_id i-0abc123, got %s", decoded.ResourceID)
	}
	if decoded.EstimatedMonthlyWaste != 45.50 {
		t.Fatalf("expected waste 45.50, got %f", decoded.EstimatedMonthlyWaste)
	}
}

func TestScanResult_JSON(t *testing.T) {
	r := ScanResult{
		Findings: []Finding{
			{
				ID:           FindingUnusedEIP,
				Severity:     SeverityMedium,
				ResourceType: ResourceEIP,
				ResourceID:   "eipalloc-abc123",
				Region:       "us-west-2",
				Message:      "Not associated",
			},
		},
		ResourcesScanned: 10,
		RegionsScanned:   2,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
	if decoded.ResourcesScanned != 10 {
		t.Fatalf("expected 10 resources scanned, got %d", decoded.ResourcesScanned)
	}
}

func TestFinding_NoMetadata(t *testing.T) {
	f := Finding{
		ID:           FindingDetachedEBS,
		Severity:     SeverityHigh,
		ResourceType: ResourceEBS,
		ResourceID:   "vol-abc123",
		Region:       "eu-west-1",
		Message:      "Detached for 14 days",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// metadata should be omitted when nil
	str := string(data)
	if contains(str, "metadata") {
		t.Fatal("expected metadata to be omitted when nil")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
