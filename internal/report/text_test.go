package report

import (
	"bytes"
	"strings"
	"testing"

	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

func TestTextReporter_SortsBySeverityDescending(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	data := sampleData()
	data.Findings = []awstype.Finding{
		{ID: "LOW_1", Severity: awstype.SeverityLow, ResourceType: awstype.ResourceEC2, ResourceID: "low-1", Message: "low finding 1"},
		{ID: "MEDIUM_1", Severity: awstype.SeverityMedium, ResourceType: awstype.ResourceEC2, ResourceID: "medium-1", Message: "medium finding 1"},
		{ID: "HIGH_1", Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEC2, ResourceID: "high-1", Message: "high finding 1"},
		{ID: "LOW_2", Severity: awstype.SeverityLow, ResourceType: awstype.ResourceEC2, ResourceID: "low-2", Message: "low finding 2"},
		{ID: "HIGH_2", Severity: awstype.SeverityHigh, ResourceType: awstype.ResourceEC2, ResourceID: "high-2", Message: "high finding 2"},
	}
	data.Summary.TotalFindings = len(data.Findings)

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	positions := make(map[string]int, len(data.Findings))
	for _, id := range []string{"high-1", "high-2", "medium-1", "low-1", "low-2"} {
		idx := strings.Index(output, id)
		if idx < 0 {
			t.Fatalf("expected resource %s in output", id)
		}
		positions[id] = idx
	}

	if positions["high-1"] >= positions["medium-1"] || positions["medium-1"] >= positions["low-1"] {
		t.Fatalf("expected high < medium < low ordering, got positions %v", positions)
	}
	// Stable within same severity: high-1 stays before high-2, low-1 before low-2.
	if positions["high-1"] >= positions["high-2"] {
		t.Fatalf("expected high-1 before high-2 (stable order), got positions %v", positions)
	}
	if positions["low-1"] >= positions["low-2"] {
		t.Fatalf("expected low-1 before low-2 (stable order), got positions %v", positions)
	}

	// Original data.Findings slice must be left untouched (Generate must not mutate caller data).
	if data.Findings[0].ResourceID != "low-1" {
		t.Fatalf("expected Generate to leave data.Findings order untouched, got %s first", data.Findings[0].ResourceID)
	}
}
