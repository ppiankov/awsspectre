package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/awsspectre/internal/analyzer"
	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

func sampleData() Data {
	return Data{
		Tool:      "awsspectre",
		Version:   "0.1.0",
		Timestamp: time.Date(2026, 2, 24, 12, 0, 0, 0, time.UTC),
		Target: Target{
			Type:    "aws-account",
			URIHash: "sha256:abc123",
		},
		Config: ReportConfig{
			Regions:        []string{"us-east-1"},
			IdleDays:       7,
			StaleDays:      90,
			MinMonthlyCost: 1.0,
		},
		Findings: []awstype.Finding{
			{
				ID:                    awstype.FindingIdleEC2,
				Severity:              awstype.SeverityHigh,
				ResourceType:          awstype.ResourceEC2,
				ResourceID:            "i-abc123",
				ResourceName:          "web-server",
				Region:                "us-east-1",
				Message:               "CPU 2% over 7 days",
				EstimatedMonthlyWaste: 50.0,
			},
		},
		Summary: analyzer.Summary{
			TotalResourcesScanned: 100,
			TotalFindings:         1,
			TotalMonthlyWaste:     50.0,
			BySeverity:            map[string]int{"high": 1},
			ByResourceType:        map[string]int{"ec2": 1},
			RegionsScanned:        1,
		},
	}
}

func TestData_JSON(t *testing.T) {
	data := sampleData()

	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Data
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Tool != "awsspectre" {
		t.Fatalf("expected tool awsspectre, got %s", decoded.Tool)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
	if decoded.Summary.TotalMonthlyWaste != 50.0 {
		t.Fatalf("expected waste 50.0, got %f", decoded.Summary.TotalMonthlyWaste)
	}
}

func TestTextReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "awsspectre") {
		t.Fatal("expected awsspectre header in text output")
	}
	if !strings.Contains(output, "web-server") {
		t.Fatal("expected resource name in text output")
	}
	if !strings.Contains(output, "$50.00") {
		t.Fatal("expected waste amount in text output")
	}
	if !strings.Contains(output, "Summary") {
		t.Fatal("expected Summary section in text output")
	}
}

func TestTextReporter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	data := sampleData()
	data.Findings = nil
	data.Summary.TotalFindings = 0

	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No idle resources found") {
		t.Fatal("expected 'No idle resources found' message")
	}
}

func TestJSONReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	schema, ok := envelope["$schema"].(string)
	if !ok || schema != "spectre/v1" {
		t.Fatalf("expected $schema spectre/v1, got %v", envelope["$schema"])
	}
	if envelope["tool"] != "awsspectre" {
		t.Fatalf("expected tool awsspectre, got %v", envelope["tool"])
	}
}

func TestSpectreHubReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	schema, ok := envelope["$schema"].(string)
	if !ok || schema != "spectrehub/v1" {
		t.Fatalf("expected $schema spectrehub/v1, got %v", envelope["$schema"])
	}
}

func TestSARIFReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if sarif["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected 1 SARIF run")
	}

	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatal("expected 1 SARIF result")
	}

	result := results[0].(map[string]any)
	if result["ruleId"] != "IDLE_EC2" {
		t.Fatalf("expected ruleId IDLE_EC2, got %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Fatalf("expected level error, got %v", result["level"])
	}
}
