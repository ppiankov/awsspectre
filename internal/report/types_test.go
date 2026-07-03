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

	schema, ok := envelope["schema"].(string)
	if !ok || schema != "spectre/v1" {
		t.Fatalf("expected schema spectre/v1, got %v", envelope["schema"])
	}
}

func TestSARIFReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	data := sampleData()
	// WO-198: CloudFront result rule IDs must be declared in SARIF rule metadata.
	data.Findings = append(data.Findings,
		awstype.Finding{
			ID:                    awstype.FindingCloudFrontDisabled,
			Severity:              awstype.SeverityLow,
			ResourceType:          awstype.ResourceCloudFront,
			ResourceID:            "E123DISABLED",
			ResourceName:          "arn:aws:cloudfront::123456789012:distribution/E123DISABLED",
			Region:                "global",
			Message:               "CloudFront distribution is disabled but still exists",
			EstimatedMonthlyWaste: 0,
			Hygiene:               true,
		},
		awstype.Finding{
			ID:                    awstype.FindingCloudFrontIdle,
			Severity:              awstype.SeverityMedium,
			ResourceType:          awstype.ResourceCloudFront,
			ResourceID:            "E123IDLE",
			ResourceName:          "arn:aws:cloudfront::123456789012:distribution/E123IDLE",
			Region:                "global",
			Message:               "CloudFront distribution had zero requests over the last 7 days",
			EstimatedMonthlyWaste: 0,
			Hygiene:               true,
		},
	)

	if err := r.Generate(data); err != nil {
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
	if !ok || len(results) != 3 {
		t.Fatal("expected 3 SARIF results")
	}

	result := sarifResultByRuleID(t, results, string(awstype.FindingIdleEC2))
	if result["ruleId"] != "IDLE_EC2" {
		t.Fatalf("expected ruleId IDLE_EC2, got %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Fatalf("expected level error, got %v", result["level"])
	}

	ruleLevels := sarifRuleLevelsByID(t, run)
	wantRuleLevels := map[string]string{
		string(awstype.FindingIdleEC2):            "error",
		string(awstype.FindingCloudFrontDisabled): "note",
		string(awstype.FindingCloudFrontIdle):     "warning",
	}
	for id, wantLevel := range wantRuleLevels {
		if gotLevel, ok := ruleLevels[id]; !ok || gotLevel != wantLevel {
			t.Fatalf("expected SARIF rule %s level %s, got %q (present=%t)", id, wantLevel, gotLevel, ok)
		}
	}
	for _, raw := range results {
		result := raw.(map[string]any)
		ruleID, ok := result["ruleId"].(string)
		if !ok || ruleID == "" {
			t.Fatalf("expected result ruleId, got %#v", result["ruleId"])
		}
		if _, ok := ruleLevels[ruleID]; !ok {
			t.Fatalf("SARIF result references undeclared ruleId %s", ruleID)
		}
	}

	cloudFrontResult := sarifResultByRuleID(t, results, string(awstype.FindingCloudFrontIdle))
	locations := cloudFrontResult["locations"].([]any)
	location := locations[0].(map[string]any)
	physicalLocation := location["physicalLocation"].(map[string]any)
	artifactLocation := physicalLocation["artifactLocation"].(map[string]any)
	if artifactLocation["uri"] != "aws://global/cloudfront/E123IDLE" {
		t.Fatalf("expected CloudFront SARIF location URI, got %v", artifactLocation["uri"])
	}
}

func TestSARIFReporter_DefaultHygieneRulesDeclared(t *testing.T) {
	data := sampleData()
	// WO-200: default-visible hygiene findings must have SARIF rule metadata.
	defaultHygieneRules := []struct {
		id           awstype.FindingID
		resourceType awstype.ResourceType
	}{
		{id: awstype.FindingIdleLambda, resourceType: "lambda"},
		{id: awstype.FindingKinesisStreamIdle, resourceType: "kinesis"},
		{id: awstype.FindingKinesisFirehoseIdle, resourceType: "firehose"},
		{id: awstype.FindingSQSIdle, resourceType: "sqs"},
		{id: awstype.FindingSQSNoConsumer, resourceType: "sqs"},
		{id: awstype.FindingSQSDLQOrphaned, resourceType: "sqs"},
		{id: awstype.FindingSNSNoSubscribers, resourceType: "sns"},
		{id: awstype.FindingSNSIdle, resourceType: "sns"},
	}
	data.Findings = make([]awstype.Finding, 0, len(defaultHygieneRules))
	for _, rule := range defaultHygieneRules {
		ruleID := string(rule.id)
		data.Findings = append(data.Findings, awstype.Finding{
			ID:           rule.id,
			Severity:     awstype.SeverityMedium,
			ResourceType: rule.resourceType,
			ResourceID:   ruleID,
			ResourceName: ruleID,
			Region:       "us-east-1",
			Message:      ruleID,
			Hygiene:      true,
		})
	}

	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected 1 SARIF run")
	}

	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != len(data.Findings) {
		t.Fatalf("expected %d SARIF results, got %d", len(data.Findings), len(results))
	}

	ruleLevels := sarifRuleLevelsByID(t, run)
	for _, rule := range defaultHygieneRules {
		ruleID := string(rule.id)
		if _, ok := ruleLevels[ruleID]; !ok {
			t.Fatalf("expected declared SARIF rule for %s", ruleID)
		}
		if result := sarifResultByRuleID(t, results, ruleID); result["ruleId"] != ruleID {
			t.Fatalf("expected SARIF result for %s, got %#v", ruleID, result["ruleId"])
		}
	}
}

func TestSARIFReporter_CostBearingRulesDeclared(t *testing.T) {
	data := sampleData()
	// WO-201: remaining cost-bearing findings must have SARIF rule metadata.
	costBearingRules := []struct {
		id           awstype.FindingID
		resourceType awstype.ResourceType
	}{
		{id: awstype.FindingLowTrafficNATGateway, resourceType: awstype.ResourceNATGateway},
		{id: awstype.FindingKinesisOverProvisioned, resourceType: awstype.ResourceKinesis},
	}
	data.Findings = make([]awstype.Finding, 0, len(costBearingRules))
	for _, rule := range costBearingRules {
		ruleID := string(rule.id)
		data.Findings = append(data.Findings, awstype.Finding{
			ID:                    rule.id,
			Severity:              awstype.SeverityMedium,
			ResourceType:          rule.resourceType,
			ResourceID:            ruleID,
			ResourceName:          ruleID,
			Region:                "us-east-1",
			Message:               ruleID,
			EstimatedMonthlyWaste: 12.34,
		})
	}

	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	if err := r.Generate(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected 1 SARIF run")
	}

	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != len(data.Findings) {
		t.Fatalf("expected %d SARIF results, got %d", len(data.Findings), len(results))
	}

	ruleLevels := sarifRuleLevelsByID(t, run)
	for _, rule := range costBearingRules {
		ruleID := string(rule.id)
		if level, ok := ruleLevels[ruleID]; !ok || level != "warning" {
			t.Fatalf("expected SARIF rule %s level warning, got %q (present=%t)", ruleID, level, ok)
		}
		if result := sarifResultByRuleID(t, results, ruleID); result["ruleId"] != ruleID {
			t.Fatalf("expected SARIF result for %s, got %#v", ruleID, result["ruleId"])
		}
	}
}

func sarifResultByRuleID(t *testing.T, results []any, ruleID string) map[string]any {
	t.Helper()

	for _, raw := range results {
		result := raw.(map[string]any)
		if result["ruleId"] == ruleID {
			return result
		}
	}
	t.Fatalf("SARIF result for ruleId %s not found", ruleID)
	return nil
}

func sarifRuleLevelsByID(t *testing.T, run map[string]any) map[string]string {
	t.Helper()

	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	levels := make(map[string]string, len(rules))
	for _, raw := range rules {
		rule := raw.(map[string]any)
		defaultConfig := rule["defaultConfiguration"].(map[string]any)
		levels[rule["id"].(string)] = defaultConfig["level"].(string)
	}
	return levels
}
