package report

import (
	"encoding/json"
	"fmt"

	awstype "github.com/ppiankov/awsspectre/internal/aws"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

// sarifReport is the top-level SARIF v2.1.0 structure.
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	DefaultConfig    sarifDefaultLevel `json:"defaultConfiguration"`
}

type sarifDefaultLevel struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLoc     `json:"locations,omitempty"`
	Props     map[string]any `json:"properties,omitempty"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// Generate writes SARIF v2.1.0 output.
func (r *SARIFReporter) Generate(data Data) error {
	rules := buildSARIFRules()
	results := make([]sarifResult, 0, len(data.Findings))

	for _, f := range data.Findings {
		results = append(results, sarifResult{
			RuleID:  string(f.ID),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLoc{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{
							URI: fmt.Sprintf("aws://%s/%s/%s", f.Region, f.ResourceType, f.ResourceID),
						},
					},
				},
			},
			Props: map[string]any{
				"resourceName":          f.ResourceName,
				"estimatedMonthlyWaste": f.EstimatedMonthlyWaste,
				"metadata":              f.Metadata,
			},
		})
	}

	report := sarifReport{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    data.Tool,
						Version: data.Version,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode SARIF report: %w", err)
	}
	return nil
}

func sarifLevel(s awstype.Severity) string {
	switch s {
	case awstype.SeverityHigh:
		return "error"
	case awstype.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildSARIFRules() []sarifRule {
	return []sarifRule{
		{ID: string(awstype.FindingIdleEC2), ShortDescription: sarifMessage{Text: "Idle EC2 instance"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingStoppedEC2), ShortDescription: sarifMessage{Text: "Stopped EC2 instance"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingDetachedEBS), ShortDescription: sarifMessage{Text: "Detached EBS volume"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingUnusedEIP), ShortDescription: sarifMessage{Text: "Unused Elastic IP"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(awstype.FindingIdleALB), ShortDescription: sarifMessage{Text: "Idle Application Load Balancer"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingIdleNLB), ShortDescription: sarifMessage{Text: "Idle Network Load Balancer"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingIdleNATGateway), ShortDescription: sarifMessage{Text: "Idle NAT Gateway"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingIdleRDS), ShortDescription: sarifMessage{Text: "Idle RDS instance"}, DefaultConfig: sarifDefaultLevel{Level: "error"}},
		{ID: string(awstype.FindingStaleSnapshot), ShortDescription: sarifMessage{Text: "Stale EBS snapshot"}, DefaultConfig: sarifDefaultLevel{Level: "warning"}},
		{ID: string(awstype.FindingUnusedSecurityGroup), ShortDescription: sarifMessage{Text: "Unused security group"}, DefaultConfig: sarifDefaultLevel{Level: "note"}},
	}
}
